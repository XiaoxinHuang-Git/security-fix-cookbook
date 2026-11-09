# 11 · 暴力破解防护

没有登录失败次数限制，攻击者用字典或彩虹表撞账号密码。

## 问题触发条件

- 扫描报告：缺少账户锁定机制 / 缺少验证码
- 实际场景：登录接口可以无限制尝试

## 对照

### 纯用户名密码校验，没有任何限制

**错误写法**

```php
// PHP
public function login() {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $user = DB::table('users')->where('username', $username)->first();
    if ($user && password_verify($password, $user->password)) {
        // 登录成功，写入 session
    }
    // 失败直接返回，不记录、不计数
}
```

```go
// Go（Gin 示例）
func Login(c *gin.Context) {
    var req LoginReq
    c.ShouldBindJSON(&req)
    user, err := userDB.FindByName(req.Username)
    if err == nil && bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password)) == nil {
        // 登录成功
    }
    // 没有失败计数、没有锁定
}
```

**正确写法**

三层防护：**失败计数 → 临时锁定 → 验证码兜底**。

```php
// PHP：用 Redis 做计数，key = login_attempt:{ip}:{username}
public function login() {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $ip = $_SERVER['REMOTE_ADDR'];

    // 1. 检查是否已被锁定
    $lockKey = "login_lock:{$ip}:{$username}";
    if (Redis::exists($lockKey)) {
        $ttl = Redis::ttl($lockKey);
        return response()->json(['msg' => "账号已锁定，请 {$ttl} 秒后重试"])->setStatusCode(429);
    }

    // 2. 验证码校验（第 3 次失败后强制出现）
    $attemptKey = "login_attempt:{$ip}:{$username}";
    $attempts = (int) Redis::get($attemptKey);
    if ($attempts >= 3) {
        $captcha = $_POST['captcha'];
        if (!Captcha::verify($captcha, $_SESSION['captcha_token'])) {
            return response()->json(['msg' => '验证码错误'])->setStatusCode(400);
        }
    }

    // 3. 正常登录逻辑
    $user = DB::table('users')->where('username', $username)->first();
    if ($user && password_verify($password, $user->password)) {
        Redis::del($attemptKey);  // 成功后清零
        Redis::del($lockKey);
        // 生成 session / JWT...
        return response()->json(['token' => $token]);
    }

    // 4. 失败，计数 +1
    Redis::incr($attemptKey);
    Redis::expire($attemptKey, 300);  // 5 分钟窗口

    if ($attempts + 1 >= 5) {
        // 5 次失败 → 锁定 15 分钟
        Redis::setex($lockKey, 900, 1);
    }

    return response()->json(['msg' => '用户名或密码错误'])->setStatusCode(401);
}
```

```go
// Go：用 Redis + 速率限制
func Login(c *gin.Context) {
    var req LoginReq
    c.ShouldBindJSON(&req)
    ip := c.ClientIP()

    lockKey := fmt.Sprintf("login_lock:%s:%s", ip, req.Username)
    if locked, _ := redisClient.Exists(c.Request.Context(), lockKey).Result(); locked > 0 {
        c.JSON(429, gin.H{"msg": "账号已锁定，请稍后重试"})
        return
    }

    attemptKey := fmt.Sprintf("login_attempt:%s:%s", ip, req.Username)
    attempts, _ := redisClient.Get(c.Request.Context(), attemptKey).Int()
    if attempts >= 3 {
        if req.Captcha == "" || !verifyCaptcha(req.Captcha) {
            c.JSON(400, gin.H{"msg": "请输入验证码"})
            return
        }
    }

    user, err := userDB.FindByName(req.Username)
    if err == nil && bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password)) == nil {
        redisClient.Del(c.Request.Context(), attemptKey)
        redisClient.Del(c.Request.Context(), lockKey)
        token := generateToken(user)
        c.JSON(200, gin.H{"token": token})
        return
    }

    redisClient.Incr(c.Request.Context(), attemptKey)
    redisClient.Expire(c.Request.Context(), attemptKey, 5*time.Minute)

    if attempts+1 >= 5 {
        redisClient.SetEX(c.Request.Context(), lockKey, 1, 15*time.Minute)
    }

    c.JSON(401, gin.H{"msg": "用户名或密码错误"})
}
```

## 判定要点

- 锁定键最好同时包含 IP 和用户名，不然同一 IP 可以遍历撞不同用户名
- 错误提示不要区分「用户不存在」和「密码错误」，否则攻击者可以先枚举用户名再撞密码
- Redis key 设置过期很重要，否则锁定永远不会自动解除
- 管理员账户（admin、root）应该加更严格的策略：强制验证码、限 IP 白名单登录
- 可以把登录失败日志接入 WAF / SIEM，超过阈值触发告警
