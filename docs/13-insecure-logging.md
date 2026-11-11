# 13 · 不安全的日志记录

> OWASP A09: Security Logging and Monitoring Failures

日志本身不能修复漏洞，但糟糕的日志会让两件事变难：
1. 安全事件发生后**根本查不到**记录
2. 明明有日志，却因为格式混乱、敏感信息泄露、被攻击者塞了伪造行而**不敢用**

本手册聚焦「日志实现层面的代码漏洞」，不是「要记哪些日志」的监控设计问题。

---

## 漏洞清单

| # | 子类型 | 现象 | 后果 |
|---|---|---|---|
| A | 敏感信息写入日志 | 密码、Token、完整身份证号直接出现在日志 | 日志泄露即凭据泄露 |
| B | 未记录关键操作 | 登录失败、权限变更、管理员操作没有审计记录 | 攻击者擦掉痕迹后无从追溯 |
| C | 日志可被伪造（日志注入） | 用户输入直接拼到日志行里，换行未转义 | 攻击者塞假日志行，混淆调查方向 |
| D | 日志级别滥用 | 所有请求都 WARN / ERROR，或关键异常只打 DEBUG | 告警风暴淹没真实事件 / 关键异常被忽略 |
| E | 日志只在本地文件 | 日志文件和应用在同一台机器上 | 服务器被删库时日志一起消失 |

---

## A · 敏感信息写入日志

### 错误写法

```php
// PHP
log_info("user login: " . $username . ", password=" . $_POST['password']);
log_info("payment card: " . $order->card_number); // 完整卡号
```

```go
// Go
log.Printf("admin login: user=%s token=%s\n", username, req.Token)
log.Printf("payment: card=%s cvv=%s\n", cardNo, cvv)
```

```javascript
// Node.js
logger.info("login", { username, password: req.body.password });
logger.info(req.headers); // Authorization Bearer Token 直接打出来
```

### 正确写法

**掩码化**——按字段类型定义掩码规则，不手写字符串替换：

```php
// PHP
function mask($value, $keepStart = 2, $keepEnd = 2) {
    $len = strlen($value);
    if ($len <= $keepStart + $keepEnd) return str_repeat('*', $len);
    return substr($value, 0, $keepStart) . str_repeat('*', $len - $keepStart - $keepEnd) . substr($value, -$keepEnd);
}

log_info("user login: " . $username . ", password=" . mask($_POST['password']));
log_info("payment card: " . mask($order->card_number, 4, 4));
```

```go
// Go
func mask(s string, keepStart, keepEnd int) string {
    if len(s) <= keepStart+keepEnd {
        return strings.Repeat("*", len(s))
    }
    return s[:keepStart] + strings.Repeat("*", len(s)-keepStart-keepEnd) + s[len(s)-keepEnd:]
}

log.Printf("admin login: user=%s token=%s\n", username, mask(req.Token, 4, 4))
log.Printf("payment: card=%s cvv=***\n", mask(cardNo, 4, 4))
```

```javascript
// Node.js —— pino / winston 的 redact 配置
const pino = require('pino');
const logger = pino({
  redact: {
    paths: ['password', '*.password', 'token', 'authorization', '*.cvv'],
    censor: '***'
  }
});

logger.info({ username }, 'user login');
```

### 判定要点

- **密码永远不写日志**——哪怕是开发环境
- Token / Cookie / SessionID 最多保留前后 2-4 位
- 身份证号保留前 6 后 4
- 银行卡号保留前 4 后 4，CVV 一律 `***`
- 不要指望「日志文件权限收好了」——运维、外包、误传都可能泄露

---

## B · 未记录关键操作

### 错误写法

```php
// PHP —— 只记成功，不记失败
if (password_verify($input, $stored)) {
    // ... 登录逻辑
} else {
    // 什么都不做，或者只打一条 DEBUG
}

// 管理员改了用户权限，没记录
$user->role = 'admin';
$user->save();
```

```go
// Go —— 批量删除没有审计
func (h *Handler) DeleteUsers(ids []int) {
    h.db.Delete(&User{}, ids) // 谁删的、什么时候、删了谁，日志里全没有
}
```

### 正确写法

**关键操作清单**（无论成败都要记）：

| 类别 | 必须记录 |
|---|---|
| 认证 | 登录成功 / 失败、Token 签发 / 吊销、密码修改 |
| 授权 | 角色变更、权限变更、管理员操作 |
| 数据 | 批量删除 / 批量更新、敏感字段修改、导出下载 |
| 配置 | 环境参数变更、密钥轮换 |

```php
// PHP —— 登录失败也要记
if (password_verify($input, $stored)) {
    audit_log('login_success', ['uid' => $user->id, 'ip' => $_SERVER['REMOTE_ADDR']]);
} else {
    audit_log('login_failed', ['username' => $username, 'ip' => $_SERVER['REMOTE_ADDR']]);
    // 同时触发第 11 条暴力破解计数
}

// 管理员权限变更
$user->role = 'admin';
$user->save();
audit_log('role_change', [
    'target_uid' => $user->id,
    'old_role'   => 'user',
    'new_role'   => 'admin',
    'op_uid'     => current_user_id(),
    'op_ip'      => $_SERVER['REMOTE_ADDR'],
]);
```

### 判定要点

- 审计日志和业务日志**分开存**——前者不轮转、只增不改，后者可以定期清理
- 审计记录必须包含：谁、做了什么、对谁、结果、IP、时间、关联 ID（request_id / trace_id）
- 即使操作失败也要记录——失败次数本身就是情报

---

## C · 日志可被伪造（日志注入）

### 错误写法

```php
// PHP —— 直接把用户输入拼进日志，攻击者可以输入 "\n2026-01-01 admin login success"
log_info("login attempt for " . $_GET['user']);
```

```go
// Go
log.Printf("search: %s", userInput) // userInput 里有 \n 的话，多行就是多条假日志
```

### 正确写法

**结构化日志 + 转义换行**：

```php
// PHP —— JSON 结构化，天然解决换行问题
log_info(json_encode([
    'action' => 'login_attempt',
    'user'   => $_GET['user'],
    'ip'     => $_SERVER['REMOTE_ADDR'],
], JSON_UNESCAPED_UNICODE));

// 或者显式转义
log_info("login attempt for " . str_replace(["\n", "\r"], ' ', $_GET['user']));
```

```go
// Go —— logrus / zap 结构化
logrus.WithFields(logrus.Fields{
    "action": "login_attempt",
    "user":   userInput,
    "ip":     ip,
}).Info("")

// 标准库手动转义
log.Printf("search: %s", strings.ReplaceAll(strings.ReplaceAll(userInput, "\n", "\\n"), "\r", "\\r"))
```

```javascript
// Node.js
logger.info({ action: 'login_attempt', user: userInput, ip }, 'login');
// pino / winston / bunyan 默认都是 JSON，用户输入的 \n 会变成 \u000a
```

### 判定要点

- 日志输出**一律用结构化格式**（JSON / key=value），不要用自由文本拼接
- 必须转义的字符：`\n` `\r` `\t` 以及可能的控制字符
- 如果用 grep 排查问题，结构化日志 + jq 比文本靠谱得多

---

## D · 日志级别滥用

### 错误写法

```php
// PHP
Log::warn("GET /api/users");          // 正常请求用 WARN
Log::error("user id not found");      // 404 业务正常返回用 ERROR
```

```go
// Go
log.Printf("query ok: %d rows", n)    // 所有 SQL 查询都打一条，而且没分级
log.Printf("admin login from %s", ip) // 管理员登录也只是 Printf，不是 Warn
```

### 正确写法

**级别对齐语义**：

| 级别 | 何时使用 |
|---|---|
| DEBUG | SQL 参数、函数入参、中间变量（线上默认关闭） |
| INFO | 正常业务流程：请求摘要、关键步骤完成 |
| WARN | 预期外但可恢复：重试触发、缓存穿透、第三方慢响应 |
| ERROR | 业务失败需要排查：SQL 异常、支付失败、外部服务 5xx |
| FATAL | 应用级崩溃：配置缺失、数据库无法连接导致启动失败 |

```php
// PHP
Log::info("GET /api/users", ['uid' => $user->id, 'cost_ms' => $ms]);
Log::warn("cache miss, fallback to db", ['key' => $key]);
Log::error("payment callback failed", ['order_no' => $no, 'reason' => $e->getMessage()]);
```

### 判定要点

- **INFO 是常态**——告警系统不该盯着 INFO 级别
- **WARN 会触发告警**——确认 WARN 里的内容真值得有人来看
- **ERROR 必须有人看**——不设监控告警的 ERROR 级别日志等于没打
- 开发环境 DEBUG 全开，生产环境默认只开 INFO 及以上

---

## E · 日志只在本地文件

### 错误写法

```bash
# 所有日志都写 /var/log/app/，服务器被删库、被断电、被格式化就没了
./myapp >> /var/log/app/app.log 2>&1
```

### 正确做法

| 场景 | 推荐方案 |
|---|---|
| 单机私有化 | 应用写本地 + logrotate + 定时同步到另一台服务器（rsync / scp） |
| Docker / K8s | stdout → 容器日志收集器 → Loki / ELK / Splunk |
| SaaS / 云环境 | 直接接入云厂商日志服务（阿里云 SLS / AWS CloudWatch / 腾讯云 CLS） |

```go
// Go —— 写入标准输出，交给外部收集
func main() {
    log.SetOutput(os.Stdout)
    // ... 由 systemd / docker 来接管日志收集
}
```

### 判定要点

- **审计日志绝对不能只在本地**——必须多副本、不可篡改（追加式、带校验和）
- 业务日志可以本地轮转，但要保留足够长（一般 14-90 天）
- 不要把应用日志和系统日志混在一个文件里

---

## 三个快速自检

1. **随便找一条用户输入**（比如搜索框输入 `a\nadmin=1`），它会不会在日志里造出一条假记录？
2. **找一个密码字段**，它有没有机会出现在某个 log 调用里？
3. **找一个管理员操作**，它的审计记录能回答「谁、什么时候、做了什么、结果如何」吗？

三个问题有任意一个答不上来，就该改。
