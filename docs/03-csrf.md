# 03 · CSRF 跨站请求伪造

**CWE-352** / OWASP A01:2021 Broken Access Control

## 成因

浏览器会自动携带目标站点的 Cookie，攻击者只要诱导用户访问一个恶意页面，就能以用户身份发起状态变更请求。

## ❌ 错误写法

```php
// 仅靠 Cookie 判断登录态，没有任何请求来源校验
if (isset($_COOKIE['uid'])) {
    $pdo->exec("UPDATE users SET email = '{$_POST['email']}' WHERE id = {$_COOKIE['uid']}");
}
```

```go
func transfer(w http.ResponseWriter, r *http.Request) {
    // Cookie 鉴权，未校验 CSRF token
    uid := sessionUser(r)
    doTransfer(uid, r.FormValue("to"), r.FormValue("amount"))
}
```

攻击者页面只需一个自动提交的表单：

```html
<form action="https://victim.com/transfer" method="POST" id="f">
  <input name="to" value="attacker">
  <input name="amount" value="10000">
</form>
<script>document.getElementById('f').submit()</script>
```

## ✅ 正确写法

### 基础方案：Synchronizer Token

PHP：

```php
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// 表单中输出
echo '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8') . '">';

// 提交时校验，使用 hash_equals 防时序攻击
$token = $_POST['csrf_token'] ?? '';
if (!hash_equals($_SESSION['csrf_token'], $token)) {
    http_response_code(403);
    exit('Invalid CSRF token');
}
```

Go：

```go
func csrfMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method == http.MethodGet || r.Method == http.MethodHead {
            next.ServeHTTP(w, r)
            return
        }
        want, _ := r.Cookie("csrf")
        got := r.Header.Get("X-CSRF-Token")
        if want == nil || subtle.ConstantTimeCompare([]byte(got), []byte(want.Value)) != 1 {
            http.Error(w, "invalid csrf token", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

Node.js（Express）：

```js
const csrf = require('csrf');
const tokens = new csrf();

// 下发
app.get('/form', (req, res) => {
  const secret = tokens.secretSync();
  req.session.csrfSecret = secret;
  res.render('form', { token: tokens.create(secret) });
});

// 校验
app.post('/submit', (req, res, next) => {
  if (!tokens.verify(req.session.csrfSecret, req.body._csrf)) {
    return res.status(403).send('invalid csrf token');
  }
  next();
});
```

> `csurf` 中间件已于 2022 年废弃，不建议继续使用，可用 `csrf-csrf` 或上面的 `csrf` 包自行实现。

### 加固方案：SameSite Cookie

```
Set-Cookie: SESSIONID=xxx; Path=/; HttpOnly; Secure; SameSite=Lax
```

- `Lax`：跨站 POST 不带 Cookie，能挡住绝大多数 CSRF，同时不影响普通链接跳转
- `Strict`：最严，但跨站跳转过来会丢失登录态
- `None`：必须配合 `Secure`，且等于放弃 CSRF 防护

SameSite 是**纵深防御**，不能完全替代 Token：老浏览器、以及同站子域场景仍需 Token。

### 接口场景

- 前端用 `Authorization: Bearer` 头带 Token 的 API，天然不易被 CSRF（浏览器不会自动附加）
- 如果鉴权仍依赖 Cookie，就要校验 `Origin` / `Referer` 头，并配合 Token

## 判定要点

- 所有会改变状态的请求（POST/PUT/DELETE/PATCH）都要校验
- 不要用 GET 做状态变更——`<img src="/delete?id=1">` 就能打
- Token 必须绑定会话，且用常量时间比较（`hash_equals` / `subtle.ConstantTimeCompare`）
- 登录、注册、改密、绑卡这类敏感接口是重点检查对象
