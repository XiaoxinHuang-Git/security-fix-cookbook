# 09 · 安全响应头缺失

安全响应头告诉浏览器如何处理页面内容。缺失这些头会导致 XSS、点击劫持、信息泄露等次生漏洞被利用。

## 问题触发条件

- 扫描工具报告「缺少 X-Frame-Options / CSP / HSTS / X-Content-Type-Options」
- 手动检查：curl 响应头里看不到这些字段

## 对照

### HTTP 安全响应头缺失

**错误写法**

```php
// PHP：什么也不做，让框架默认输出
// 浏览器只能依赖自己的默认行为
```

```go
// Go：不设置任何安全响应头
w.Header().Set("Content-Type", "text/html; charset=utf-8")
w.Write([]byte(html))
```

```javascript
// Node.js / Express：没有 helmet，手动也不加
app.get('/page', (req, res) => {
  res.send(html)
})
```

**正确写法**

```php
// PHP：入口处统一设置
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:');
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}
```

```go
// Go：封装中间件
func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
        if r.TLS != nil {
            w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        }
        next.ServeHTTP(w, r)
    })
}
```

```javascript
// Node.js / Express：用 helmet（生产环境标准做法）
import helmet from 'helmet'
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"]
    }
  }
}))
```

### Nginx 层统一处理（推荐）

```nginx
# 放在 server {} 块里，一处搞定
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

## 判定要点

- `X-Frame-Options` 不存在时页面可以被 iframe 嵌入 → 点击劫持风险
- `Content-Security-Policy` 不存在时即使 XSS 漏洞被触发也没有额外防护层
- HSTS 只在 HTTPS 环境有意义，HTTP 站点加了也白加
- CSP 的 `script-src` 不要放 `'unsafe-inline'` 除非真的用了 inline script
- 如果已经有 CSP，检查是否过于宽松（比如 `default-src *`）——那等于没加
