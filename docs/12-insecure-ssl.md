# 12 · 不安全 HTTPS 与敏感数据传输

全站走 HTTP、或者某些敏感接口（登录、支付）降级到 HTTP，数据在传输链路明文裸奔。

## 问题触发条件

- 扫描报告：TLS 版本过低（TLSv1.0 / TLSv1.1）、缺少 TLS 强制跳转、明文 HTTP 暴露敏感接口
- 浏览器地址栏有警告、混合内容（HTTPS 页面加载 HTTP 资源）

## 对照

### 未强制 HTTPS，敏感接口可被 HTTP 访问

**错误写法**

```php
// PHP：不管协议，接口直接暴露
// http://example.com/api/v1/login  能直接访问
// http://example.com/api/v1/pay    能直接访问
```

```go
// Go：只监听 HTTP
func main() {
    r := gin.Default()
    r.POST("/api/v1/login", LoginHandler)
    r.Run(":8080")  // 没有 TLS
}
```

**正确写法**

**方案 A：Nginx 层强制跳转（推荐，一劳永逸）**

```nginx
# HTTP 全部 301 到 HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}

# HTTPS server 块加上严格 TLS 配置
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/nginx/cert/example.com.pem;
    ssl_certificate_key /etc/nginx/cert/example.com.key;

    # 禁用 TLSv1.0 / TLSv1.1，只允许 TLSv1.2+
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...;
    ssl_prefer_server_ciphers on;

    # 混合内容防护
    add_header Content-Security-Policy "upgrade-insecure-requests" always;
}
```

**方案 B：应用层兜底拦截**

```php
// PHP：全局 middleware 强制 HTTPS
// Laravel 示例：在 AppServiceProvider 里注册
public function boot() {
    if (env('FORCE_HTTPS', false) || app()->environment('production')) {
        URL::forceScheme('https');
    }
}

// 或者用 middleware 拦截敏感接口
public function handle($request, Closure $next) {
    $uri = $request->getRequestUri();
    $sensitive = ['/api/v1/login', '/api/v1/pay', '/api/v1/user/profile'];
    foreach ($sensitive as $prefix) {
        if (str_starts_with($uri, $prefix) && !$request->isSecure()) {
            return redirect()->secure($uri);
        }
    }
    return $next($request);
}
```

```go
// Go：同时监听 HTTP 和 HTTPS，HTTP 做重定向
func main() {
    r := gin.Default()
    r.POST("/api/v1/login", LoginHandler)

    // HTTP 重定向到 HTTPS
    go func() {
        http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
            target := "https://" + req.Host + req.URL.Path
            http.Redirect(w, req, target, http.StatusMovedPermanently)
        }))
    }()

    log.Fatal(http.ListenAndServeTLS(":443", "cert.pem", "key.pem", r))
}
```

### 敏感数据在 URL query 里传递（即使 HTTPS 也会泄露到浏览器历史、日志）

**错误写法**

```php
// PHP
$url = "/api/v1/transfer?amount={$amount}&bank_card={$_GET['card']}&password={$_GET['pwd']}";
// 密码在 URL 里，被浏览器历史存下来了
```

**正确写法**

敏感参数一律放 POST body，不要放 URL。URL 只放非敏感的路由参数和页面标识。

```php
// PHP
// 前端用 fetch POST，密码在 body 里
example.com/api/v1/transfer  // body: { amount: 100, bank_card: '6225...', password: '***' }
```

## 判定要点

- TLSv1.0 / TLSv1.1 已被正式废弃（RFC 8996），2024 年起主流浏览器已移除支持
- 敏感接口（登录、支付、个人信息查询）**绝不能**让 HTTP 也能访问
- URL query 参数中的敏感信息会被 Web 服务器日志、CDN 日志、浏览器历史、Referer 头记录
- 混合内容（HTTPS 页面加载 HTTP 的 CSS/JS）虽然部分浏览器会拦截，但还是应该在 Nginx 层统一 `add_header Content-Security-Policy "upgrade-insecure-requests"`
- 证书到期会导致服务中断，建议配置到期告警（7 天、3 天双重提醒）
