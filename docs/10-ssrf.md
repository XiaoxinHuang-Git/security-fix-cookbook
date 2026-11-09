# 10 · SSRF 服务端请求伪造

把用户可控的 URL 交给服务器去请求——服务器在内网，能访问用户访问不到的资源，比如云元数据服务（169.254.169.254）。

## 问题触发条件

- 扫描报告：SSRF（Server-Side Request Forgery）
- 代码里有根据用户输入拼接 URL 然后 `curl` / `file_get_contents` / `http.Get` / `axios.get` 的地方

## 对照

### 直接用用户输入拼 URL

**错误写法**

```php
// PHP
$url = $_GET['url'];  // 用户给啥就是啥
$content = file_get_contents($url);  // 可能请求到 http://169.254.169.254/latest/meta-data/
echo $content;
```

```go
// Go
func fetchURL(c *gin.Context) {
    url := c.Query("url")
    resp, err := http.Get(url)  // 用户可以塞 http://127.0.0.1:6379 或内网服务
    // ...
}
```

```javascript
// Node.js
app.get('/proxy', async (req, res) => {
  const url = req.query.url
  const resp = await axios.get(url)  // SSRF
  res.send(resp.data)
})
```

**正确写法**

核心思路：**白名单域名 + 解析 IP 后拒绝内网地址**。

```php
// PHP
function safe_fetch(string $url): string {
    $host = parse_url($url, PHP_URL_HOST);
    // 白名单
    $allowed = ['api.example.com', 'cdn.example.com'];
    if (!in_array($host, $allowed, true)) {
        throw new Exception('host not allowed');
    }
    // 解析 IP 后拒绝私有地址
    $ip = gethostbyname($host);
    $private = [
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
        '127.0.0.0/8', '169.254.0.0/16', '0.0.0.0/8',
    ];
    foreach ($private as $cidr) {
        if (ip_in_cidr($ip, $cidr)) {
            throw new Exception('private ip blocked');
        }
    }
    // 加超时，防止拖死
    $ctx = stream_context_create(['http' => ['timeout' => 5]]);
    return file_get_contents($url, false, $ctx);
}
```

```go
// Go
func safeFetch(rawURL string) ([]byte, error) {
    u, err := url.Parse(rawURL)
    if err != nil {
        return nil, err
    }
    // 白名单
    allowed := map[string]bool{
        "api.example.com": true,
        "cdn.example.com":  true,
    }
    if !allowed[u.Hostname()] {
        return nil, fmt.Errorf("host not allowed")
    }
    // 解析 IP 并拒绝私有地址
    ips, err := net.LookupIP(u.Hostname())
    if err != nil {
        return nil, err
    }
    for _, ip := range ips {
        if isPrivateIP(ip) {
            return nil, fmt.Errorf("private ip blocked: %s", ip)
        }
    }
    // 加超时
    client := &http.Client{Timeout: 5 * time.Second}
    resp, err := client.Get(rawURL)
    // ...
}

func isPrivateIP(ip net.IP) bool {
    privateRanges := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"}
    for _, cidr := range privateRanges {
        _, network, _ := net.ParseCIDR(cidr)
        if network.Contains(ip) {
            return true
        }
    }
    return false
}
```

```javascript
// Node.js
import { URL } from 'url'
import axios from 'axios'
import dns from 'dns'
import { promisify } from 'util'
const lookup = promisify(dns.lookup)

const PRIVATE_RANGES = [
  '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
  '127.0.0.0/8', '169.254.0.0/16'
]

function isPrivateIP(ip) {
  // 简化版：实际用 ip-address 库
  return ip.startsWith('10.') || ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) ||
    ip.startsWith('127.') || ip.startsWith('169.254.')
}

app.get('/proxy', async (req, res) => {
  const { hostname, href } = new URL(req.query.url)
  // 白名单
  if (!['api.example.com', 'cdn.example.com'].includes(hostname)) {
    return res.status(400).send('host not allowed')
  }
  // DNS 解析后检查
  const { address } = await lookup(hostname)
  if (isPrivateIP(address)) {
    return res.status(400).send('private ip blocked')
  }
  const resp = await axios.get(href, { timeout: 5000 })
  res.send(resp.data)
})
```

## 判定要点

- 只做 URL 格式校验（`filter_var(FILTER_VALIDATE_URL)` 或 `url.Parse`）**不够**，攻击者可以塞合法格式的内网 URL
- 白名单域名后仍需做 DNS 解析检查——攻击者可能把白名单域名解析到内网 IP（DNS Rebinding）
- 超时必须加，不然 SSRF 可以用来做拒绝服务
- 不需要支持 SSRF 的地方（比如接口参数就是外部 URL），考虑直接移除这个功能
