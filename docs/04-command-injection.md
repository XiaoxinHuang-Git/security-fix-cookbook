# 04 · 命令注入

**CWE-78** / OWASP A03:2021 Injection

## 成因

把用户输入拼进 Shell 命令字符串，Shell 会把 `;`、`|`、`&&`、`$()` 等元字符解释成新的命令。

## ❌ 错误写法

### PHP

```php
$host = $_GET['host'];
system("ping -c 1 " . $host);
```

`host=127.0.0.1; cat /etc/passwd` 即执行任意命令。

### Go

```go
host := r.URL.Query().Get("host")
cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
out, _ := cmd.Output()
```

经过 `sh -c` 就会解析元字符。

### Node.js

```js
const { exec } = require('child_process');
exec(`ping -c 1 ${req.query.host}`, cb);
```

`exec` 走 `/bin/sh`，同样危险。

## ✅ 正确写法

核心原则：**能不用 Shell 就不用；必须用 Shell 时，用参数数组而非字符串拼接。**

### PHP

```php
$host = $_GET['host'];

// 1. 输入校验：只允许合法主机名/IP
if (!filter_var($host, FILTER_VALIDATE_IP) && !preg_match('/^[a-zA-Z0-9.\-]{1,253}$/', $host)) {
    exit('invalid host');
}

// 2. 避免经过 shell，用数组形式
$proc = proc_open(['ping', '-c', '1', $host], [
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
], $pipes);

// 如果只能拼字符串，至少用 escapeshellarg 包裹每个参数
$out = shell_exec('ping -c 1 ' . escapeshellarg($host));
```

`proc_open` 的数组形式在 PHP 7.4+ 可用，不经过 shell，元字符不会被解释。

### Go

```go
// exec.Command 不经过 shell，参数原样传给进程
cmd := exec.Command("ping", "-c", "1", host)
out, err := cmd.Output()
```

绝对不能写成 `exec.Command("sh", "-c", "...")` 再拼接变量。

### Node.js

```js
const { execFile } = require('child_process');

// execFile 不经过 shell
execFile('ping', ['-c', '1', host], (err, stdout) => {
  if (err) return res.status(500).send('failed');
  res.send(stdout);
});
```

需要 shell 特性（管道、重定向）时，用 `spawn` 并配合 `shell: false`（默认值），或把整条管道拆成多个进程。

## 输入校验白名单

命令注入的输入往往有明确的格式约束，白名单比转义更可靠：

```php
// 只允许 IP
if (!filter_var($host, FILTER_VALIDATE_IP)) { exit('invalid'); }
```

```go
if net.ParseIP(host) == nil {
    http.Error(w, "invalid ip", http.StatusBadRequest)
    return
}
```

```js
const net = require('net');
if (!net.isIP(host)) return res.status(400).send('invalid ip');
```

## 相关风险

- **参数注入**：即使不经过 shell，如果参数以 `-` 开头，可能被目标程序当成选项（如 `tar -czf out.tar --checkpoint-action=exec=...`）。命令后加 `--` 或校验开头字符。
- **路径注入**：命令参数是文件路径时，同时要考虑路径穿越（见 05）。

## 判定要点

- 搜索 `system(`、`exec(`、`shell_exec`、`popen`、`proc_open`、`exec.Command("sh"`、`child_process.exec`
- 只要拼接了外部可控变量，就是高危
- `escapeshellarg` 只对当前平台有效，跨平台项目建议直接改用数组形式
- `escapeshellcmd` 不要单独使用，它对某些元字符的处理并不完整
