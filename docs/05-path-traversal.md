# 05 · 路径穿越

**CWE-22** / OWASP A01:2021 Broken Access Control

## 成因

用户可控的文件名拼进路径，通过 `../` 跳出预期目录，读取或写入本不该访问的文件。

## ❌ 错误写法

### PHP

```php
$file = $_GET['file'];
readfile('/var/www/uploads/' . $file);
```

请求 `?file=../../../../etc/passwd` 即可读取系统文件。

### Go

```go
name := r.URL.Query().Get("file")
data, _ := os.ReadFile(filepath.Join("/data/uploads", name))
```

`filepath.Join` 会正常解析 `../`，起不到防护作用。

### Node.js

```js
const file = path.join('/data/uploads', req.query.file);
fs.createReadStream(file).pipe(res);
```

## ✅ 正确写法

思路：**先把路径规范化成绝对路径，再校验它是否仍在允许的根目录内**。

### PHP

```php
$base = realpath('/var/www/uploads');
$target = realpath($base . '/' . basename($_GET['file']));

if ($target === false || strpos($target, $base . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(403);
    exit('forbidden');
}
readfile($target);
```

- `basename()` 去掉目录部分，是最直接的收敛方式
- `realpath()` 会解析 `..` 和符号链接；返回 `false` 表示文件不存在
- 前缀比较时一定要带 `DIRECTORY_SEPARATOR`，否则 `/var/www/uploads-evil` 也能通过

### Go

```go
base, _ := filepath.Abs("/data/uploads")
target, err := filepath.Abs(filepath.Join(base, name))
if err != nil || !strings.HasPrefix(target, base+string(os.PathSeparator)) {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}
data, err := os.ReadFile(target)
```

Go 1.20+ 还可以用 `os.Root`（1.24+）或 `filepath.IsLocal` 做更严格的校验：

```go
if !filepath.IsLocal(name) {
    http.Error(w, "forbidden", http.StatusForbidden)
    return
}
```

### Node.js

```js
const path = require('path');
const fs = require('fs');

const base = path.resolve('/data/uploads');
const target = path.resolve(base, req.query.file);

if (!target.startsWith(base + path.sep)) {
    return res.status(403).send('forbidden');
}
fs.createReadStream(target).pipe(res);
```

注意 `path.resolve` 才能解析 `..`，`path.join` 不会给出绝对路径做前缀比较。

## 更稳妥的方案

如果文件名是系统生成的，直接用**映射表**而不是用户输入：

```
上传时：生成 uuid → 存库 {uuid, 原文件名, 真实路径}
下载时：/download?key=<uuid> → 查库得到真实路径
```

用户永远接触不到文件系统路径，从根本上消除穿越问题，同时避免暴露真实目录结构。

## 相关变体

- **空字节截断**：老版本 PHP 中 `file.php%00.jpg` 可绕过扩展名校验（PHP 5.3.4+ 已修复）
- **URL 编码**：`%2e%2e%2f` 等价于 `../`，校验必须在解码之后进行
- **符号链接**：`realpath` 会解析软链接，`filepath.Abs` 不会，需要时补 `filepath.EvalSymlinks`
- **Windows 短文件名**：`PROGRA~1` 这类 8.3 名称也会绕过简单匹配
- **压缩包解压**：zip slip——解压时条目名含 `../` 会写到目录外，需逐条校验

## 判定要点

- 搜索 `readfile`、`file_get_contents`、`os.ReadFile`、`fs.readFile`、`fs.createReadStream` 且参数含用户输入
- 只做了 `str_replace('../', '')` 这类替换是不够的，`....//` 可以绕过
- 上传目录必须禁止脚本执行（Nginx 中关闭该目录的 PHP/JS 解析）
