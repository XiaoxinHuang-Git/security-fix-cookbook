# 02 · XSS 跨站脚本

**CWE-79** / OWASP A03:2021 Injection

## 成因

用户可控的数据未经编码就输出到 HTML 页面，浏览器把它当成脚本执行。
分反射型、存储型、DOM 型三类，修法都是「**输出时按上下文编码**」，而不是「输入时过滤」。

## ❌ 错误写法

### PHP

```php
echo '<div>欢迎，' . $_GET['name'] . '</div>';
```

访问 `?name=<script>alert(1)</script>` 即触发。

### Go

```go
// text/template 不做 HTML 转义
t := template.Must(template.New("t").Parse("<div>欢迎，{{.Name}}</div>"))
t.Execute(w, data)
```

### Node.js（EJS）

```ejs
<div>欢迎，<%- user.name %></div>
```

`<%-` 是原样输出，`<%=` 才是转义输出。

## ✅ 正确写法

### PHP

```php
echo '<div>欢迎，' . htmlspecialchars($_GET['name'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '</div>';
```

框架场景优先用模板自动转义（Laravel Blade `{{ }}`、ThinkPHP `{$name|htmlentities}`）。

### Go

```go
// 用 html/template，会自动按上下文转义
t := template.Must(template.New("t").Parse("<div>欢迎，{{.Name}}</div>"))
t.Execute(w, data)
```

Go 的 `html/template` 会区分 HTML 正文、属性、JS、CSS、URL 上下文分别编码，**不要用 `text/template` 渲染用户输入**。

### Node.js

```ejs
<div>欢迎，<%= user.name %></div>
```

### 富文本场景

富文本无法直接转义（会把标签也转掉），需要做 HTML 白名单净化：

```js
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);

const safe = purify.sanitize(userContent, {
  ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li', 'a'],
  ALLOWED_ATTR: ['href']
});
```

PHP 可用 `HTMLPurifier` 做同样的事。**不要自己写正则过滤标签**。

## 不同上下文的编码方式

| 输出位置 | 处理方式 |
|---|---|
| HTML 正文 | HTML 实体编码 |
| HTML 属性 | HTML 实体编码 + 属性值加引号 |
| `<script>` 内 | JSON 序列化，禁止直接插值 |
| URL 参数 | `urlencode` |
| CSS | 避免用户可控值进入 style |

## 纵深防御

- 设置 `Content-Security-Policy`，限制脚本来源
- Cookie 加 `HttpOnly`，降低被窃取风险
- 输入校验只能减少攻击面，**不能替代输出编码**

## 判定要点

- 扫描器常把 `htmlspecialchars` 的第三个参数缺失报为问题：PHP 8 默认已是 UTF-8，但 `ENT_QUOTES` 仍需显式指定
- 模板里出现 `<%-`、`v-html`、`dangerouslySetInnerHTML`、`innerHTML =` 都要逐个确认数据来源
- `htmlspecialchars` 不能用在 `<script>` 里，属性值里也必须保证引号闭合
