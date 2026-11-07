# 08 · 不安全反序列化

**CWE-502** / OWASP A08:2021 Software and Data Integrity Failures

## 成因

把不可信数据交给反序列化函数，攻击者可以构造对象注入、魔术方法触发、甚至直接执行代码。

## ❌ 错误写法

### PHP

```php
$data = unserialize($_COOKIE['user']);
echo $data['name'];
```

`unserialize` 会实例化任意类并触发 `__wakeup`、`__destruct`，配合 POP 链可导致 RCE。

### Node.js

```js
// node-serialize 反序列化用户输入，历史上存在远程代码执行
const serialize = require('node-serialize');
const obj = serialize.unserialize(req.cookies.user);
```

```js
// 用 eval / new Function 处理"配置"
const config = eval('(' + req.body.config + ')');
```

### Go

```go
// encoding/gob 反序列化外部数据，可能触发 panic 或内存耗尽
var v MyStruct
gob.NewDecoder(r.Body).Decode(&v)
```

Go 不像 Java/PHP 那样有现成的 gadget 链，但 `gob` 处理不可信输入仍可能造成 DoS；另外 `encoding/json` 反序列化到 `interface{}` 再自行断言时，容易产生类型混淆。

## ✅ 正确写法

### PHP：改用 JSON

```php
$raw = base64_decode($_COOKIE['user'] ?? '', true);
$data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
echo htmlspecialchars($data['name'], ENT_QUOTES, 'UTF-8');
```

如果必须传对象状态，用**带签名的 JSON**：

```php
$payload = json_encode($state);
$sig = hash_hmac('sha256', $payload, $secretKey, true);
$token = base64_encode($payload) . '.' . base64_encode($sig);

// 校验
[$p, $s] = explode('.', $token);
$payload = base64_decode($p);
if (!hash_equals(hash_hmac('sha256', $payload, $secretKey, true), base64_decode($s))) {
    throw new RuntimeException('invalid signature');
}
$state = json_decode($payload, true);
```

> 确实无法改造的遗留系统：给 `unserialize` 加 `['allowed_classes' => false]`，至少禁止对象实例化。

```php
$data = unserialize($raw, ['allowed_classes' => false]);
```

### Node.js

```js
// 用 JSON
const obj = JSON.parse(req.body.config);
```

数据结构需要类型约束时用 JSON Schema 或 zod 校验：

```js
const { z } = require('zod');
const Config = z.object({
  name: z.string().max(64),
  retries: z.number().int().min(0).max(10),
});
const cfg = Config.parse(JSON.parse(req.body.config));
```

**绝对不要**对用户输入使用 `eval`、`new Function`、`vm.runInNewContext`。

### Go

```go
// 优先 json，并限制请求体大小
r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
dec := json.NewDecoder(r.Body)
dec.DisallowUnknownFields()
var v MyStruct
if err := dec.Decode(&v); err != nil {
    http.Error(w, "bad request", http.StatusBadRequest)
    return
}
```

不要用 `gob` 接收外部输入；`gob` 只适合进程间内部通信。

## 相关风险点

| 场景 | 风险 |
|---|---|
| PHP `unserialize($_GET/$_POST/$_COOKIE)` | 高危，几乎必报 |
| Java `ObjectInputStream.readObject` | 高危，gadget 链成熟 |
| Python `pickle.loads` | 高危，等价于执行任意代码 |
| Python `yaml.load`（非 `safe_load`） | 可构造对象实例化 |
| Node `node-serialize`、`serialize-javascript` 反序列化 | 高危 |
| Redis 缓存里存序列化对象 | 若缓存可被写入，等同二次注入 |

## 安全替代方案

| 语言 | 推荐 |
|---|---|
| PHP | `json_encode` / `json_decode` |
| Go | `encoding/json`、`encoding/xml`（注意 XXE 需禁用外部实体） |
| Node.js | `JSON.parse` + 结构校验 |
| Python | `json`、`yaml.safe_load` |
| Java | JSON（Jackson 关闭 `enableDefaultTyping`） |

## 判定要点

- 搜索 `unserialize(`、`pickle.loads`、`yaml.load(`、`node-serialize`、`eval`、`new Function`
- 反序列化的数据如果来自 Cookie、Header、请求体，一律视为不可信
- 校验签名能防篡改，但**不能**防「自己签了恶意数据」的场景，仍应优先换成 JSON
