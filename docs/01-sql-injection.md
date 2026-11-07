# 01 · SQL 注入

**CWE-89** / OWASP A03:2021 Injection

## 成因

用户输入被直接拼接进 SQL 语句，数据库把它当成语句的一部分执行，而不是当成数据。

## ❌ 错误写法

### PHP

```php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
$rows = $pdo->query($sql)->fetchAll();
```

`id=1 OR 1=1` 就能拿到全表数据。

### Go

```go
id := r.URL.Query().Get("id")
rows, _ := db.Query("SELECT * FROM users WHERE id = " + id)
```

### Node.js

```js
const id = req.query.id;
const [rows] = await connection.query(
  `SELECT * FROM users WHERE id = ${id}`
);
```

## ✅ 正确写法

### PHP（PDO 预处理）

```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$_GET['id']]);
$rows = $stmt->fetchAll();
```

命名参数版本：

```php
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute([':id' => $_GET['id']]);
```

注意：`PDO::ATTR_EMULATE_PREPARES` 建议设为 `false`，让预处理真正发生在数据库端。

### Go（占位符）

```go
rows, err := db.Query("SELECT * FROM users WHERE id = ?", id)
```

PostgreSQL 用 `$1` 占位符，写法一样：

```go
rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)
```

### Node.js（mysql2 预处理）

```js
const [rows] = await connection.execute(
  'SELECT * FROM users WHERE id = ?', [id]
);
```

用 `execute` 而不是 `query`，前者走服务端预处理。

## 无法参数化的位置

表名、列名、`ORDER BY` 字段、`LIMIT` 偏移这些位置不能绑定参数，只能用**白名单映射**：

```php
$allowedSort = ['created_at', 'amount', 'id'];
$sort = in_array($_GET['sort'] ?? '', $allowedSort, true)
    ? $_GET['sort'] : 'id';
$sql = "SELECT * FROM orders ORDER BY {$sort} LIMIT 20";
```

```go
var allowed = map[string]bool{"created_at": true, "amount": true, "id": true}
sort := "id"
if s := r.URL.Query().Get("sort"); allowed[s] {
    sort = s
}
query := fmt.Sprintf("SELECT * FROM orders ORDER BY %s LIMIT 20", sort)
```

这里用 `fmt.Sprintf` 是安全的，因为 `sort` 只可能来自固定的三个值。

## 判定要点

- 代码里出现 `"SELECT ... " + $var`、字符串模板拼 SQL，基本都是问题
- ORM 的原始 SQL 方法（如 GORM 的 `Raw`、Sequelize 的 `sequelize.query`）同样需要参数化
- `LIKE` 查询要参数化值，并单独转义 `%` 和 `_`
- 存储过程内部如果有动态 SQL（`PREPARE ... CONCAT`），同样要检查
