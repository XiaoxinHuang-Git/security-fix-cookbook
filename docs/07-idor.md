# 07 · 越权访问（IDOR）

**CWE-639** / OWASP A01:2021 Broken Access Control

## 成因

接口只校验了「是否登录」，没有校验「这条数据是否属于当前用户」。
攻击者把 URL 里的 id 改成别人的，就能读写他人数据。

## ❌ 错误写法

### PHP

```php
$uid = $_SESSION['uid'];
$order = $pdo->query("SELECT * FROM orders WHERE id = {$_GET['id']}")->fetch();
// 只要有登录态就返回，没有校验归属
echo json_encode($order);
```

### Go

```go
orderID := r.URL.Query().Get("id")
var o Order
db.Where("id = ?", orderID).First(&o)   // 缺少 user_id 条件
json.NewEncoder(w).Encode(o)
```

### Node.js

```js
app.get('/api/orders/:id', auth, async (req, res) => {
  const order = await Order.findByPk(req.params.id);  // 未校验归属
  res.json(order);
});
```

把 `/api/orders/1001` 改成 `1002` 就能读到别人的订单。

## ✅ 正确写法

核心原则：**数据查询条件里必须带上当前用户身份，而不是查完再判断。**

### PHP

```php
$stmt = $pdo->prepare('SELECT * FROM orders WHERE id = ? AND user_id = ?');
$stmt->execute([$_GET['id'], $_SESSION['uid']]);
$order = $stmt->fetch();

if (!$order) {
    http_response_code(404);   // 不要返回 403，避免泄露"该资源存在"
    exit;
}
```

### Go

```go
var o Order
err := db.Where("id = ? AND user_id = ?", orderID, currentUserID(r)).First(&o).Error
if errors.Is(err, gorm.ErrRecordNotFound) {
    http.Error(w, "not found", http.StatusNotFound)
    return
}
```

### Node.js

```js
const order = await Order.findOne({
  where: { id: req.params.id, userId: req.user.id },
});
if (!order) return res.status(404).json({ error: 'not found' });
```

## 水平越权与垂直越权

| 类型 | 场景 | 防护 |
|---|---|---|
| 水平越权 | 同角色用户互相访问数据 | 查询条件绑定 `user_id` |
| 垂直越权 | 普通用户调用管理员接口 | 接口级 RBAC 权限校验 |

垂直越权示例（Go）：

```go
func requireRole(roles ...string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            u := currentUser(r)
            for _, role := range roles {
                if u.Role == role {
                    next.ServeHTTP(w, r)
                    return
                }
            }
            http.Error(w, "forbidden", http.StatusForbidden)
        })
    }
}
```

## 其他常见越权点

- **批量接口**：`POST /orders/batch-delete` 接收 id 数组，只校验了部分 id
- **导出接口**：`/export?userId=123` 直接信任参数里的 userId
- **关联对象**：修改订单里的 `addressId` 时，未校验该地址属于当前用户
- **文件下载**：`/file?path=...` 未校验文件归属
- **状态流转**：`PUT /orders/1/status` 未校验订单归属与当前状态是否允许该操作

## 修复策略

把「归属校验」收敛成统一的数据访问层，避免每个接口各写一遍：

```go
// 所有按 ID 查询的仓储方法强制带 userID
func (r *OrderRepo) FindByIDAndUser(ctx context.Context, id, userID int64) (*Order, error)
```

不要提供 `FindByID` 这种无归属约束的公开方法，从接口层面杜绝遗漏。

## 判定要点

- 扫描器通常报「IDOR」「Missing Function Level Access Control」，但很多要靠人工看代码
- 检查所有带 `{id}`、`?id=`、`userId=` 参数的接口
- 返回 404 而不是 403：避免攻击者通过状态码枚举有效资源 ID
- 自定义角色/数据权限（如部门可见范围）要单独测
