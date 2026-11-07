# 06 · 硬编码密钥与敏感信息泄露

**CWE-798 / CWE-312** / OWASP A02:2021 Cryptographic Failures

## 成因

数据库密码、AK/SK、JWT 私钥、第三方接口 Token 直接写在源码里，随代码库、构建产物、镜像一起扩散。

## ❌ 错误写法

```php
$pdo = new PDO('mysql:host=10.0.0.5;dbname=app', 'root', 'Passw0rd@2024');
```

```go
const (
    accessKey = "LTAI5tXXXXXXXXXXXX"
    secretKey = "3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c"
)
```

```js
const jwtSecret = 'my-super-secret-key';
```

```yaml
# docker-compose.yml 直接写死
environment:
  - DB_PASSWORD=Passw0rd@2024
```

## ✅ 正确写法

### 从环境变量读取

PHP：

```php
$pdo = new PDO(
    sprintf('mysql:host=%s;dbname=%s', getenv('DB_HOST'), getenv('DB_NAME')),
    getenv('DB_USER'),
    getenv('DB_PASS')
);
```

Go：

```go
db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s",
    os.Getenv("DB_USER"), os.Getenv("DB_PASS"), os.Getenv("DB_HOST"), os.Getenv("DB_NAME")))
```

Node.js：

```js
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});
```

启动时做一次必填校验，避免密钥缺失时静默使用默认值：

```go
func mustEnv(key string) string {
    v := os.Getenv(key)
    if v == "" {
        log.Fatalf("missing required env: %s", key)
    }
    return v
}
```

### 配置文件不入库

`.gitignore` 至少要包含：

```gitignore
.env
.env.*
!.env.example
*.pem
*.key
*.p12
config/local.*
```

提交一份只有占位符的 `.env.example`：

```
DB_HOST=127.0.0.1
DB_USER=your_user
DB_PASS=your_password
JWT_SECRET=change_me
```

### 生产环境的密钥管理

- 容器编排：K8s Secret、Docker Secret
- 云上：阿里云 KMS / 密钥管理服务、AWS Secrets Manager
- 自建：Vault、Consul KV
- 最低要求：配置文件权限 600，属主为运行用户

## 已经泄露了怎么办

**顺序很重要：先轮换，再清理历史。**

1. **立即吊销/轮换** —— 密钥一旦进过 Git，就视为已泄露（包括私有仓库）
2. **评估影响范围** —— 查访问日志，确认是否被使用过
3. **清理 Git 历史** —— `git filter-repo` 或 BFG，然后强制推送并通知所有协作者重新克隆
4. **加检测** —— pre-commit hook 或 CI 中跑 `gitleaks`

```bash
# gitleaks 检测当前仓库与历史
gitleaks detect --source . -v

# 只扫本次提交
gitleaks protect --staged -v
```

## 其他容易忽略的泄露点

| 位置 | 说明 |
|---|---|
| 前端打包产物 | 前端代码里的 `VITE_xxx` / `REACT_APP_xxx` 会明文出现在 bundle 中，不能放密钥 |
| 错误堆栈 | 生产环境返回完整堆栈，会泄露路径、SQL、内网 IP |
| 日志 | 日志里打印了完整请求体、Token、身份证号 |
| 仓库其他文件 | 测试脚本、Postman 集合、备份的 `.sql`、`.zip` |
| 注释 | `// TODO: remove before prod` 后面跟着真实密钥 |

## 判定要点

- 扫描器报「Hardcoded Password」「Secret in Source」时，先确认是**真实凭据**还是**示例值**
- 文档和示例代码里用 `<YOUR_KEY>`、`change_me` 这类明显的占位符，可以避免误报
- 检查 CI 配置（`.github/workflows`、`.gitlab-ci.yml`）里是否直接写了密钥
