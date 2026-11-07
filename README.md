# security-fix-cookbook

常见 Web 安全漏洞的「错误写法 → 正确写法」对照手册，覆盖 **PHP / Go / Node.js** 三种后端语言。

不是漏洞原理教科书，而是一份可以直接对照改代码的速查表。

## 为什么有这个仓库

安全扫描报告通常只给一个漏洞名称和一个文件行号，真正花时间的是「这一行到底应该怎么改」。
这个仓库把常见漏洞整理成对照形式：左边是会被扫出来的写法，右边是修复后的写法，外加判定要点。

## 目录

| 编号 | 漏洞类型 | 文档 |
|---|---|---|
| 01 | SQL 注入 | [docs/01-sql-injection.md](docs/01-sql-injection.md) |
| 02 | XSS 跨站脚本 | [docs/02-xss.md](docs/02-xss.md) |
| 03 | CSRF 跨站请求伪造 | [docs/03-csrf.md](docs/03-csrf.md) |
| 04 | 命令注入 | [docs/04-command-injection.md](docs/04-command-injection.md) |
| 05 | 路径穿越 | [docs/05-path-traversal.md](docs/05-path-traversal.md) |
| 06 | 硬编码密钥 / 敏感信息泄露 | [docs/06-hardcoded-secrets.md](docs/06-hardcoded-secrets.md) |
| 07 | 越权访问（IDOR） | [docs/07-idor.md](docs/07-idor.md) |
| 08 | 不安全反序列化 | [docs/08-insecure-deserialization.md](docs/08-insecure-deserialization.md) |

上线前自查： [checklist.md](checklist.md)

## 使用方式

1. 拿到扫描报告里的漏洞类型和文件行号
2. 在 `docs/` 里找到对应文档
3. 对照「错误写法」确认命中的是同一类问题
4. 按「正确写法」修改，注意末尾的「判定要点」——不是每个扫描结果都是真漏洞，也不是每一处都要改成同一个方案

## 约定

- 代码片段只保留最小可复现结构，省略了框架初始化和错误处理
- `❌` 标记的是会被扫描器命中的写法
- `✅` 标记的是修复后的写法，优先选语言和框架自带的安全能力，其次才是手写过滤
- 涉及文件路径、命令、SQL 标识符的场景，一律优先白名单，其次才是转义

## 免责声明

本仓库内容仅用于**自身代码的安全审查**和**获得授权的安全测试**。
请勿用于未授权的渗透测试或攻击行为。

## 参考

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
