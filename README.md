# security-fix-cookbook

[![security](https://img.shields.io/badge/security-OWASP%20Top%2010-lightgrey.svg)]()
[![language](https://img.shields.io/badge/PHP-Go-Node.js-brightgreen.svg)]()
[![coverage](https://img.shields.io/badge/OWASP%20A01--A10-13%20docs-2ea44f.svg)]()
[![license](https://img.shields.io/badge/License-MIT-yellow.svg)]()

常见 Web 安全漏洞的「错误写法 → 正确写法」对照手册，覆盖 **PHP / Go / Node.js** 三种后端语言。

不是漏洞原理教科书，而是一份可以直接对照改代码的速查表。

## 为什么有这个仓库

安全扫描报告通常只给一个漏洞名称和一个文件行号，真正花时间的是「这一行到底应该怎么改」。
这个仓库把常见漏洞整理成对照形式：左边是会被扫出来的写法，右边是修复后的写法，外加判定要点。

## 目录

| 编号 | 漏洞类型 | OWASP 对应 | 文档 |
|---|---|---|---|
| 01 | SQL 注入 | A01 注入 | [docs/01-sql-injection.md](docs/01-sql-injection.md) |
| 02 | XSS 跨站脚本 | A03 失效的访问控制 | [docs/02-xss.md](docs/02-xss.md) |
| 03 | CSRF 跨站请求伪造 | A03 失效的访问控制 | [docs/03-csrf.md](docs/03-csrf.md) |
| 04 | 命令注入 | A01 注入 | [docs/04-command-injection.md](docs/04-command-injection.md) |
| 05 | 路径穿越 | A01 注入 | [docs/05-path-traversal.md](docs/05-path-traversal.md) |
| 06 | 硬编码密钥 / 敏感信息泄露 | A02 加密机制失效 | [docs/06-hardcoded-secrets.md](docs/06-hardcoded-secrets.md) |
| 07 | 越权访问（IDOR） | A03 失效的访问控制 | [docs/07-idor.md](docs/07-idor.md) |
| 08 | 不安全反序列化 | A08 软件和数据完整性失效 | [docs/08-insecure-deserialization.md](docs/08-insecure-deserialization.md) |
| 09 | 安全响应头缺失 | A04 安全配置错误 | [docs/09-security-headers.md](docs/09-security-headers.md) |
| 10 | SSRF 服务端请求伪造 | A10 服务器端请求伪造 | [docs/10-ssrf.md](docs/10-ssrf.md) |
| 11 | 暴力破解防护 | A07 身份验证失效 | [docs/11-brute-force.md](docs/11-brute-force.md) |
| 12 | 不安全 HTTPS 与敏感数据传输 | A02 加密机制失效 | [docs/12-insecure-ssl.md](docs/12-insecure-ssl.md) |
| 13 | 不安全的日志记录 | A09 安全日志和监控失效 | [docs/13-insecure-logging.md](docs/13-insecure-logging.md) |

上线前自查： [checklist.md](checklist.md)

## 使用方式

1. 拿到扫描报告里的漏洞类型和文件行号
2. 在 `docs/` 里找到对应文档
3. 对照「错误写法」确认命中的是同一类问题
4. 按「正确写法」修改，注意末尾的「判定要点」——不是每个扫描结果都是真漏洞，也不是每一处都要改成同一个方案

## 覆盖的漏洞来源

参考 OWASP Top 10（2021），按实际扫描工具（Nessus / SAST / 绿盟）报告中高频出现的漏洞类型整理。

| OWASP 分类 | 本手册对应编号 |
|---|---|
| A01 注入 | 01 SQL 注入、04 命令注入、05 路径穿越 |
| A02 加密机制失效 | 06 硬编码密钥、12 不安全 HTTPS |
| A03 失效的访问控制 | 02 XSS、03 CSRF、07 IDOR |
| A04 安全配置错误 | 09 响应头、12 TLS 配置 |
| A05 脆弱的设计 | 11 暴力破解 |
| A06 易受攻击的组件 | （升级依赖后用 06 的密钥管理思路） |
| A07 身份验证和身份识别失效 | 11 暴力破解 |
| A08 软件和数据完整性失效 | 08 反序列化 |
| A09 安全日志和监控失效 | **13 不安全的日志记录** |
| A10 服务器端请求伪造 | 10 SSRF |

## 约定

- 代码片段只保留最小可复现结构，省略了框架初始化和无关的依赖
- 修复方案优先展示「最直接的写法」，不追求每个片段都引入新库
- 判定要点部分记录「什么时候扫描结果是假阳性」以及「修复时容易漏掉的细节」

## 贡献

欢迎 PR 补充更多漏洞类型、更多语言的修复方案，或者补充判定要点里的边缘案例。

## License

MIT
