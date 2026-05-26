# SafeScan Lite — 轻量级安全扫描工具

SafeScan Lite 是一款面向安全测试人员的轻量级扫描工具，基于 Python 构建，集成 TCP/UDP 端口扫描、Banner 服务指纹识别、敏感目录爆破、弱口令检测、Web 漏洞主动探测、漏洞指纹匹配和可视化报告生成等核心能力。项目采用模块化设计，各功能组件可独立运行，也可通过主入口串联为完整的自动化扫描流程。

---

## 目录结构

```
SafeScan Lite/
├── safescan_lite.py          # 主入口，串联全部扫描流程
├── port_scanner.py           # 多线程 TCP 端口扫描模块
├── banner_grabber.py         # Banner 抓取与服务指纹识别模块
├── udp_scanner.py            # UDP 端口扫描模块
├── dir_scanner.py            # 多线程敏感目录/文件爆破模块
├── web_vuln_scanner.py       # Web 漏洞主动检测模块
├── password_cracker.py       # SSH/FTP/Telnet/MySQL/SMTP 弱口令检测模块
├── reporter.py               # HTML 可视化报告生成模块（含 Chart.js 图表）
├── vuln_fingerprint.json     # 漏洞指纹规则库（47条）
├── username.txt              # 弱口令用户名字典
├── password.txt              # 弱口令密码字典
└── dicts/
    └── dirs.txt              # 敏感路径字典
```

---

## 功能模块

### 1. TCP 端口扫描 (`port_scanner.py`)

- 基于 `concurrent.futures.ThreadPoolExecutor` 实现高并发 TCP 端口探测
- 支持自定义端口范围，默认扫描 1–1000，默认 50 线程
- 内置服务名映射表，将系统端口名（如 `microsoft-ds`）标准化为通用名称（如 `SMB`），确保后续指纹匹配准确

### 2. Banner 抓取与服务指纹识别 (`banner_grabber.py`)

- 对每个开放端口发送协议探针（SSH/FTP/SMTP 等直接读取握手 Banner，HTTP 发送 GET 请求，Redis 发送 PING）
- 通过正则指纹库识别真实服务名称和版本号（Apache/Nginx/IIS/OpenSSH/ProFTPD/MySQL 等 30+ 种指纹）
- 识别结果自动合并到端口扫描结果，用于提升漏洞匹配精度
- 对二进制协议（如 SMB/RPC）会明确提示"非文本协议"

### 3. UDP 端口扫描 (`udp_scanner.py`)

- 向常见 UDP 服务发送协议探针包，根据响应判断端口开放状态
- 覆盖 DNS(53)、NTP(123)、SNMP(161)、NetBIOS(137)、UPnP(1900)、mDNS(5353)、RIP(520) 共 7 种协议
- 多线程并发，默认 30 线程

### 4. 敏感目录扫描 (`dir_scanner.py`)

- 基于字典文件对目标 Web 服务发起 HTTP GET 请求
- 识别 200（存在）、301/302（跳转）、403（禁止但存在）四类响应
- `ThreadPoolExecutor` 多线程并发，默认 30 线程，大幅提升大批量字典扫描速度
- 支持自定义 User-Agent 伪装，3 秒超时控制

### 5. Web 漏洞主动检测 (`web_vuln_scanner.py`)

在目录扫描基础上主动探测四类常见 Web 漏洞：

| 检测项 | 方法 |
|--------|------|
| SQL 注入 | 在 URL 参数中注入单引号 / `AND 1=1`，匹配 10 种数据库错误回显特征 |
| XSS | 注入 `<script>` / `<img onerror>` 等 5 种 Payload，检测响应中原样回显 |
| 备份文件泄露 | 探测 `.bak`、`.swp`、`.tar.gz`、`.git/config`、`.env`、`.DS_Store` 等 14 种常见后缀 |
| 目录遍历 | 注入 `../../etc/passwd` 等 5 种 Payload，检测 Linux/Windows 系统文件特征 |

### 6. 弱口令检测 (`password_cracker.py`)

- 支持 **SSH**（Paramiko）、**FTP**（ftplib）、**Telnet**（telnetlib）、**MySQL**（原生 socket 握手 + `mysql_native_password`）、**SMTP**（smtplib AUTH LOGIN）五种协议
- 自动从 `username.txt` / `password.txt` 加载字典去重遍历爆破
- 按开放端口自动匹配对应服务，返回命中的账号密码

### 7. 漏洞指纹匹配 (`vuln_fingerprint_match`)

- 读取 `vuln_fingerprint.json` 规则库（47 条），将开放端口及标准化后的服务名与已知漏洞签名进行比对
- 覆盖 SSH/FTP/HTTP/HTTPS/MySQL/Redis/MongoDB/PostgreSQL/MSSQL/SMTP/Telnet/DNS/SNMP/Jenkins/Tomcat/RDP/SMB/Memcached/Elasticsearch/Docker、WebLogic/Spring Boot/LDAP/NetBIOS/VNC 等 25+ 类服务
- 匹配成功则输出漏洞名称、严重等级（高危/中危/低危）、描述及修复建议

### 8. 报告生成 (`reporter.py`)

- 终端内输出结构化的文本扫描摘要，覆盖全部 6 类扫描结果
- 生成带完整 CSS 样式的 **HTML 可视化报告**，包含：
  - 概览卡片（TCP/UDP 端口数、漏洞数、弱口令数）
  - Chart.js 漏洞等级环形图
  - TCP 端口/Banner 表格
  - UDP 端口表格
  - 弱口令高亮表格
  - 漏洞指纹表格（按高危/中危/低危分色徽章标注）
  - 敏感目录表格
  - Web 漏洞检测表格

---

## 依赖环境

| 依赖 | 版本要求 | 用途 |
|------|----------|------|
| Python | ≥ 3.8 | 运行环境 |
| paramiko | ≥ 2.7 | SSH 弱口令爆破 |
| requests | ≥ 2.25 | HTTP 目录扫描与 Web 漏洞检测 |

安装依赖：

```bash
pip install paramiko requests
```

---

## 使用方式

### 完整扫描（命令行模式）

```bash
python safescan_lite.py -t 192.168.1.1
```

### 完整扫描（交互模式）

```bash
python safescan_lite.py
```

按提示输入目标 IP 即可。

### 常用参数

```
-t, --target       目标 IP 地址
-p, --port-range   TCP 端口范围，格式: 起始-结束 (默认: 1-1000)
-u, --url          目标 URL（用于目录扫描和 Web 漏洞检测，默认 http://<IP>）
--threads          TCP 端口扫描线程数 (默认: 50)
--dir-threads      目录扫描线程数 (默认: 30)
--dict             目录扫描字典路径
--no-banner        跳过 Banner 抓取
--no-udp           跳过 UDP 端口扫描
--no-brute         跳过弱口令爆破
--no-dir           跳过目录扫描
--no-web           跳过 Web 漏洞检测
--no-report        不生成 HTML 报告
-o, --output       HTML 报告输出文件名
```

### 示例

```bash
# 快速扫描（仅端口和 Banner）
python safescan_lite.py -t 192.168.1.1 -p 1-500 --no-udp --no-brute --no-dir --no-web

# 仅 Web 检测
python safescan_lite.py -t 192.168.1.1 -u http://192.168.1.1:8080 -p 8080-8080 --no-udp --no-brute

# 全端口深度扫描
python safescan_lite.py -t 10.0.0.1 -p 1-65535 --threads 200
```

### 模块独立运行

```bash
python port_scanner.py         # TCP 端口扫描
python banner_grabber.py       # Banner 抓取
python udp_scanner.py          # UDP 端口扫描
python dir_scanner.py          # 目录扫描
python web_vuln_scanner.py     # Web 漏洞检测
python password_cracker.py     # 弱口令爆破
```

---

## 扫描流程

```
步骤1: TCP 端口扫描      →  发现开放端口及服务名
步骤2: Banner 抓取        →  识别真实服务类型和版本号
步骤3: UDP 端口扫描       →  探测 UDP 服务开放状态（可跳过）
步骤4: 弱口令爆破         →  对 SSH/FTP/Telnet/MySQL/SMTP 进行字典爆破（可跳过）
步骤5: 漏洞指纹匹配       →  将开放端口与 47 条已知漏洞规则比对
步骤6: 目录扫描           →  爆破 Web 敏感路径（可跳过）
步骤7: Web 漏洞检测       →  SQL注入/XSS/备份文件/目录遍历（可跳过）
步骤8: 终端摘要报告       →  命令行结构化输出
步骤9: HTML 可视化报告    →  浏览器中查看完整报告（可跳过）
```

---

## 未来扩展方向

- 配置中心（YAML 多 Profile 快速/深度扫描模式切换）
- 分布式扫描（Redis + Celery 多节点并发）
- 资产管理与历史对比（SQLite 存储，多版本 Diff）
- 插件化架构（统一扫描插件接口）
- 实时 Web 仪表盘（Flask + WebSocket 进度推送）

---

## 安全声明

本工具仅供授权的安全测试、CTF 竞赛、教学研究及防御性用途使用。对未获得明确授权的目标进行扫描可能违反法律法规。使用者应确保遵守所在地区相关法律规定，并自行承担所有使用风险。

---

## 许可证

本项目仅供学习与合法安全测试使用。
