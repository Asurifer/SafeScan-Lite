# SafeScan Lite — 轻量级安全扫描工具

SafeScan Lite 是一款面向安全测试人员的轻量级扫描工具，基于 Python 构建，集成了端口扫描、敏感目录爆破、弱口令检测、漏洞指纹匹配和可视化报告生成等核心能力。项目采用模块化设计，各功能组件可独立运行，也可通过主入口串联为完整的自动化扫描流程。

---

## 目录结构

```
SafeScan Lite/
├── safescan_lite.py          # 主入口，串联全部扫描流程
├── port_scanner.py           # 多线程端口扫描模块
├── dir_scanner.py            # 敏感目录/文件爆破模块
├── password_cracker.py       # SSH / FTP 弱口令检测模块
├── reporter.py               # HTML 可视化报告生成模块
├── vuln_fingerprint.json     # 漏洞指纹规则库
├── username.txt              # 弱口令用户名字典
├── password.txt              # 弱口令密码字典
└── dicts/
    └── dirs.txt              # 敏感路径字典
```

---

## 功能模块

### 1. 端口扫描 (`port_scanner.py`)

- 基于 `concurrent.futures.ThreadPoolExecutor` 实现高并发 TCP 端口探测，默认 50 线程
- 支持自定义端口范围，默认扫描 1–1000
- 自动映射常见端口到服务名（通过 `socket.getservbyport`）

### 2. 敏感目录扫描 (`dir_scanner.py`)

- 基于字典文件对目标 Web 服务发起 HTTP GET 请求
- 识别 200（存在）、301/302（跳转）、403（禁止但存在）四类响应
- 支持自定义 User-Agent 伪装，3 秒超时控制

### 3. 弱口令检测 (`password_cracker.py`)

- 支持 **SSH**（基于 Paramiko）和 **FTP**（基于 ftplib）两种协议
- 自动从 `username.txt` / `password.txt` 加载字典，去重后遍历爆破
- 按开放端口自动匹配对应服务，返回命中的账号密码

### 4. 漏洞指纹匹配 (`vuln_fingerprint_match`)

- 读取 `vuln_fingerprint.json` 规则库，将开放端口及其服务与已知漏洞签名进行比对
- 匹配成功则输出漏洞名称、等级、描述及修复建议

### 5. 报告生成 (`reporter.py`)

- 终端内输出结构化的文本扫描摘要
- 同时生成带 CSS 样式的 **HTML 可视化报告**，包含目录爆破、端口、弱口令及漏洞匹配四类结果的完整展示

---

## 依赖环境

| 依赖 | 版本要求 | 用途 |
|------|----------|------|
| Python | ≥ 3.8 | 运行环境 |
| paramiko | ≥ 2.7 | SSH 弱口令爆破 |
| requests | ≥ 2.25 | HTTP 目录扫描 |

安装依赖：

```bash
pip install paramiko requests
```

---

## 使用方式

### 完整扫描

```bash
python safescan_lite.py
```

按提示输入目标 IP，工具将自动完成端口扫描 → 弱口令爆破 → 漏洞指纹匹配 → 目录扫描 → 报告生成全流程。

### 模块独立运行

各模块均可单独执行以进行功能测试：

```bash
python port_scanner.py        # 本地回环 1-1000 端口
python dir_scanner.py         # 对 http://127.0.0.1 进行目录扫描
python password_cracker.py    # 模拟 21/22 端口弱口令检测
```

---

## 当前局限性

- 端口扫描仅覆盖 TCP，未支持 UDP
- 弱口令检测仅覆盖 SSH、FTP，缺少 Telnet、MySQL、RDP 等常见服务
- 目录扫描为单线程串行请求，大批量字典时速度较慢
- 漏洞指纹库仅 3 条规则，覆盖范围有限
- 服务识别仅依赖端口号映射，未做 Banner 抓取
- 无命令行参数支持，每次均需交互输入

---

## 项目扩展规划

以下为建议的扩展方向，按优先级分为三个梯队。

### 第一阶段：核心增强（短期）

#### 1.1 Banner 抓取与服务指纹识别

在端口扫描确认端口开放后，主动发送探针请求并读取 Banner 回显，通过正则匹配识别真实服务及版本号，替代当前仅靠端口号映射的粗糙方式。

```
新增模块: banner_grabber.py
改造范围: port_scanner.py (check_port 函数)、vuln_fingerprint.json (增加 banner 正则字段)
```

#### 1.2 命令行参数支持

引入 `argparse`，支持通过命令行参数指定目标 IP、端口范围、线程数、字典路径等，兼顾交互式与脚本化两种使用场景。

```
改造范围: safescan_lite.py 主入口
```

#### 1.3 弱口令服务扩展

新增以下协议的支持：
- **Telnet** — 基于 `telnetlib`
- **MySQL** — 基于 `pymysql`
- **RDP** — 基于 `python-rdpy` 或自定义 NLA 握手
- **SMTP / POP3** — 基于 `smtplib` / `poplib`

```
新增模块: password_cracker/telnet_crack.py, mysql_crack.py, rdp_crack.py
改造范围: password_cracker.py
```

#### 1.4 目录扫描并发化

将 `dir_scanner.py` 改为 `ThreadPoolExecutor` 或 `asyncio + aiohttp` 实现高并发请求，显著缩短大批量字典扫描时间。

```
改造范围: dir_scanner.py
```

---

### 第二阶段：能力扩展（中期）

#### 2.1 UDP 端口扫描

新增 UDP 探测模块，向常见 UDP 服务（DNS/53、SNMP/161、NTP/123 等）发送探针包，根据响应判断端口开放状态。

```
新增模块: udp_scanner.py
改造范围: safescan_lite.py 流程编排
```

#### 2.2 Web 漏洞主动检测

在目录扫描基础上新增轻量级漏洞检测插件：

| 检测项 | 方法 |
|--------|------|
| SQL 注入 | 在 URL 参数中注入单引号/`AND 1=1`，检测报错或响应差异 |
| XSS | 注入 `<script>alert(1)</script>` 检测回显 |
| 备份文件泄露 | 扩展字典，探测 `.bak`、`.swp`、`.tar.gz` 等后缀 |
| 目录遍历 | 注入 `../` 路径检测文件读取 |

```
新增模块: web_vuln_scanner.py
关联改造: dir_scanner.py、dicts/dirs.txt
```

#### 2.3 漏洞指纹库大规模扩充

将 `vuln_fingerprint.json` 从 3 条扩充至 100+ 条，覆盖常见中间件（Tomcat、Nginx、IIS）、数据库（MySQL、Redis、MongoDB）、网络设备等。同时支持从远程 URL 拉取最新规则。

```
新增模块: fingerprint_updater.py (远程规则拉取与本地缓存)
改造范围: vuln_fingerprint.json
```

#### 2.4 HTML 报告升级

- 端口扫描结果以表格形式展示（端口 / 服务 / Banner / 关联漏洞）
- 弱口令结果以高亮卡片展示
- 漏洞匹配结果按严重等级（高危/中危/低危）分色标注
- 引入 Chart.js 生成风险等级饼图

```
改造范围: reporter.py
```

---

### 第三阶段：工程化与协作（长期）

#### 3.1 配置中心

将散落在代码中的硬编码参数（超时、线程数、User-Agent、字典路径）统一收敛到 `config.yaml`，支持多 Profile 切换（如"快速扫描"/"深度扫描"）。

```
新增文件: config.yaml
新增模块: config_loader.py
改造范围: 全部模块
```

#### 3.2 分布式扫描

引入 Redis + Celery 实现多节点分布式扫描：
- Redis 作为任务队列与结果缓存
- Celery Worker 部署于多台主机并发执行扫描任务
- 主节点汇总结果并生成统一报告

```
新增模块: task_broker.py, worker.py
新增依赖: redis, celery
```

#### 3.3 资产管理与历史对比

- 使用 SQLite 存储历次扫描结果
- 支持对同一目标多次扫描结果进行 Diff 对比（新开放端口、新增漏洞、修复情况）
- 提供资产视图：按 IP 聚合展示完整安全状态

```
新增模块: database.py, diff_analyzer.py
新增依赖: sqlite3 (内置)
```

#### 3.4 插件化架构

定义统一的扫描插件接口（`BaseScanner`），将端口扫描、目录爆破、弱口令检测、漏洞匹配全部实现为可插拔插件，通过入口文件动态加载，方便第三方贡献。

```
新增模块: plugin_base.py, plugin_loader.py
改造范围: safescan_lite.py 及全部扫描模块
```

#### 3.5 实时 Web 仪表盘

基于 Flask + WebSocket 构建一个轻量级 Web 控制台：
- 浏览器端输入目标发起扫描
- 实时推送扫描进度与阶段性发现
- 历史报告在线查阅与导出（PDF）

```
新增模块: web_dashboard/
新增依赖: flask, flask-socketio
```

---

## 扩展路线图总览

```
阶段一 (短期)           阶段二 (中期)              阶段三 (长期)
──────────────────────────────────────────────────────────────
Banner 抓取      ──►   UDP 端口扫描         ──►   配置中心
CLI 参数支持     ──►   Web 漏洞检测         ──►   分布式扫描
弱口令扩展       ──►   漏洞指纹库扩充       ──►   资产管理 + 历史对比
目录扫描并发化   ──►   HTML 报告升级        ──►   插件化架构
                                               ──►   Web 仪表盘
```

---

## 安全声明

本工具仅供授权的安全测试、CTF 竞赛、教学研究及防御性用途使用。对未获得明确授权的目标进行扫描可能违反法律法规。使用者应确保遵守所在地区相关法律规定，并自行承担所有使用风险。

---

## 许可证

本项目仅供学习与合法安全测试使用。
