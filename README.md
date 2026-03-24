# SafeScan Lite

轻量级网络安全扫描工具，专为网安学习者设计，整合端口扫描、弱口令检测、简易漏洞指纹匹配三大核心功能，基于Python开发，后续可扩展更多功能。

环境要求与配置

基础环境

- 操作系统：Windows 10/11、Ubuntu 20.04+、macOS

- Python 版本：3.9+

- 第三方依赖：paramiko==2.12.0

快速配置

# 安装依赖（Windows/Ubuntu/macOS通用，Ubuntu/macOS替换pip为pip3）
pip install paramiko==2.12.0

快速开始

1. 将项目所有文件（port_scanner.py、password_cracker.py、safescan_lite.py、username.txt、password.txt、vuln_fingerprint.json）放入同一目录。

2. 终端进入项目目录，执行命令：
        # Windows
python safescan_lite.py
# Ubuntu/macOS
python3.9 safescan_lite.py

3. 输入目标IP（如127.0.0.1），等待扫描完成，查看终端输出的扫描报告。

核心文件说明

port_scanner.py       # 端口扫描模块
password_cracker.py   # 弱口令检测模块
safescan_lite.py      # 项目主程序（整合+报告生成）
username.txt/password.txt # 弱口令字典（可自定义）
vuln_fingerprint.json # 漏洞指纹库（可扩展）

注意事项

- 本工具仅用于合法的网络安全自查、学习研究，严禁未授权扫描他人目标，使用者自行承担法律责任。

- 运行报错请检查：文件是否齐全、Python版本及依赖是否安装正确。

📄 开源协议

本项目采用MIT开源协议，允许自由使用、修改、分发。

贡献与联系

欢迎提交Issue、Pull Request完善项目；
