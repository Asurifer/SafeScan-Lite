import paramiko
from ftplib import FTP
import telnetlib
import smtplib
import socket
import time
import struct
import hashlib
import base64
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------- SSH 弱口令检测 ----------------------
def ssh_brute_force(target_ip, port, username_list, password_list):
    """
    SSH服务弱口令爆破
    """
    print(f" 开始对 {target_ip}:{port} 进行SSH弱口令爆破")
    for username in username_list:
        for password in password_list:
            try:
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh_client.connect(
                    hostname=target_ip,
                    port=port,
                    username=username,
                    password=password,
                    timeout=5
                )
                print(f" SSH弱口令发现：用户名={username}，密码={password}")
                ssh_client.close()
                return (username, password)
            except Exception:
                continue
    print(f" SSH弱口令爆破完成，未发现有效账号密码")
    return None

# ---------------------- FTP 弱口令检测 ----------------------
def ftp_brute_force(target_ip, port, username_list, password_list):
    """
    FTP服务弱口令爆破
    """
    print(f" 开始对 {target_ip}:{port} 进行FTP弱口令爆破")
    for username in username_list:
        for password in password_list:
            try:
                ftp_client = FTP()
                ftp_client.timeout = 5
                ftp_client.connect(target_ip, port)
                ftp_client.login(username, password)
                print(f" FTP弱口令发现：用户名={username}，密码={password}")
                ftp_client.quit()
                return (username, password)
            except Exception:
                continue
    print(f" FTP弱口令爆破完成，未发现有效账号密码")
    return None

# ---------------------- Telnet 弱口令检测 ----------------------
def telnet_brute_force(target_ip, port, username_list, password_list):
    """
    Telnet服务弱口令爆破
    """
    print(f" 开始对 {target_ip}:{port} 进行Telnet弱口令爆破")
    for username in username_list:
        for password in password_list:
            try:
                tn = telnetlib.Telnet(target_ip, port, timeout=5)
                # 等待登录提示
                tn.read_until(b"login: ", timeout=3)
                tn.write(username.encode("utf-8") + b"\n")
                tn.read_until(b"Password: ", timeout=3)
                tn.write(password.encode("utf-8") + b"\n")
                time.sleep(1)
                # 读取响应判断是否登录成功
                output = tn.read_very_eager().decode("utf-8", errors="replace")
                tn.close()
                # 常见登录失败标志
                fail_keywords = ["Login incorrect", "login incorrect", "Login failed",
                                 "Authentication failed", "invalid", "Incorrect"]
                if not any(kw in output for kw in fail_keywords) and output.strip():
                    print(f" Telnet弱口令发现：用户名={username}，密码={password}")
                    return (username, password)
            except EOFError:
                # 连接被关闭，可能登录成功
                print(f" Telnet弱口令发现（EOF）：用户名={username}，密码={password}")
                return (username, password)
            except Exception:
                continue
    print(f" Telnet弱口令爆破完成，未发现有效账号密码")
    return None

# ---------------------- MySQL 弱口令检测 ----------------------
def mysql_brute_force(target_ip, port, username_list, password_list):
    """
    MySQL服务弱口令爆破（基于原生 socket 模拟握手，避免依赖 pymysql）
    """
    print(f" 开始对 {target_ip}:{port} 进行MySQL弱口令爆破")
    for username in username_list:
        for password in password_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target_ip, port))
                # 读取服务端握手包
                greeting = sock.recv(4096)
                if len(greeting) < 5:
                    sock.close()
                    continue

                # 解析服务端握手包中的认证插件名和salt
                # 简化处理：检查是否为 MySQL 协议（首字节 0x0a 或 packet 以版本号开头）
                if not greeting[4:].startswith(b"5.") and not greeting[4:].startswith(b"8.") and not greeting[4:].startswith(b"10."):
                    sock.close()
                    continue

                # 提取 salt (mysql_native_password)
                # salt1 = greeting[13:21], salt2 = after 0x00 terminator following server capabilities
                try:
                    end_of_salt2 = greeting.find(b"\x00", 40)
                    salt = greeting[13:21]
                    if end_of_salt2 > 40:
                        salt += greeting[40:end_of_salt2]
                    salt = salt[:20]
                except Exception:
                    sock.close()
                    continue

                # 使用 mysql_native_password 计算认证哈希
                import hashlib
                # Stage1: SHA1(password)
                sha1_pass = hashlib.sha1(password.encode()).digest()
                # Stage2: SHA1(SHA1(password))
                sha1_sha1_pass = hashlib.sha1(sha1_pass).digest()
                # Stage3: SHA1(salt + SHA1(SHA1(password))) XOR SHA1(password)
                xor_input = salt + sha1_sha1_pass
                sha1_salt_sha1 = hashlib.sha1(xor_input).digest()
                auth_response = bytes(a ^ b for a, b in zip(sha1_pass, sha1_salt_sha1))

                # 构建握手响应包 (简化版)
                # 客户端标志 = 0x0281a200 (支持 mysql_native_password)
                client_flags = 0x0281a200
                max_packet = 16777215
                charset = 33  # utf8

                payload = bytearray()
                payload += struct.pack("<I", client_flags)       # 4 bytes
                payload += struct.pack("<I", max_packet)         # 4 bytes
                payload += struct.pack("<B", charset)            # 1 byte
                payload += b"\x00" * 23                          # filler
                payload += username.encode() + b"\x00"           # username
                payload += struct.pack("<B", len(auth_response)) # auth len
                payload += auth_response                        # auth data
                payload += b"mysql_native_password\x00"          # auth plugin name

                # 包头 (4 bytes: 3 byte length + 1 byte seq)
                packet_len = len(payload)
                header = struct.pack("<I", packet_len)[:3] + bytes([1])

                sock.sendall(header + payload)
                response = sock.recv(4096)
                sock.close()

                # 检查响应：OK packet 首字节为 0x00，ERR packet 为 0xFF
                if response and len(response) > 4:
                    if response[4] == 0x00:
                        print(f" MySQL弱口令发现：用户名={username}，密码={password}")
                        return (username, password)
            except Exception:
                try:
                    sock.close()
                except Exception:
                    pass
                continue
    print(f" MySQL弱口令爆破完成，未发现有效账号密码")
    return None

# ---------------------- SMTP 弱口令检测 ----------------------
def smtp_brute_force(target_ip, port, username_list, password_list):
    """
    SMTP服务弱口令爆破（使用 AUTH LOGIN 方式）
    """
    import base64
    print(f" 开始对 {target_ip}:{port} 进行SMTP弱口令爆破")
    for username in username_list:
        for password in password_list:
            try:
                smtp = smtplib.SMTP(target_ip, port, timeout=5)
                smtp.ehlo("safescan")
                # 检查是否支持 AUTH LOGIN
                if smtp.has_extn("auth"):
                    smtp.login(username, password)
                    print(f" SMTP弱口令发现：用户名={username}，密码={password}")
                    smtp.quit()
                    return (username, password)
                smtp.quit()
            except smtplib.SMTPAuthenticationError:
                continue
            except Exception:
                continue
    print(f" SMTP弱口令爆破完成，未发现有效账号密码")
    return None

# ---------------------- 字典加载工具函数 ----------------------
def load_dict(file_path):
    """
    加载用户名/密码字典文件
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            dict_list = list(set([line.strip() for line in f if line.strip()]))
        return dict_list
    except FileNotFoundError:
        print(f" 字典文件 {file_path} 未找到，请检查路径")
        return []

# ---------------------- 弱口令检测入口函数 ----------------------
def password_crack(target_ip, open_ports):
    """
    弱口令检测入口，根据开放端口自动选择对应服务进行爆破
    """
    brute_result = {}
    username_list = load_dict(os.path.join(BASE_DIR, "username.txt"))
    password_list = load_dict(os.path.join(BASE_DIR, "password.txt"))

    if not username_list or not password_list:
        print(" 用户名/密码字典加载失败，无法进行弱口令爆破")
        return brute_result

    for port_info in open_ports:
        port = port_info["port"]
        service = port_info.get("service", "").upper()

        if service == "SSH" or port == 22:
            result = ssh_brute_force(target_ip, port, username_list, password_list)
            if result:
                brute_result["SSH"] = result
        elif service == "FTP" or port == 21:
            result = ftp_brute_force(target_ip, port, username_list, password_list)
            if result:
                brute_result["FTP"] = result
        elif service == "TELNET" or port == 23:
            result = telnet_brute_force(target_ip, port, username_list, password_list)
            if result:
                brute_result["TELNET"] = result
        elif service == "MYSQL" or port == 3306:
            result = mysql_brute_force(target_ip, port, username_list, password_list)
            if result:
                brute_result["MySQL"] = result
        elif service == "SMTP" or port in [25, 587]:
            result = smtp_brute_force(target_ip, port, username_list, password_list)
            if result:
                brute_result["SMTP"] = result

    return brute_result

# 测试代码
if __name__ == "__main__":
    target = "127.0.0.1"
    mock_open_ports = [
        {"port": 21, "service": "FTP"},
        {"port": 22, "service": "SSH"},
        {"port": 23, "service": "Telnet"},
        {"port": 3306, "service": "MySQL"},
        {"port": 25, "service": "SMTP"},
    ]
    password_crack(target, mock_open_ports)
