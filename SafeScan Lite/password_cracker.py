import paramiko
from ftplib import FTP
import time

# ---------------------- SSH 弱口令检测 ----------------------
def ssh_brute_force(target_ip, port, username_list, password_list):
    """
    SSH服务弱口令爆破
    :param target_ip: 目标IP
    :param port: SSH端口（默认22）
    :param username_list: 用户名列表
    :param password_list: 密码列表
    :return: 成功的账号密码（tuple），失败返回None
    """
    print(f" 开始对 {target_ip}:{port} 进行SSH弱口令爆破")
    for username in username_list:
        for password in password_list:
            try:
                # 创建SSH客户端实例
                ssh_client = paramiko.SSHClient()
                # 自动添加未知主机密钥（避免首次连接报错）
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                # 尝试连接SSH服务
                ssh_client.connect(
                    hostname=target_ip,
                    port=port,
                    username=username,
                    password=password,
                    timeout=5
                )
                # 连接成功，返回账号密码
                print(f" SSH弱口令发现：用户名={username}，密码={password}")
                ssh_client.close()
                return (username, password)
            except Exception as e:
                # 认证失败，继续下一个密码
                continue
    print(f" SSH弱口令爆破完成，未发现有效账号密码")
    return None

# ---------------------- FTP 弱口令检测 ----------------------
def ftp_brute_force(target_ip, port, username_list, password_list):
    """
    FTP服务弱口令爆破（使用Python内置ftplib，无需额外依赖）
    :param target_ip: 目标IP
    :param port: FTP端口（默认21）
    :param username_list: 用户名列表
    :param password_list: 密码列表
    :return: 成功的账号密码（tuple），失败返回None
    """
    print(f" 开始对 {target_ip}:{port} 进行FTP弱口令爆破")
    for username in username_list:
        for password in password_list:
            try:
                # 创建FTP客户端实例
                ftp_client = FTP()
                # 设置超时时间
                ftp_client.timeout = 5
                # 尝试连接FTP服务
                ftp_client.connect(target_ip, port)
                # 尝试登录
                ftp_client.login(username, password)
                # 登录成功，返回账号密码
                print(f" FTP弱口令发现：用户名={username}，密码={password}")
                ftp_client.quit()
                return (username, password)
            except Exception as e:
                # 认证失败，继续下一个密码
                continue
    print(f" FTP弱口令爆破完成，未发现有效账号密码")
    return None

# ---------------------- 字典加载工具函数 ----------------------
def load_dict(file_path):
    """
    加载用户名/密码字典文件
    :param file_path: 字典文件路径
    :return: 字典列表（去重，去除空行）
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # 读取每行，去除换行符和空格，去重，过滤空行
            dict_list = list(set([line.strip() for line in f if line.strip()]))
        return dict_list
    except FileNotFoundError:
        print(f" 字典文件 {file_path} 未找到，请检查路径")
        return []

# ---------------------- 弱口令检测入口函数 ----------------------
def password_crack(target_ip, open_ports):
    """
    弱口令检测入口，根据开放端口自动选择对应服务进行爆破
    :param target_ip: 目标IP
    :param open_ports: 开放端口列表（来自端口扫描模块）
    :return: 弱口令结果字典
    """
    brute_result = {}
    # 加载字典文件
    username_list = load_dict("username.txt")
    password_list = load_dict("password.txt")

    # 判读字典是否加载成功
    if not username_list or not password_list:
        print(" 用户名/密码字典加载失败，无法进行弱口令爆破")
        return brute_result

    # 遍历开放端口，对支持的服务进行爆破
    for port_info in open_ports:
        port = port_info["port"]
        service = port_info["service"]

        if service == "SSH" and port == 22:
            ssh_result = ssh_brute_force(target_ip, port, username_list, password_list)
            if ssh_result:
                brute_result["SSH"] = ssh_result
        elif service == "FTP" and port == 21:
            ftp_result = ftp_brute_force(target_ip, port, username_list, password_list)
            if ftp_result:
                brute_result["FTP"] = ftp_result

    return brute_result

# 测试代码（运行该文件可单独测试弱口令检测功能，需先确保目标SSH/FTP端口开放）
if __name__ == "__main__":
    target = "127.0.0.1"
    # 模拟端口扫描结果（实际使用时来自port_scan函数）
    mock_open_ports = [
        {"port": 21, "service": "FTP"},
        {"port": 22, "service": "SSH"}
    ]
    password_crack(target, mock_open_ports)