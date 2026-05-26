import socket
from concurrent.futures import ThreadPoolExecutor

# 标准服务名映射，解决 socket.getservbyport 命名不一致问题
SERVICE_ALIAS = {
    "microsoft-ds": "SMB",
    "epmap": "DCE-RPC",
    "ms-wbt-server": "RDP",
    "http": "HTTP",
    "https": "HTTPS",
    "ssh": "SSH",
    "ftp": "FTP",
    "smtp": "SMTP",
    "telnet": "Telnet",
    "mysql": "MySQL",
    "ms-sql-s": "MSSQL",
    "domain": "DNS",
    "snmp": "SNMP",
    "ldap": "LDAP",
    "netbios-ssn": "NetBIOS",
}


def check_port(ip, port, timeout=1):
    """检测单个端口的逻辑"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                raw = socket.getservbyport(port) if port < 1024 else "Unknown"
                service = SERVICE_ALIAS.get(raw, raw)
                return {"port": port, "service": service}
    except:
        pass
    return None

def port_scan(ip, start_port, end_port, threads=50):
    print(f" 正在高并发扫描 {ip} ({start_port}-{end_port})，线程数: {threads}")
    open_ports = []
    
    # 使用线程池
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # 提交任务
        futures = [executor.submit(check_port, ip, port) for port in range(start_port, end_port + 1)]
        
        for future in futures:
            res = future.result()
            if res:
                print(f" 发现开放端口: {res['port']}")
                open_ports.append(res)
                
    return open_ports

# 测试代码（运行该文件可单独测试端口扫描功能）
if __name__ == "__main__":
    target = "127.0.0.1"  # 本地回环地址，可替换为其他目标
    start = 1
    end = 1000
    port_scan(target, start, end)