import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# 常见服务的 Banner 正则指纹库
SERVICE_FINGERPRINTS = {
    "SSH": [
        (r"SSH-([\d.]+)-?(?:OpenSSH[_-]?([\d.p]+))?", "OpenSSH"),
        (r"SSH-([\d.]+)-?(?:dropbear[_-]?([\d.]+))?", "Dropbear"),
    ],
    "HTTP": [
        (r"Server:\s*Apache/([\d.]+)", "Apache"),
        (r"Server:\s*nginx/([\d.]+)", "Nginx"),
        (r"Server:\s*Microsoft-IIS/([\d.]+)", "IIS"),
        (r"Server:\s*Tomcat/([\d.]+)", "Tomcat"),
        (r"Server:\s*Caddy", "Caddy"),
        (r"Server:\s*LiteSpeed", "LiteSpeed"),
    ],
    "FTP": [
        (r"(\d{3})\s*(?:Welcome to )?(?:vsftpd|ProFTPD|Pure-FTPd|FileZilla)\s*([\d.]+)?", None),
        (r"([\d]{3})\s*(?:Microsoft FTP Service)", "IIS-FTP"),
    ],
    "SMTP": [
        (r"(\d{3})\s*(.+)", None),
        (r"ESMTP\s*(Postfix|Exim|Sendmail)\s*([\d.]+)?", None),
    ],
    "MySQL": [
        (r"([\d.]+)-MariaDB", "MariaDB"),
        (r"([\d.]+)\x00", "MySQL"),
    ],
    "Redis": [
        (r"-ERR.*", "Redis"),
        (r"\+PONG", "Redis"),
    ],
    "Telnet": [
        (r"Ubuntu\s*([\d.]+)", "Ubuntu-Telnet"),
        (r"Debian\s*([\d.]+)", "Debian-Telnet"),
        (r"CentOS\s*[\d.]+", "CentOS-Telnet"),
    ],
}

# 针对不同端口的 Banner 探针数据
PROBES = {
    "HTTP": b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
    "SSH": None,       # SSH 连接后自动发送 Banner
    "FTP": None,        # FTP 连接后自动发送 Banner
    "SMTP": None,       # SMTP 连接后自动发送 Banner
    "MySQL": None,      # MySQL 连接后自动发送 Banner
    "Redis": b"PING\r\n",
    "Telnet": None,
}


def grab_banner(ip, port, service_hint=None, timeout=3):
    """
    尝试连接到目标端口并抓取 Banner 信息。
    返回格式: {"port": port, "service": "xxx", "version": "x.x", "banner_raw": "..."}
    """
    result = {"port": port, "service": service_hint or "Unknown", "version": "", "banner_raw": ""}

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            banner_raw = ""
            service_name = service_hint or "Unknown"

            # 根据端口或服务提示选择探针
            probe_key = service_hint.upper() if service_hint else guess_service_by_port(port)
            probe_data = PROBES.get(probe_key)

            if probe_data is not None and probe_key == "HTTP":
                # HTTP 探针
                s.sendall(probe_data % ip.encode())
                while True:
                    try:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        banner_raw += chunk.decode("utf-8", errors="replace")
                    except socket.timeout:
                        break
            elif probe_data is not None and probe_key == "Redis":
                s.sendall(probe_data)
                chunk = s.recv(1024)
                banner_raw = chunk.decode("utf-8", errors="replace")
            else:
                # 直接等待服务端 Banner (SSH, FTP, SMTP 等)
                try:
                    chunk = s.recv(4096)
                    banner_raw = chunk.decode("utf-8", errors="replace")
                except socket.timeout:
                    pass

            result["banner_raw"] = banner_raw[:500]  # 截断过长 Banner
            if banner_raw:
                # 指纹匹配
                fp_results = SERVICE_FINGERPRINTS.get(probe_key, [])
                matched = match_fingerprint(banner_raw, fp_results)
                if matched:
                    result["service"] = matched["name"]
                    result["version"] = matched.get("version", "")

    except Exception:
        pass

    return result


def guess_service_by_port(port):
    try:
        return socket.getservbyport(port).upper() if port < 1024 else "Unknown"
    except Exception:
        common_map = {3306: "MySQL", 6379: "Redis", 8080: "HTTP", 8443: "HTTP",
                      27017: "MongoDB", 5432: "PostgreSQL", 1433: "MSSQL"}
        return common_map.get(port, "Unknown")


def match_fingerprint(banner, fingerprints):
    for pattern, name in fingerprints:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
            actual_name = name if name else m.group(0)[:30]
            return {"name": actual_name, "version": version}
    return None


def batch_grab_banners(ip, open_ports, threads=20):
    """对开放的端口列表批量抓取 Banner"""
    print(f"\n 开始对 {ip} 进行 Banner 抓取（{len(open_ports)} 个端口）...")
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(grab_banner, ip, p["port"], p.get("service")): p
            for p in open_ports
        }
        for future in as_completed(futures):
            res = future.result()
            if res["banner_raw"]:
                print(f"  Banner 获取成功 [{res['port']}]: {res['service']} {res['version']}")
            else:
                print(f"  Banner 未获取 [{res['port']}]: 无响应或非文本协议")
            results.append(res)

    return results


if __name__ == "__main__":
    test_results = batch_grab_banners("127.0.0.1", [
        {"port": 22, "service": "SSH"},
        {"port": 80, "service": "HTTP"},
        {"port": 3306, "service": "MySQL"},
    ])
    for r in test_results:
        print(r)
