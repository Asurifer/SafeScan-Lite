import socket
import time

def port_scan(target_ip, start_port, end_port):
    """
    端口扫描核心函数（TCP全连接扫描）
    :param target_ip: 目标IP地址（字符串，如"127.0.0.1"）
    :param start_port: 起始端口（整数，如1）
    :param end_port: 结束端口（整数，如100）
    :return: 开放端口列表（包含端口号和对应服务）
    """
    open_ports = []
    # 常见端口-服务映射表（后续可扩展，放入配置文件）
    port_service_map = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        6379: "Redis"
    }

    print(f"[*] 开始扫描目标 {target_ip}，端口范围 {start_port}-{end_port}")
    start_time = time.time()

    # 遍历端口范围进行扫描
    for port in range(start_port, end_port + 1):
        try:
            # 创建TCP套接字
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 设置超时时间（避免卡顿，推荐0.5秒）
            sock.settimeout(0.5)
            # 尝试连接目标IP和端口
            result = sock.connect_ex((target_ip, port))
            # 连接成功（返回0）说明端口开放
            if result == 0:
                service = port_service_map.get(port, "Unknown Service")
                open_port_info = {
                    "port": port,
                    "service": service
                }
                open_ports.append(open_port_info)
                print(f"[+] 端口 {port} 开放，对应服务：{service}")
            # 关闭套接字
            sock.close()
        except Exception as e:
            # 忽略扫描过程中的异常（如网络错误）
            continue

    end_time = time.time()
    scan_duration = round(end_time - start_time, 2)
    print(f"[*] 扫描完成，耗时 {scan_duration} 秒")
    print(f"[*] 共发现 {len(open_ports)} 个开放端口")

    return open_ports

# 测试代码（运行该文件可单独测试端口扫描功能）
if __name__ == "__main__":
    target = "127.0.0.1"  # 本地回环地址，可替换为其他目标
    start = 1
    end = 1000
    port_scan(target, start, end)