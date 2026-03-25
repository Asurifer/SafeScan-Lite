import socket
from concurrent.futures import ThreadPoolExecutor

def check_port(ip, port, timeout=1):
    """检测单个端口的逻辑"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                # 这里简单返回服务名映射，你也可以用你原有的逻辑
                service = socket.getservbyport(port) if port < 1024 else "Unknown"
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