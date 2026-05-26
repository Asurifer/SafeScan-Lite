import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed

# 常见 UDP 服务探针映射
UDP_PROBES = {
    53:   ("DNS",   b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"),
    123:  ("NTP",   b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    161:  ("SNMP",  b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"),
    137:  ("NetBIOS", b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"),
    520:  ("RIP",   b"\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    1900: ("UPnP",  b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"),
    5353: ("mDNS",  b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"),
}


def udp_probe(ip, port, timeout=2):
    """
    向目标 IP:Port 发送 UDP 探针包，根据响应判断端口是否开放。
    """
    probe = UDP_PROBES.get(port)
    if probe is None:
        return None

    service_name, payload = probe

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (ip, port))
            data, addr = s.recvfrom(2048)
            if data:
                print(f"  UDP 端口开放: {port} ({service_name})，响应长度 {len(data)} 字节")
                return {"port": port, "service": service_name, "proto": "UDP", "response_len": len(data)}
    except socket.timeout:
        pass
    except Exception:
        pass

    return None


def udp_scan(ip, ports=None, threads=30):
    """
    对目标 IP 执行 UDP 端口扫描。
    :param ip: 目标 IP
    :param ports: 要扫描的 UDP 端口列表，默认使用 UDP_PROBES 中定义的所有端口
    :param threads: 并发线程数
    :return: 开放的 UDP 端口列表
    """
    if ports is None:
        ports = sorted(UDP_PROBES.keys())

    print(f"\n 开始对 {ip} 进行 UDP 端口扫描（{len(ports)} 个端口），线程数: {threads}")
    open_ports = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(udp_probe, ip, port): port for port in ports}
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    print(f" UDP 扫描完成，发现 {len(open_ports)} 个开放端口")
    return open_ports


if __name__ == "__main__":
    result = udp_scan("127.0.0.1")
    print(result)
