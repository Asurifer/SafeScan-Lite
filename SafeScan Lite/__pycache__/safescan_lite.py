import json
import argparse
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from port_scanner import port_scan
from banner_grabber import batch_grab_banners
from udp_scanner import udp_scan
from password_cracker import password_crack
from dir_scanner import scan_directories
from web_vuln_scanner import web_vuln_scan
from reporter import generate_html_report


def vuln_fingerprint_match(target_ip, open_ports):
    """
    简易漏洞指纹匹配
    :param target_ip: 目标IP
    :param open_ports: 开放端口列表（可含Banner信息）
    :return: 漏洞匹配结果列表
    """
    vuln_results = []
    try:
        fp = os.path.join(BASE_DIR, "vuln_fingerprint.json")
        with open(fp, "r", encoding="utf-8") as f:
            vuln_data = json.load(f)
        vuln_fingerprints = vuln_data.get("vulnerabilities", [])
    except FileNotFoundError:
        print(f" 漏洞指纹库文件 vuln_fingerprint.json 未找到，跳过漏洞匹配")
        return vuln_results

    print(f" 开始进行漏洞指纹匹配")
    matched_ids = set()
    for port_info in open_ports:
        port = port_info["port"]
        service = port_info.get("service", "Unknown")
        for vuln in vuln_fingerprints:
            if vuln["port"] == port and vuln["service"].upper() == service.upper():
                key = (vuln["port"], vuln["vuln_name"])
                if key not in matched_ids:
                    matched_ids.add(key)
                    vuln_results.append(vuln)
                    print(f"[!] 发现漏洞：{vuln['vuln_name']}（{vuln['vuln_level']}）")
                    print(f"    漏洞描述：{vuln['vuln_desc']}")
                    print(f"    修复建议：{vuln['fix_suggestion']}\n")

    if not vuln_results:
        print(f" 未发现匹配的漏洞指纹")
    return vuln_results


def generate_scan_report(target_ip, open_ports, brute_result, vuln_results, dir_scan_result, web_vuln_results, udp_results):
    """
    生成简易扫描报告（终端输出）
    """
    print("=" * 60)
    print(f"[最终扫描报告] 目标IP：{target_ip}")
    print("=" * 60)

    # 1. 开放端口汇总
    print("\n1. TCP 开放端口汇总")
    print("-" * 30)
    if open_ports:
        for port_info in open_ports:
            service = port_info.get("service", "Unknown")
            version = port_info.get("version", "")
            v_str = f" ({version})" if version else ""
            print(f"   端口 {port_info['port']}：{service}{v_str}")
    else:
        print("   未发现 TCP 开放端口")

    # 2. UDP 端口
    print("\n2. UDP 开放端口汇总")
    print("-" * 30)
    if udp_results:
        for u in udp_results:
            print(f"   端口 {u['port']}：{u['service']} (UDP)")
    else:
        print("   未发现 UDP 开放端口")

    # 3. 弱口令检测汇总
    print("\n3. 弱口令检测汇总")
    print("-" * 30)
    if brute_result:
        for service, (username, password) in brute_result.items():
            print(f"   {service} 服务：用户名={username}，密码={password}")
    else:
        print("   未发现任何弱口令")

    # 4. 漏洞匹配汇总
    print("\n4. 漏洞匹配汇总")
    print("-" * 30)
    if vuln_results:
        for vuln in vuln_results:
            print(f"   漏洞名称：{vuln['vuln_name']}（{vuln['vuln_level']}）")
            print(f"   修复建议：{vuln['fix_suggestion']}\n")
    else:
        print("   未发现匹配的已知漏洞")

    # 5. 敏感目录
    print("\n5. 敏感目录/文件汇总")
    print("-" * 30)
    if dir_scan_result:
        for d in dir_scan_result:
            print(f"   {d['url']} (状态码: {d['status']})")
    else:
        print("   未发现敏感目录/文件")

    # 6. Web 漏洞检测
    print("\n6. Web 漏洞检测汇总")
    print("-" * 30)
    if web_vuln_results:
        for w in web_vuln_results:
            print(f"   [{w['type']}] {w.get('url', '')} — {w.get('evidence', '')}")
    else:
        print("   未发现 Web 漏洞")

    print("=" * 60)
    print(" 扫描报告生成完成")


def parse_args():
    parser = argparse.ArgumentParser(
        description="SafeScan Lite — 轻量级安全扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python safescan_lite.py -t 192.168.1.1
  python safescan_lite.py -t 10.0.0.1 -p 1-65535 --threads 100
  python safescan_lite.py -t 192.168.1.1 --no-udp --no-web
  python safescan_lite.py -t 192.168.1.1 -u http://192.168.1.1:8080
        """
    )
    parser.add_argument("-t", "--target", help="目标 IP 地址")
    parser.add_argument("-p", "--port-range", default="1-1000",
                        help="TCP 端口范围，格式: 起始-结束 (默认: 1-1000)")
    parser.add_argument("--threads", type=int, default=50,
                        help="TCP 端口扫描线程数 (默认: 50)")
    parser.add_argument("--dir-threads", type=int, default=30,
                        help="目录扫描线程数 (默认: 30)")
    parser.add_argument("-u", "--url", help="目标 URL（用于目录扫描和 Web 漏洞检测）")
    parser.add_argument("--dict", default=os.path.join(BASE_DIR, "dicts", "dirs.txt"),
                        help="目录扫描字典路径 (默认: dicts/dirs.txt)")
    parser.add_argument("--no-banner", action="store_true",
                        help="跳过 Banner 抓取")
    parser.add_argument("--no-udp", action="store_true",
                        help="跳过 UDP 端口扫描")
    parser.add_argument("--no-brute", action="store_true",
                        help="跳过弱口令爆破")
    parser.add_argument("--no-dir", action="store_true",
                        help="跳过目录扫描")
    parser.add_argument("--no-web", action="store_true",
                        help="跳过 Web 漏洞主动检测")
    parser.add_argument("--no-report", action="store_true",
                        help="不生成 HTML 可视化报告")
    parser.add_argument("-o", "--output", help="HTML 报告输出文件名")

    return parser.parse_args()


# ---------------------- 项目主入口 ----------------------
if __name__ == "__main__":
    args = parse_args()

    # 目标IP
    if args.target:
        target_ip = args.target
    else:
        target_ip = input("请输入目标IP地址：")

    # 解析端口范围
    try:
        start_port, end_port = map(int, args.port_range.split("-"))
    except ValueError:
        print(f" 端口范围格式错误: {args.port_range}，使用默认 1-1000")
        start_port, end_port = 1, 1000

    # 目标 URL
    if args.url:
        target_url = args.url
    else:
        target_url = f"http://{target_ip}"

    print("=" * 60)
    print(f" SafeScan Lite 扫描开始")
    print(f" 目标: {target_ip} | 端口范围: {start_port}-{end_port}")
    print("=" * 60)

    # 步骤1：TCP 端口扫描
    tcp_results = port_scan(target_ip, start_port, end_port, threads=args.threads)

    # 步骤2：Banner 抓取
    banner_results = []
    if not args.no_banner and tcp_results:
        banner_results = batch_grab_banners(target_ip, tcp_results)
        # 将 Banner 信息合并到端口结果
        banner_map = {b["port"]: b for b in banner_results if b["banner_raw"]}
        for port_info in tcp_results:
            b = banner_map.get(port_info["port"])
            if b and b.get("service") != "Unknown":
                port_info["service"] = b["service"]
            if b and b.get("version"):
                port_info["version"] = b["version"]
            if b:
                port_info["banner"] = b.get("banner_raw", "")

    # 步骤3：UDP 端口扫描
    udp_results = []
    if not args.no_udp:
        udp_results = udp_scan(target_ip)

    # 步骤4：弱口令检测
    brute_force_result = {}
    if not args.no_brute and tcp_results:
        brute_force_result = password_crack(target_ip, tcp_results)

    # 步骤5：漏洞指纹匹配
    vuln_match_result = vuln_fingerprint_match(target_ip, tcp_results)

    # 步骤6：目录扫描
    dir_scan_result = []
    if not args.no_dir:
        dir_scan_result = scan_directories(target_url, dict_file=args.dict, threads=args.dir_threads)

    # 步骤7：Web 漏洞主动检测
    web_vuln_results = []
    if not args.no_web:
        web_vuln_results = web_vuln_scan(target_url)

    # 步骤8：生成文本报告
    generate_scan_report(target_ip, tcp_results, brute_force_result,
                         vuln_match_result, dir_scan_result,
                         web_vuln_results, udp_results)

    # 步骤9：生成 HTML 可视化报告
    if not args.no_report:
        all_results = {
            "target": target_ip,
            "ports": tcp_results,
            "udp_ports": udp_results,
            "banners": banner_results,
            "brute": brute_force_result,
            "vulns": vuln_match_result,
            "dirs": dir_scan_result,
            "web_vulns": web_vuln_results,
        }
        filename = args.output if args.output else f"report_{target_ip}.html"
        report_path = os.path.join(BASE_DIR, filename)
        print("\n 正在生成可视化 HTML 报告...")
        generate_html_report(all_results, filename=report_path)
