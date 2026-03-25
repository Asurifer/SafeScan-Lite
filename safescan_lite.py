import json
from port_scanner import port_scan
from password_cracker import password_crack
from dir_scanner import scan_directories
from reporter import generate_html_report

def vuln_fingerprint_match(target_ip, open_ports):
    """
    简易漏洞指纹匹配
    :param target_ip: 目标IP
    :param open_ports: 开放端口列表
    :return: 漏洞匹配结果列表
    """
    vuln_results = []
    # 加载漏洞指纹库
    try:
        with open("vuln_fingerprint.json", 'r', encoding='utf-8') as f:
            vuln_data = json.load(f)
        vuln_fingerprints = vuln_data.get("vulnerabilities", [])
    except FileNotFoundError:
        print(f" 漏洞指纹库文件 vuln_fingerprint.json 未找到，跳过漏洞匹配")
        return vuln_results

    print(f" 开始进行漏洞指纹匹配")
    # 遍历开放端口，匹配漏洞指纹
    for port_info in open_ports:
        port = port_info["port"]
        service = port_info["service"]
        for vuln in vuln_fingerprints:
            if vuln["port"] == port and vuln["service"] == service:
                vuln_results.append(vuln)
                print(f"[!] 发现漏洞：{vuln['vuln_name']}（{vuln['vuln_level']}）")
                print(f"    漏洞描述：{vuln['vuln_desc']}")
                print(f"    修复建议：{vuln['fix_suggestion']}\n")

    if not vuln_results:
        print(f" 未发现匹配的漏洞指纹")
    return vuln_results

def generate_scan_report(target_ip, open_ports, brute_result, vuln_results):
    """
    生成简易扫描报告
    :param target_ip: 目标IP
    :param open_ports: 开放端口列表
    :param brute_result: 弱口令检测结果
    :param vuln_results: 漏洞匹配结果
    :return: 无返回值，直接打印报告
    """
    print("="*60)
    print(f"[最终扫描报告] 目标IP：{target_ip}")
    print("="*60)

    # 1. 开放端口汇总
    print("\n1. 开放端口汇总")
    print("-"*30)
    for port_info in open_ports:
        print(f"   端口 {port_info['port']}：{port_info['service']}")

    # 2. 弱口令检测汇总
    print("\n2. 弱口令检测汇总")
    print("-"*30)
    if brute_result:
        for service, (username, password) in brute_result.items():
            print(f"   {service} 服务：用户名={username}，密码={password}")
    else:
        print("   未发现任何弱口令")

    # 3. 漏洞匹配汇总
    print("\n3. 漏洞匹配汇总")
    print("-"*30)
    if vuln_results:
        for vuln in vuln_results:
            print(f"   漏洞名称：{vuln['vuln_name']}（{vuln['vuln_level']}）")
            print(f"   修复建议：{vuln['fix_suggestion']}\n")
    else:
        print("   未发现匹配的已知漏洞")

    print("="*60)
    print(" 扫描报告生成完成")

# ---------------------- 项目主入口 ----------------------
if __name__ == "__main__":
    # 配置扫描参数（后续可扩展为命令行参数输入，如argparse库）
    TARGET_IP = input("请输入目标IP地址：")  # 交互式输入目标IP，更友好
    START_PORT = 1
    END_PORT = 1000

    # 步骤1：端口扫描
    open_ports_list = port_scan(TARGET_IP, START_PORT, END_PORT)

    # 步骤2：弱口令检测（仅当有开放端口时执行）
    brute_force_result = {}
    if open_ports_list:
        brute_force_result = password_crack(TARGET_IP, open_ports_list)

    # 步骤3：漏洞指纹匹配
    vuln_match_result = vuln_fingerprint_match(TARGET_IP, open_ports_list)
    
    # 步骤4： Web扫描通常需要URL，这里我们简单拼接 http:// 作为默认测试
    target_url = f"http://{TARGET_IP}" 
    dir_scan_result = scan_directories(target_url)

    # 步骤5：生成最终扫描报告
    generate_scan_report(TARGET_IP, open_ports_list, brute_force_result, vuln_match_result)

    #步骤6：整合所有扫描数据，生成 HTML 可视化报告
    all_results = {
        'target': TARGET_IP,
        'ports': open_ports_list,       # 端口结果
        'brute': brute_force_result,    # 弱口令结果
        'vulns': vuln_match_result,     # 漏洞匹配结果
        'dirs': dir_scan_result         # 目录爆破结果
    }
    print("\n 正在生成可视化 HTML 报告...")
    # 报告文件名以目标 IP 命名，防止覆盖
    generate_html_report(all_results, filename=f"report_{TARGET_IP}.html")







