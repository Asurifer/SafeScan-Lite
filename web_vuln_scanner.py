import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


def check_sql_injection(url, timeout=5):
    """
    SQL 注入检测：在 URL 参数中注入单引号 / AND 1=1，对比响应差异。
    """
    findings = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    # 仅对有查询参数的 URL 做检测
    if "?" not in url:
        return findings

    base_url, query = url.split("?", 1)
    params = {}
    for pair in query.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[k] = v

    payloads = [
        ("'", "单引号注入探测"),
        ("\"", "双引号注入探测"),
        ("1' AND '1'='1", "AND 永真注入"),
        ("1' OR '1'='1", "OR 永真注入"),
        ("1 AND 1=1", "数字型 AND 注入"),
    ]

    for payload, desc in payloads:
        test_params = params.copy()
        first_key = list(test_params.keys())[0]
        test_params[first_key] = test_params[first_key] + payload
        try:
            resp = requests.get(base_url, params=test_params, headers=headers, timeout=timeout)
            # 检测常见的 SQL 错误回显
            sql_errors = [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"unclosed quotation mark",
                r"Microsoft OLE DB.*SQL",
                r"ODBC.*Driver",
                r"PostgreSQL.*ERROR",
                r"SQLite.*error",
                r"ORA-\d{5}",
                r"SQL command not properly ended",
            ]
            text = resp.text[:2000]
            for err_pattern in sql_errors:
                if re.search(err_pattern, text, re.IGNORECASE):
                    findings.append({
                        "type": "SQL注入",
                        "payload": payload,
                        "desc": desc,
                        "url": url,
                        "evidence": re.search(err_pattern, text, re.IGNORECASE).group(0)[:100],
                    })
                    break
        except requests.RequestException:
            pass

    return findings


def check_xss(url, timeout=5):
    """
    XSS 检测：在 URL 参数中注入 <script>alert(1)</script> 并检测回显。
    """
    findings = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    if "?" not in url:
        return findings

    base_url, query = url.split("?", 1)
    params = {}
    for pair in query.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[k] = v

    xss_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'><script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "javascript:alert(1)",
    ]

    for payload in xss_payloads:
        test_params = params.copy()
        first_key = list(test_params.keys())[0]
        test_params[first_key] = test_params[first_key] + payload
        try:
            resp = requests.get(base_url, params=test_params, headers=headers, timeout=timeout)
            if payload in resp.text:
                findings.append({
                    "type": "XSS",
                    "payload": payload,
                    "url": url,
                    "evidence": f"Payload 在响应中原样回显",
                })
                break
        except requests.RequestException:
            pass

    return findings


def check_backup_files(target_url, timeout=3):
    """
    备份文件泄露检测：探测常见备份后缀。
    """
    findings = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    backup_suffixes = [
        ".bak", ".swp", ".tar.gz", ".zip", ".rar", ".7z", ".sql",
        ".old", ".orig", ".save", ".backup", ".tgz", ".bz2",
        "~", ".git/config", ".env", ".DS_Store",
    ]

    base = target_url.rstrip("/")

    for suffix in backup_suffixes:
        test_url = base + suffix
        try:
            resp = requests.get(test_url, headers=headers, timeout=timeout, allow_redirects=False)
            if resp.status_code in [200, 206]:
                content_type = resp.headers.get("Content-Type", "")
                findings.append({
                    "type": "备份文件泄露",
                    "url": test_url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "content_type": content_type,
                })
        except requests.RequestException:
            pass

    return findings


def check_directory_traversal(target_url, timeout=5):
    """
    目录遍历检测：注入 ../ 路径检测文件读取。
    """
    findings = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    traversal_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../../../etc/hosts",
        "....//....//....//etc/passwd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    ]

    # 向 URL 路径追加遍历 Payload
    base = target_url.rstrip("/") + "/"

    for payload in traversal_payloads:
        test_url = base + payload
        try:
            resp = requests.get(test_url, headers=headers, timeout=timeout)
            text = resp.text[:2000]
            # Linux passwd 文件特征
            if "root:x:0:0:" in text:
                findings.append({
                    "type": "目录遍历",
                    "payload": payload,
                    "url": test_url,
                    "evidence": "读取到 /etc/passwd 文件内容",
                })
                break
            # Windows win.ini 特征
            if "[fonts]" in text.lower() or "[extensions]" in text.lower():
                findings.append({
                    "type": "目录遍历",
                    "payload": payload,
                    "url": test_url,
                    "evidence": "读取到 Windows 系统文件",
                })
                break
        except requests.RequestException:
            pass

    return findings


def web_vuln_scan(target_url, threads=10):
    """
    Web 漏洞主动检测入口，整合全部检测项。
    :param target_url: 目标 URL
    :param threads: 并发数
    :return: 漏洞发现列表
    """
    print(f"\n 开始对 {target_url} 进行 Web 漏洞主动检测...")
    all_findings = []

    # 先做备份文件检测（独立于 URL 参数）
    all_findings.extend(check_backup_files(target_url))

    # 如果 URL 有参数，再做注入类检测
    if "?" in target_url:
        all_findings.extend(check_sql_injection(target_url))
        all_findings.extend(check_xss(target_url))

    # 目录遍历检测
    all_findings.extend(check_directory_traversal(target_url))

    # 输出汇总
    if all_findings:
        print(f"\n [!] 共发现 {len(all_findings)} 个 Web 漏洞/风险项：")
        for f in all_findings:
            print(f"  [{f['type']}] {f.get('url', target_url)} — {f.get('evidence', f.get('desc', ''))}")
    else:
        print(f" 未发现 Web 漏洞")

    return all_findings


if __name__ == "__main__":
    result = web_vuln_scan("http://testphp.vulnweb.com/listproducts.php?cat=1")
    for r in result:
        print(r)
