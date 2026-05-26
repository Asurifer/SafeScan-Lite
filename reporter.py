import datetime
import json


def _build_port_table(ports):
    """构建开放端口表格的 HTML 行"""
    rows = ""
    if ports:
        for p in ports:
            service = p.get("service", "Unknown")
            version = p.get("version", "")
            banner = p.get("banner", "")[:80]
            display = f"{service} {version}" if version else service
            rows += f"""
                <tr>
                    <td>{p['port']}</td>
                    <td>{display}</td>
                    <td title="{banner}">{banner[:60] if banner else '-'}</td>
                </tr>
            """
    else:
        rows = '<tr><td colspan="3" style="text-align:center; color:#999;">未发现 TCP 开放端口</td></tr>'
    return rows


def _build_udp_table(udp_ports):
    """构建 UDP 端口表格"""
    rows = ""
    if udp_ports:
        for u in udp_ports:
            rows += f"""
                <tr>
                    <td>{u['port']}</td>
                    <td>{u.get('service', 'Unknown')}</td>
                    <td>UDP</td>
                </tr>
            """
    else:
        rows = '<tr><td colspan="3" style="text-align:center; color:#999;">未发现 UDP 开放端口</td></tr>'
    return rows


def _build_brute_table(brute_result):
    """构建弱口令结果 HTML"""
    if not brute_result:
        return '<tr><td colspan="3" style="text-align:center; color:#28a745;">未发现弱口令</td></tr>'
    rows = ""
    for service, (username, password) in brute_result.items():
        rows += f"""
            <tr class="vuln-high">
                <td>{service}</td>
                <td>{username}</td>
                <td>{password}</td>
            </tr>
        """
    return rows


def _build_vuln_table(vuln_results):
    """构建漏洞匹配表格，按等级分色"""
    if not vuln_results:
        return '<tr><td colspan="4" style="text-align:center; color:#28a745;">未发现匹配的已知漏洞</td></tr>', {}

    level_order = {"高危": 3, "中危": 2, "低危": 1}
    sorted_vulns = sorted(vuln_results, key=lambda v: level_order.get(v.get("vuln_level", ""), 0), reverse=True)

    level_count = {}
    rows = ""
    for v in sorted_vulns:
        level = v.get("vuln_level", "未知")
        level_count[level] = level_count.get(level, 0) + 1
        cls = ""
        if "高危" in level:
            cls = "vuln-high"
        elif "中危" in level:
            cls = "vuln-medium"
        elif "低危" in level:
            cls = "vuln-low"

        rows += f"""
            <tr class="{cls}">
                <td><strong>{v['vuln_name']}</strong></td>
                <td><span class="badge-{cls}">{level}</span></td>
                <td>{v.get('port', '-')}</td>
                <td>{v.get('fix_suggestion', '-')}</td>
            </tr>
        """
    return rows, level_count


def _build_dirs_table(dirs_result):
    """构建敏感目录表格"""
    if not dirs_result:
        return '<tr><td colspan="2" style="text-align:center; color:#999;">未发现敏感目录/文件</td></tr>'
    rows = ""
    for d in dirs_result:
        sc = d["status"]
        cls = "status-200" if sc == 200 else ("status-403" if sc == 403 else "")
        rows += f"""
            <tr>
                <td><a href="{d['url']}" target="_blank">{d['url']}</a></td>
                <td class="{cls}">{sc}</td>
            </tr>
        """
    return rows


def _build_webvuln_table(web_vulns):
    """构建 Web 漏洞检测表格"""
    if not web_vulns:
        return '<tr><td colspan="3" style="text-align:center; color:#28a745;">未发现 Web 漏洞</td></tr>'
    rows = ""
    for w in web_vulns:
        rows += f"""
            <tr class="vuln-medium">
                <td><strong>{w['type']}</strong></td>
                <td>{w.get('url', '-')}</td>
                <td>{w.get('evidence', w.get('desc', '-'))}</td>
            </tr>
        """
    return rows


def _build_chart_data(level_count):
    """构建 Chart.js 饼图 JSON 数据"""
    labels = []
    values = []
    bg_colors = {"高危": "#dc3545", "中危": "#fd7e14", "低危": "#ffc107"}
    for level in ["高危", "中危", "低危"]:
        if level in level_count:
            labels.append(level)
            values.append(level_count[level])

    if not labels:
        labels = ["无漏洞"]
        values = [1]
        bg_colors_list = ["#28a745"]
    else:
        bg_colors_list = [bg_colors.get(l, "#6c757d") for l in labels]

    return json.dumps(labels, ensure_ascii=False), json.dumps(values), json.dumps(bg_colors_list, ensure_ascii=False)


def generate_html_report(results, filename="scan_report.html"):
    """
    将扫描结果字典转换为 HTML 可视化报告。
    results 格式:
    {
        'target': str,
        'ports': [...],
        'udp_ports': [...],
        'banners': [...],
        'brute': {...},
        'vulns': [...],
        'dirs': [...],
        'web_vulns': [...]
    }
    """
    time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target = results.get("target", "未知目标")

    ports = results.get("ports", [])
    udp_ports = results.get("udp_ports", [])
    brute = results.get("brute", {})
    vulns = results.get("vulns", [])
    dirs = results.get("dirs", [])
    web_vulns = results.get("web_vulns", [])

    port_rows = _build_port_table(ports)
    udp_rows = _build_udp_table(udp_ports)
    brute_rows = _build_brute_table(brute)
    vuln_rows, level_count = _build_vuln_table(vulns)
    dir_rows = _build_dirs_table(dirs)
    webvuln_rows = _build_webvuln_table(web_vulns)

    chart_labels, chart_values, chart_colors = _build_chart_data(level_count)

    total_tcp = len(ports)
    total_udp = len(udp_ports)
    total_vulns = len(vulns)
    total_brute = len(brute)

    html_content = f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>安全扫描报告 - {target}</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
        <style>
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            body {{
                font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
                background-color: #f0f2f5;
                color: #333;
                line-height: 1.6;
            }}
            .container {{
                max-width: 1100px;
                margin: 30px auto;
                padding: 0 20px;
            }}
            .header {{
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                color: #fff;
                padding: 30px 40px;
                border-radius: 12px 12px 0 0;
            }}
            .header h1 {{ font-size: 28px; margin-bottom: 8px; }}
            .header p {{ font-size: 14px; opacity: 0.85; }}
            .summary-cards {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 16px;
                padding: 24px 40px;
                background: #fff;
                border-bottom: 1px solid #eee;
            }}
            .card {{
                background: #f8f9fa;
                border-radius: 8px;
                padding: 18px 20px;
                text-align: center;
                border-left: 4px solid #3498db;
            }}
            .card.high {{ border-left-color: #dc3545; }}
            .card.warn {{ border-left-color: #fd7e14; }}
            .card .count {{ font-size: 32px; font-weight: 700; color: #2c3e50; }}
            .card .label {{ font-size: 13px; color: #6c757d; margin-top: 4px; }}
            .section {{
                background: #fff;
                padding: 30px 40px;
                border-bottom: 1px solid #eee;
            }}
            .section:last-child {{ border-radius: 0 0 12px 12px; border-bottom: none; }}
            h2 {{
                font-size: 20px;
                color: #2c3e50;
                margin-bottom: 18px;
                padding-bottom: 10px;
                border-bottom: 2px solid #e9ecef;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
                margin-top: 10px;
            }}
            th, td {{
                border: 1px solid #dee2e6;
                padding: 10px 14px;
                text-align: left;
                font-size: 14px;
            }}
            th {{
                background-color: #2c3e50;
                color: #fff;
                font-weight: 600;
            }}
            tr:nth-child(even) {{ background-color: #f8f9fa; }}
            tr:hover {{ background-color: #e9ecef; }}
            .vuln-high {{ background-color: #fff5f5 !important; }}
            .vuln-medium {{ background-color: #fff8f0 !important; }}
            .vuln-low {{ background-color: #fffefa !important; }}
            .badge-vuln-high {{
                display: inline-block;
                padding: 3px 10px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 600;
                color: #fff;
                background-color: #dc3545;
            }}
            .badge-vuln-medium {{
                display: inline-block;
                padding: 3px 10px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 600;
                color: #fff;
                background-color: #fd7e14;
            }}
            .badge-vuln-low {{
                display: inline-block;
                padding: 3px 10px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 600;
                color: #333;
                background-color: #ffc107;
            }}
            .status-200 {{ color: #28a745; font-weight: bold; }}
            .status-403 {{ color: #fd7e14; font-weight: bold; }}
            .chart-container {{
                display: flex;
                justify-content: center;
                align-items: center;
                margin: 20px 0;
            }}
            .chart-box {{
                width: 320px;
                height: 320px;
            }}
            .footer {{
                text-align: center;
                padding: 20px;
                color: #999;
                font-size: 13px;
            }}
            a {{ color: #3498db; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>SafeScan Lite 安全扫描报告</h1>
                <p><strong>目标：</strong>{target} &nbsp;|&nbsp; <strong>生成时间：</strong>{time_now}</p>
            </div>

            <div class="summary-cards">
                <div class="card">
                    <div class="count">{total_tcp}</div>
                    <div class="label">TCP 开放端口</div>
                </div>
                <div class="card">
                    <div class="count">{total_udp}</div>
                    <div class="label">UDP 开放端口</div>
                </div>
                <div class="card warn">
                    <div class="count">{total_vulns}</div>
                    <div class="label">匹配漏洞</div>
                </div>
                <div class="card high">
                    <div class="count">{total_brute}</div>
                    <div class="label">弱口令</div>
                </div>
            </div>

            <div class="section">
                <h2>漏洞风险分布</h2>
                <div class="chart-container">
                    <div class="chart-box">
                        <canvas id="vulnChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>TCP 开放端口与 Banner</h2>
                <table>
                    <tr>
                        <th>端口</th>
                        <th>服务</th>
                        <th>Banner / 响应摘要</th>
                    </tr>
                    {port_rows}
                </table>
            </div>

            <div class="section">
                <h2>UDP 开放端口</h2>
                <table>
                    <tr>
                        <th>端口</th>
                        <th>服务</th>
                        <th>协议</th>
                    </tr>
                    {udp_rows}
                </table>
            </div>

            <div class="section">
                <h2>弱口令检测结果</h2>
                <table>
                    <tr>
                        <th>服务</th>
                        <th>用户名</th>
                        <th>密码</th>
                    </tr>
                    {brute_rows}
                </table>
            </div>

            <div class="section">
                <h2>漏洞指纹匹配结果</h2>
                <table>
                    <tr>
                        <th>漏洞名称</th>
                        <th>风险等级</th>
                        <th>端口</th>
                        <th>修复建议</th>
                    </tr>
                    {vuln_rows}
                </table>
            </div>

            <div class="section">
                <h2>敏感目录/文件爆破</h2>
                <table>
                    <tr>
                        <th>发现的 URL</th>
                        <th>HTTP 状态码</th>
                    </tr>
                    {dir_rows}
                </table>
            </div>

            <div class="section">
                <h2>Web 漏洞主动检测</h2>
                <table>
                    <tr>
                        <th>漏洞类型</th>
                        <th>目标 URL</th>
                        <th>证据/说明</th>
                    </tr>
                    {webvuln_rows}
                </table>
            </div>

            <div class="footer">
                SafeScan Lite &copy; 仅供授权安全测试使用
            </div>
        </div>

        <script>
            const ctx = document.getElementById('vulnChart').getContext('2d');
            new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: {chart_labels},
                    datasets: [{{
                        data: {chart_values},
                        backgroundColor: {chart_colors},
                        borderWidth: 2,
                        borderColor: '#fff',
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{ font: {{ size: 14 }}, padding: 20 }}
                        }},
                        title: {{
                            display: true,
                            text: '漏洞等级分布（漏洞指纹匹配）',
                            font: {{ size: 16 }}
                        }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"\n 综合扫描报告已成功生成，请在浏览器打开查看: {filename}")
