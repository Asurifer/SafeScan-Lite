import datetime

def generate_html_report(results, filename="scan_report.html"):
    """
    将扫描结果字典转换为 HTML 可视化报告
    :param results: dict, 格式形如 {'target': 'xxx', 'dirs': [...], 'ports': [...]}
    """
    time_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target = results.get('target', '未知目标')
    
    # HTML 前端基础模板
    html_content = f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>安全扫描报告 - {target}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background-color: #f4f7f6; color: #333; }}
            .container {{ background-color: #fff; padding: 20px 40px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
            h1, h2 {{ color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 15px; margin-bottom: 30px; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background-color: #3498db; color: white; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            tr:hover {{ background-color: #f1f1f1; }}
            .status-200 {{ color: green; font-weight: bold; }}
            .status-403 {{ color: orange; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1> 轻量级安全扫描报告</h1>
            <p><strong>扫描目标：</strong> {target}</p>
            <p><strong>生成时间：</strong> {time_now}</p>
            
            <h2> 敏感目录爆破结果</h2>
            <table>
                <tr>
                    <th>发现的 URL</th>
                    <th>HTTP 状态码</th>
                </tr>
    """
    
    # 动态插入目录扫描结果
    dirs_result = results.get('dirs', [])
    if dirs_result:
        for item in dirs_result:
            status_class = f"status-{item['status']}" if item['status'] in [200, 403] else ""
            html_content += f"""
                <tr>
                    <td><a href='{item['url']}' target='_blank'>{item['url']}</a></td>
                    <td class='{status_class}'>{item['status']}</td>
                </tr>
            """
    else:
        html_content += "<tr><td colspan='2'>未发现敏感目录或文件。</td></tr>"

    # 如果有初期完成的端口结果，也可以一并预留好位置
    # 这里作为示例，仅简单展示如何扩展
    html_content += """
            </table>
            
            <h2> 开放端口检测结果 (占位)</h2>
            <p><i>（将你初期完成的端口扫描结果拼接到这里即可）</i></p>
        </div>
    </body>
    </html>
    """
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"\n 综合扫描报告已成功生成，请在浏览器打开查看: {filename}")