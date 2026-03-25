import requests
import os

def scan_directories(target_url, dict_file="dicts/dirs.txt"):
    """
    对目标URL进行敏感目录/文件扫描
    """
    print(f"\n 开始对 {target_url} 进行目录扫描...")
    found_dirs = []
    
    # 确保 URL 格式正确
    if not target_url.endswith('/'):
        target_url += '/'
        
    if not os.path.exists(dict_file):
        print(f" 字典文件 {dict_file} 未找到，请检查路径！")
        return found_dirs

    # 读取字典内容
    with open(dict_file, 'r', encoding='utf-8') as f:
        paths = f.read().splitlines()

    # 设置请求头，伪装成正常浏览器以防被简单拦截
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    for path in paths:
        # 跳过空行和注释行
        if not path or path.startswith('#'):
            continue
            
        url = target_url + path.lstrip('/')
        try:
            # 使用 GET 请求，设置较短的超时时间
            response = requests.get(url, headers=headers, timeout=3, allow_redirects=False)
            
            # 200(存在), 301/302(跳转), 403(禁止访问但存在)
            if response.status_code in [200, 301, 302, 403]:
                print(f" 发现敏感路径: {url} (状态码: {response.status_code})")
                found_dirs.append({
                    'url': url,
                    'status': response.status_code
                })
        except requests.RequestException:
            # 忽略连接超时或目标拒绝连接的错误
            pass
            
    print(f" 目录扫描完成，共发现 {len(found_dirs)} 个敏感路径。")
    return found_dirs

# 模块测试代码
if __name__ == "__main__":
    # 建议使用你可以合法测试的靶机地址
    scan_directories("http://127.0.0.1")