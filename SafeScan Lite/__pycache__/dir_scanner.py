import requests
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_directories(target_url, dict_file="dicts/dirs.txt", threads=30):
    """
    对目标URL进行敏感目录/文件扫描（多线程并发）。
    :param target_url: 目标 URL
    :param dict_file: 字典文件路径
    :param threads: 并发线程数
    :return: 发现的路径列表
    """
    print(f"\n 开始对 {target_url} 进行目录扫描（线程数: {threads}）...")
    found_dirs = []

    if not target_url.endswith("/"):
        target_url += "/"

    if not os.path.exists(dict_file):
        print(f" 字典文件 {dict_file} 未找到，请检查路径！")
        return found_dirs

    with open(dict_file, "r", encoding="utf-8") as f:
        paths = f.read().splitlines()

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    # 过滤空行和注释
    valid_paths = [p for p in paths if p and not p.startswith("#")]

    def _check_path(path):
        url = target_url + path.lstrip("/")
        try:
            resp = requests.get(url, headers=headers, timeout=3, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                print(f" 发现敏感路径: {url} (状态码: {resp.status_code})")
                return {"url": url, "status": resp.status_code}
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_check_path, p): p for p in valid_paths}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_dirs.append(result)

    print(f" 目录扫描完成，共发现 {len(found_dirs)} 个敏感路径。")
    return found_dirs


if __name__ == "__main__":
    scan_directories("http://127.0.0.1")
