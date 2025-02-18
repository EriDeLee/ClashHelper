#!/usr/bin/env python3
print("Script starting...")

import sys
import os
import socket
import json
import subprocess
import urllib.parse
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from yaml.loader import SafeLoader

# ─────────────────────────────
# 全局设置
# FAST_MODE = 1 表示采用快速检测（仅基于socket），FAST_MODE = 0 表示采用准确检测（调用Go程序）
FAST_MODE = 0
# LATENCY_THRESHOLD 单位毫秒，只有测得延迟小于此值的节点才认为合格（仅在准确检测下生效）
LATENCY_THRESHOLD = 500

# ─────────────────────────────
# 所有日志直接输出详细信息
def log(msg):
    print(msg)

# ─────────────────────────────
# NodeFilter：根据节点原始名称(_orig_name)对黑白名单进行过滤（不做日志分级）
class NodeFilter:
    def __init__(self, inclusion, exclusion):
        self.inclusion = inclusion or []
        self.exclusion = exclusion or []

    def apply(self, nodes):
        def get_name(node):
            return node.get('_orig_name', node.get('name', '')).lower()
        # 黑名单过滤：若节点名称或server字段中包含排除关键词，则过滤
        if self.exclusion:
            nodes = [node for node in nodes if not any(kw.lower() in get_name(node) or kw.lower() in node.get('server', '').lower() for kw in self.exclusion)]
        # 白名单过滤：若设置包含关键词，则保留满足其一的节点
        if self.inclusion:
            nodes = [node for node in nodes if any(kw.lower() in get_name(node) or kw.lower() in node.get('server', '').lower() for kw in self.inclusion)]
        return nodes

# ─────────────────────────────
# NodeValidator：根据FAST_MODE选择检测方式，应用延迟阈值过滤（所有日志均打印详细）
class NodeValidator:
    def __init__(self, timeout=5):
        self.timeout = timeout
        # Go程序二进制文件路径（请确保“latency”在当前目录下）
        self.go_bin = os.path.join(os.path.dirname(__file__), 'latency')

    def validate(self, nodes, max_workers=None):
        if max_workers is None:
            cpu_count = os.cpu_count()
            if FAST_MODE == 0:
                max_workers = cpu_count // 2 if cpu_count > 1 else 1 # 准确模式：CPU线程数一半，最少为1
            else:
                max_workers = cpu_count # 快速模式：CPU线程数
        if FAST_MODE == 0:
            return self._validate_accurate(nodes, max_workers)
        else:
            return self._validate_fast(nodes, max_workers)

    def _validate_accurate(self, nodes, max_workers):
        available = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._test_with_go, node): node for node in nodes}
            total = len(futures)
            completed = 0
            for future in as_completed(futures):
                completed += 1
                node = futures[future]
                try:
                    success, latency = future.result()
                    progress = f"[{completed}/{total}]"
                    subscription = node.get('subscription', 'Unknown')
                    log(f"[{subscription}] [准确模式] {progress} 节点 {node.get('_orig_name', node.get('name','Unknown'))} 延迟: {latency:.1f}ms, 可用: {success}")
                    if success and latency <= LATENCY_THRESHOLD:
                        node['latency'] = latency
                        available.append(node)
                    else:
                        log(f"[{subscription}] [准确模式] {progress} 节点 {node.get('_orig_name','Unknown')} 失败")
                except Exception as e:
                    log(f"[{subscription}] [准确模式] {progress} 节点 {node.get('_orig_name','Unknown')} 检测异常：{e}")
        available.sort(key=lambda x: x.get('latency', float('inf')))
        return available

    def _test_with_go(self, node):
        cfg = {
            "type": node['type'].lower(),
            "name": node.get('_orig_name', node.get('name', 'Unknown')),
            "server": node['server'],
            "port": int(node['port']),
            "auth": {k: v for k, v in node.items() if k not in ['name', '_orig_name', 'type', 'server', 'port']}
        }
        try:
            proc = subprocess.run([self.go_bin],
                                    input=json.dumps(cfg).encode(),
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    timeout=self.timeout)
            if proc.returncode != 0:
                log(f"节点 {cfg['name']} Go程序错误: {proc.stderr.decode().strip()}")
                return (False, 0)
            res = json.loads(proc.stdout)
            if not res.get('success'):
                log(f"节点 {cfg['name']} 检测失败: {res.get('error','')}")
                return (False, 0)
            return (True, res.get('latency', 0))
        except Exception as e:
            log(f"节点 {cfg['name']} 调用Go异常: {e}")
            return (False, 0)

    def _validate_fast(self, nodes, max_workers):
        available = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._check_port, node): node for node in nodes}
            for future in as_completed(futures):
                node = futures[future]
                if future.result():
                    available.append(node)
                    log(f"[快速模式] 节点 {node.get('_orig_name', node.get('name','Unknown'))} 可用")
                else:
                    log(f"[快速模式] 节点 {node.get('_orig_name', node.get('name','Unknown'))} 不可用")
        return available

    def _check_port(self, node):
        try:
            s = socket.create_connection((node['server'], int(node['port'])), timeout=2)
            s.close()
            return True
        except Exception:
            return False

# ─────────────────────────────
# Site：加载订阅源，过滤节点，调用检测，最后为每个节点增加订阅前缀
class Site:
    REQUIRED_FIELDS = ['name', 'type', 'server', 'port']
    def __init__(self, config):
        self.url = config.get('url')
        self.name = config.get('name') or self._generate_name_from_url(self.url)
        self.group = config.get('group', 'PROXY')
        self.nodes = []
        self.data = None
        self.filter = NodeFilter(config.get('inclusion'), config.get('exclusion'))
        self._fetch_proxy_list()

    def _generate_name_from_url(self, url):
        parts = urllib.parse.urlparse(url).netloc.split('.')
        return parts[-2] if len(parts) >= 2 else 'Unknown'

    def _fetch_proxy_list(self):
        try:
            import requests
            headers = {"User-Agent": "ClashForAndroid/2.5.12"}
            resp = requests.get(self.url, headers=headers, timeout=10)
            resp.raise_for_status()
            self.data = yaml.load(resp.text, Loader=SafeLoader)
            if self.data and 'proxies' in self.data:
                for node in self.data.get('proxies'):
                    node['_orig_name'] = node.get('name', 'Unknown')
            log(f"[{self.name}] 成功获取订阅: {len(self.data.get('proxies', []))} 个节点")
        except Exception as e:
            self.data = None
            log(f"[{self.name}] 订阅获取失败: {e}")

    def purge(self):
        if not self.data or 'proxies' not in self.data:
            log(f"[{self.name}] No proxies found")
            return
        self.nodes = self.filter.apply(self.data['proxies'])
        total_before = len(self.nodes)
        valid = [node for node in self.nodes if all(field in node for field in Site.REQUIRED_FIELDS)]
        for node in valid:
            node['subscription'] = self.name
        log(f"[{self.name}] 过滤后剩余节点: {len(valid)} (原始: {total_before})")
        log(f"[{self.name}] 开始检测 {len(valid)} 个节点可用性...")
        validator = NodeValidator(timeout=10)
        self.nodes = validator.validate(valid)
        log(f"[{self.name}] 节点检测完成，{len(self.nodes)} 个节点可用")
        # 为检测通过的节点名称增加订阅前缀
        for node in self.nodes:
            orig = node.get('_orig_name', node.get('name', 'Unknown'))
            node['subscription'] = self.name
            node['name'] = f"{self.name}-{orig}"

    def get_titles(self):
        return [node.get('name', 'Unknown') for node in self.nodes]

# ─────────────────────────────
def from_config(config):
    return Site(config)

# ─────────────────────────────
def main():
    if len(sys.argv) < 2 or len(sys.argv) > 4:
        print("Usage: python3 helper.py <sources_config> [output] [quiet/normal/debug]")
        sys.exit(1)
    sources_file = sys.argv[1]
    if not os.path.isfile(sources_file):
        print(f"错误：配置文件 {sources_file} 不存在")
        sys.exit(1)
    # 本版本不再区分日志级别，一律输出详细信息
    try:
        with open(sources_file, "r", encoding="utf-8") as f:
            sites_config = yaml.load(f, Loader=SafeLoader)
            sites_config = sites_config.get('sources', [])
    except Exception as e:
        print(f"配置加载失败: {e}")
        sys.exit(1)
    try:
        template_path = os.path.join(os.path.dirname(__file__), "template.yaml")
    except Exception:
        template_path = "template.yaml"
    if not os.path.isfile(template_path):
        print(f"错误：模板文件 {template_path} 不存在")
        sys.exit(1)
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            config_template = yaml.load(f, Loader=SafeLoader)
    except Exception as e:
        print(f"模板加载失败: {e}")
        sys.exit(1)
    config_template['proxies'] = []
    config_template['proxy-groups'] = [{"name": "PROXY", "type": "select", "proxies": []}]

    sites = []
    with ThreadPoolExecutor(max_workers=10) as executor: # 这里保持默认的线程池大小为10，用于订阅源加载
        futures = {executor.submit(from_config, conf): conf for conf in sites_config}
        for future in as_completed(futures):
            try:
                site = future.result()
                sites.append(site)
            except Exception as e:
                print(f"订阅源加载出现错误: {e}")

    # 检查订阅源名称唯一性
    site_names = [site.name for site in sites if site.data is not None]
    if len(site_names) != len(set(site_names)):
        print("错误: 订阅源的名称不唯一，请确保每个订阅源的 name 字段不同")
        sys.exit(1)

    proxy_count = 0
    for site in sites:
        if site.data is not None:
            try:
                site.purge()
                if site.nodes:
                    config_template['proxies'] += site.nodes
                    for group in config_template['proxy-groups']:
                        if group.get('name') == site.group:
                            group['proxies'] += site.get_titles()
                    proxy_count += len(site.nodes)
            except Exception as e:
                print(f"订阅源 {site.name} 处理失败: {e}")

    output_file = sys.argv[2] if (len(sys.argv) >= 3 and sys.argv[2].lower() not in ['quiet','normal','debug']) else "output.yaml"
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(yaml.dump(config_template, default_flow_style=False, allow_unicode=True))
    except Exception as e:
        print(f"写入输出文件失败: {e}")
        sys.exit(1)

    print(f"已生成包含 {proxy_count} 个节点的配置文件：{output_file}")

if __name__ == "__main__":
    main()
