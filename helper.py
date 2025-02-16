#!/usr/bin/env python3
print("Script starting...")

import sys
import os
import socket
import yaml
import requests
import urllib.parse
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from yaml.loader import SafeLoader

# 全局变量：控制是否全局去重（全局去重只保留名称唯一的节点）
ENABLE_GLOBAL_DEDUP = True

class NodeFilter:
    # 只负责黑白名单过滤，不再处理 dedup，去重将在全局处理
    def __init__(self, inclusion, exclusion):
        self.inclusion = inclusion
        self.exclusion = exclusion

    def apply(self, nodes):
        # 黑名单过滤
        if self.exclusion:
            nodes = [
                node for node in nodes
                if not any(k.lower() in node.get('name', '').lower() or k.lower() in node.get('server', '').lower()
                           for k in self.exclusion)
            ]
        # 白名单过滤
        if self.inclusion:
            nodes = [
                node for node in nodes
                if any(k.lower() in node.get('name', '').lower() or k.lower() in node.get('server', '').lower()
                       for k in self.inclusion)
            ]
        return nodes

class NodeValidator:
    def __init__(self, timeout=5, verbose='normal'):
        self.timeout = timeout
        self.verbose = verbose

    def _is_node_available(self, node, log_callback=None):
        # 尝试将 port 转换为整数，避免字符串带来的错误
        try:
            port = int(node.get('port'))
        except Exception as conv_err:
            if self.verbose == 'verbose' and log_callback:
                log_callback(f"Port conversion error on node {node.get('name', 'Unknown')}: {conv_err}")
            return False

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((node.get('server'), port))
            return True
        except Exception as e:
            if self.verbose == 'verbose' and log_callback:
                log_callback(f"Error on node {node.get('name', 'Unknown')}: {e}")
            return False
        finally:
            sock.close()

    def validate(self, nodes, max_workers=None, log_callback=None):
        available_nodes = []
        total = len(nodes)
        if max_workers is None:
            max_workers = min(50, (os.cpu_count() or 1) * 5)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_node = {executor.submit(self._is_node_available, node, log_callback): node for node in nodes}
            completed = 0
            for future in concurrent.futures.as_completed(future_to_node):
                completed += 1
                node = future_to_node[future]
                try:
                    if future.result():
                        available_nodes.append(node)
                        if log_callback:
                            log_callback(f"进度 [{completed}/{total}] - 节点可用: {node.get('name', 'Unknown')}")
                    else:
                        if log_callback:
                            log_callback(f"进度 [{completed}/{total}] - 节点不可用: {node.get('name', 'Unknown')}")
                except Exception as e:
                    if log_callback:
                        log_callback(f"进度 [{completed}/{total}] - 检测出错: {node.get('name', 'Unknown')} - {e}")
        return available_nodes

class Site:
    REQUIRED_FIELDS = ['name', 'type', 'server', 'port']  # 必填字段

    def __init__(self, config: dict, verbose: str = 'normal'):
        self.url = config.get('url')
        self.name = config.get('name') or self._generate_name_from_url(self.url)
        self.group = config.get('group', 'PROXY')
        self.verbose = verbose
        self.nodes = []
        self.data = None

        # 删除了单独 dedup 选项，只使用黑白名单过滤
        self.filter = NodeFilter(
            inclusion=config.get('inclusion', []),
            exclusion=config.get('exclusion', [])
        )
        self.validator = NodeValidator(verbose=verbose)
        self._fetch_proxy_list()

    def _generate_name_from_url(self, url):
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split('.')[-2] if parsed.netloc else 'Unknown'

    def _fetch_proxy_list(self):
        try:
            headers = {"User-Agent": "ClashForAndroid/2.5.12"}
            r = requests.get(self.url, headers=headers, timeout=10)
            r.raise_for_status()  # 非 200 会抛出异常
            self.data = yaml.load(r.text, Loader=SafeLoader)
            count = len(self.data.get('proxies', [])) if self.data else 0
            self.log(f"成功获取订阅: {count} 个节点")
        except Exception as e:
            self.data = None
            self.log(f"订阅获取失败: {e}")

    def purge(self):
        if not self.data or 'proxies' not in self.data:
            self.log("No proxies found")
            return

        # 应用黑白名单过滤
        self.nodes = self.filter.apply(self.data['proxies'])
        total_before = len(self.nodes)

        # 检查必填字段，丢弃缺少必填字段的节点
        valid_nodes = []
        for node in self.nodes:
            if all(field in node for field in Site.REQUIRED_FIELDS):
                valid_nodes.append(node)
            else:
                self.log(f"节点缺少必填字段，将被忽略: {node}")
        self.nodes = valid_nodes

        self.log(f"过滤后剩余节点: {len(self.nodes)} (原始: {total_before})")
        # 检测节点可用性
        self.log(f"开始检测 {len(self.nodes)} 个节点可用性...")
        self.nodes = self.validator.validate(self.nodes, log_callback=lambda msg: self.log(msg))
        self.log(f"节点检测完成，{len(self.nodes)} 个节点可用")

    def get_titles(self):
        return [x.get('name', 'Unknown') for x in self.nodes]

    def log(self, message: str):
        if self.verbose != 'quiet':
            print(f"[{self.name}] {message}")

def from_config(config: dict, verbose: str = 'normal'):
    return Site(config, verbose)

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 4:
        print("Usage:")
        print("    python3 helper.py <sources_config> [output] [quiet/normal/verbose]")
        sys.exit(1)

    sources_file = sys.argv[1]
    if not os.path.isfile(sources_file):
        print(f"错误：配置文件 {sources_file} 不存在")
        sys.exit(1)

    verbose = 'normal' if len(sys.argv) < 4 else sys.argv[3].lower()
    try:
        with open(sources_file, "r", encoding="utf-8") as f:
            sites_config = yaml.load(f, Loader=SafeLoader)
            sites_config = sites_config.get('sources', [])
    except Exception as e:
        print(f"配置加载失败: {e}")
        sys.exit(1)

    try:
        template_path = os.path.join(os.path.dirname(__file__), "template.yaml")
    except NameError:
        template_path = "template.yaml"
    if not os.path.isfile(template_path):
        print(f"错误：模板文件 {template_path} 不存在")
        sys.exit(1)

    try:
        with open(template_path, "r", encoding="utf-8") as f:
            config = yaml.load(f, Loader=SafeLoader)
    except Exception as e:
        print(f"模板加载失败: {e}")
        sys.exit(1)

    config['proxies'] = []
    config['proxy-groups'] = [{"name": "PROXY", "type": "select", "proxies": []}]

    sites = []
    with ThreadPoolExecutor(max_workers=min(50, (os.cpu_count() or 1) * 2)) as executor:
        future_to_site = {executor.submit(from_config, site_conf, verbose): site_conf for site_conf in sites_config}
        for future in concurrent.futures.as_completed(future_to_site):
            try:
                site = future.result()
                sites.append(site)
            except Exception as e:
                print(f"订阅源加载出现错误: {e}")

    proxy_count = 0
    for site in sites:
        if site.data is not None:
            try:
                site.purge()
                if site.nodes:
                    config['proxies'] += site.nodes
                    for group in config['proxy-groups']:
                        if group.get('name') == site.group:
                            group['proxies'] += site.get_titles()
                    proxy_count += len(site.nodes)
            except Exception as e:
                if verbose != 'quiet':
                    print(f"Failed to process {site.name}: {e}")

    if ENABLE_GLOBAL_DEDUP:
        config['proxies'] = list({node.get('name'): node for node in config['proxies']}.values())

    output_file = sys.argv[2] if len(sys.argv) >= 3 and not sys.argv[2].lower() in ['quiet', 'normal', 'verbose'] else "output.yaml"
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(yaml.dump(config, default_flow_style=False, allow_unicode=True))
    except Exception as e:
        print(f"写入输出文件失败: {e}")
        sys.exit(1)

    print(f"已生成包含 {proxy_count} 个节点的配置文件：{output_file}")

if __name__ == "__main__":
    main()
