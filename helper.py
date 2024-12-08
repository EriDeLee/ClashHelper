import yaml
import requests
import sys
import os
import socket
import urllib.parse

from yaml.loader import FullLoader

if len(sys.argv) < 2 or len(sys.argv) > 4:
    print("Usage:")
    print("    python3 helper.py <sources_config> [output] [verbose]")
    print("Example:")
    print("    python3 helper.py sources.yaml output.yaml [quiet/normal/verbose]")
    exit(1)

class Site:
    def __init__(self, config: dict, verbose: str = 'normal'):
        # 自动从URL推断名称
        self.url = config.get('url')
        self.name = config.get('name') or self._generate_name_from_url(self.url)
        
        # 默认配置
        self.group = config.get('group', 'auto')
        self.inclusion = config.get('inclusion', [])
        self.exclusion = config.get('exclusion', [])
        self.dedup = config.get('dedup', True)
        
        self.verbose = verbose
        self.nodes = []
        self.data = None

        self._fetch_proxy_list()

    def _generate_name_from_url(self, url):
        # 从URL生成一个友好的名称
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split('.')[-2] if parsed.netloc else 'Unknown'

    def _fetch_proxy_list(self):
        try:
            headers = {
                "User-Agent": "ClashForAndroid/2.5.12",
            }
            r = requests.get(self.url, headers=headers, timeout=10)
            r.raise_for_status()  # 对于非200状态码会抛出异常
            
            self.data = yaml.load(r.text, Loader=FullLoader)
            
            if self.verbose != 'quiet':
                self.log(f"成功获取订阅: {len(self.data.get('proxies', [])) if self.data else 0} 个节点")
        
        except Exception as e:
            self.data = None
            if self.verbose != 'quiet':
                self.log(f"订阅获取失败: {e}")

    def purge(self):
        if not self.data or 'proxies' not in self.data:
            if self.verbose != 'quiet':
                self.log("No proxies found")
            return

        self.nodes = self.data['proxies']
        nodes_good = []

        # 黑名单过滤
        if self.exclusion:
            nodes_good = [
                node for node in self.nodes 
                if not any(k.lower() in node['name'].lower() or k.lower() in node['server'].lower() for k in self.exclusion)
            ]
            self.nodes = nodes_good
            nodes_good = []

        # 白名单过滤
        if self.inclusion:
            nodes_good = [
                node for node in self.nodes 
                if any(k.lower() in node['name'].lower() or k.lower() in node['server'].lower() for k in self.inclusion)
            ]
            self.nodes = nodes_good
            nodes_good = []

        # 去重
        if self.dedup:
            used = set()
            for node in self.nodes:
                try:
                    ip = socket.getaddrinfo(node['server'], None)[0][4][0]
                    p = (ip, node['port'])
                    if p not in used:
                        used.add(p)
                        nodes_good.append(node)
                except:
                    if self.verbose != 'quiet':
                        self.log(f"Failed to resolve node {node['name']}: {node['server']}")
            self.nodes = nodes_good

    def get_titles(self):
        return [x['name'] for x in self.nodes]

    def log(self, message: str):
        if self.verbose != 'quiet':
            print(f"[{self.name}] {message}")

def from_config(config: dict, verbose: str = 'normal'):
    return Site(config, verbose)

def main():
    # 读取站点配置
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        sites_config = yaml.load(f, Loader=FullLoader)
        # 添加这一行：确保使用 sources 列表
        sites_config = sites_config.get('sources', [])

    # 读取模板配置
    with open("template.yaml", "r", encoding="utf-8") as f:
        config = yaml.load(f, Loader=FullLoader)

    # 初始化 proxies 和 proxy-groups
    config['proxies'] = []
    config['proxy-groups'] = [{"name": "auto", "type": "select", "proxies": []}]

    # 决定日志详细程度
    verbose = 'normal' if len(sys.argv) < 4 else sys.argv[3]

    # 处理代理站点
    sites = [from_config(site, verbose) for site in sites_config]
    
    proxy_count = 0
    for site in sites:
        if site.data is not None:
            try:
                site.purge()
                if site.nodes:
                    config['proxies'] += site.nodes
                    for group in config['proxy-groups']:
                        if group['name'] == site.group:
                            group['proxies'] += site.get_titles()
                    proxy_count += len(site.nodes)
            except Exception as e:
                if verbose != 'quiet':
                    print(f"Failed to process {site.name}: {e}")

    # 对节点名去重
    config['proxies'] = list({x['name']: x for x in config['proxies']}.values())

    # 决定输出文件
    output_file = sys.argv[2] if len(sys.argv) >= 3 and not sys.argv[2].startswith(('quiet', 'normal', 'verbose')) else "output.yaml"
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(yaml.dump(config, default_flow_style=False, allow_unicode=True))

    # 输出
    if verbose == 'quiet':
        print(f"已生成包含 {proxy_count} 个节点的配置文件：{output_file}")
    else:
        print(f"配置文件已生成：{output_file}")

if __name__ == "__main__":
    main()
