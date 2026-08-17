#!/usr/bin/env python3
print("Script starting...")

import sys
import os
import json
import math
import subprocess
import threading
import time
import unicodedata
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import yaml
from yaml.loader import SafeLoader
from yaml.reader import Reader as YamlReader

# 节点名里普遍带 emoji（🇭🇰 🟢 之类）。Windows 上 Python 的 stdout 一旦被重定向
# （写日志、管道、CI），编码就退回系统 ANSI 代码页 GBK，遇到 emoji 直接
# UnicodeEncodeError 把整轮跑崩、前面的结果全丢。这里强制 UTF-8 并允许替换，
# 保证日志再难看也不会中断检测。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ─────────────────────────────
# 全局设置
#
# LATENCY_THRESHOLD  毫秒。只有测得延迟低于此值的节点才算合格。
# TEST_TIMEOUT_MS    单节点超时。必须大于 LATENCY_THRESHOLD，否则会漏掉本该合格的节点；
#                    但也没必要大太多 —— 超过门槛的节点无论等多久最终都会被丢弃，
#                    等满 5 秒纯属浪费（旧版就是 5 秒，死节点一个吃掉 5 秒）。
# TEST_CONCURRENCY   同时测试的节点数。调得过高会让自家宽带成为瓶颈，
#                    连好节点也会超时、被误判成不可用。
LATENCY_THRESHOLD = 500
TEST_TIMEOUT_MS = 1200
TEST_CONCURRENCY = 128
# 端点选择：google.com 本体比 gstatic.com（Google 的 CDN 边缘）严得多。
# 2026-08-11 用同一批 22 个已知可用节点实测：gstatic 通过 16 个，google.com 只通过 9 个。
# 保留 google.com 是有意的 —— 能连 CDN 却连不上本体的节点实际浏览也用不了。
# 两者都正常返回 HTTP 204、不跳转，和"只认 2xx + 禁跟转发"的判定兼容。
TEST_URL = "http://www.google.com/generate_204"

# 协议白名单（初筛）。只有 type 落在这里的节点才会进入关键词过滤和测速，
# 其余在拉取后立刻丢弃。动机是省测速时间：免费订阅里明文的 http / socks5 量很大，
# 2026-08-12 那轮 output.yaml 的 69 个可用节点里就占了 19 个（27.5%）。
# 匹配方式是 type 去空格转小写后精确比对 —— "VLESS" 能收，"hy2" 不能，
# 后者 mihomo 本来也解析不了（adapter/parser.go 只认 ss / ssr / socks5 / http /
# vmess / vless / snell / trojan / hysteria / hysteria2 / wireguard / tuic /
# ssh / mieru，外加 direct / dns / reject 三个非订阅类型）。
# 改成空集合即关闭初筛，全部协议照旧送去测。
ALLOWED_TYPES = frozenset({'vless', 'trojan', 'vmess', 'hysteria2'})

FETCH_WORKERS = 10    # 并发拉取订阅源的线程数
FETCH_TIMEOUT = 10    # 单次请求超时（秒）
# 2026-08-12 实测：raw.githubusercontent.com 本身没问题 —— 串行 33/33、10 并发
# 29/29 全成功，最慢单请求 2.4s。但那天正式跑的时候 6/29 个源超时，8768 个节点
# （占全池 42%）压根没进检测；随后 3 并发重测又换了一批源失败。也就是说失败是
# 网络时段性抖动，跟并发数和域名都无关，换 jsDelivr CDN 也治不了（还会因为边缘
# 缓存拿到旧文件：实测 AU1RXX 的 CDN 副本旧了 60 分钟、少 24 个节点）。
# 对症的做法只有重试。三次尝试最坏多等 36s，换回来的是那 42%。
FETCH_ATTEMPTS = 3    # 单个源的尝试次数
FETCH_BACKOFF = 2     # 重试前等待的基数秒，第 n 次失败后等 n*BACKOFF

# 刻意不做 (ip, port) 去重。2026-08-11 实测：六个源之间字面量重复只占 2.4%，
# 加上 IP 级重复也只有 9%，去掉后耗时没有可测差别（不去重 39.5s / 去重 43.1s，
# 差异在噪声内）。而同一台机器在不同源里往往是多份不同配置、好坏并存，
# 去重反而要额外操心保留哪一份。收益接近零、维护成本不低，故不保留。
# 历史上它被删过一次（01c881f，2025-02-18），这次是第二次删，原因相同。

# 构造 auth 时要从节点字典里剔掉的键。两类键的原因完全不同，别当成一类：
#   name / type / server / port        —— 是真正的代理参数，但 payload 里已经
#                                         单独给过了，留在 auth 里等于重复传
#   _orig_name / subscription / latency —— 我们自己的记账字段，不是代理参数。
#                                         这三个会一并写进 output.yaml，是历史
#                                         输出一直带着的，Clash 能容忍，保持原样
INTERNAL_KEYS = ('name', '_orig_name', 'type', 'server', 'port',
                 'subscription', 'latency')


# ─────────────────────────────
def log(msg):
    # flush 是必要的：检测阶段的进度靠这些行体现，缓冲会让它们攒到最后一次性刷出来
    print(msg, flush=True)


def _display_width(text):
    """终端显示宽度。中文和 emoji 占两列，直接用 len() 对齐会歪。"""
    return sum(2 if unicodedata.east_asian_width(ch) in ('W', 'F') else 1
               for ch in str(text))


def _cell(text, width, right=False):
    pad = ' ' * max(0, width - _display_width(text))
    return (pad + str(text)) if right else (str(text) + pad)


def _median(values):
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def log_source_stats(sites, all_nodes, available):
    """按订阅源打一张 抓取 → 送检 → 合格 的漏斗表和命中率。

    只看合格数会把大源和好源搞混：一个源出 42 个可能是从 200 个里挑的（很强），
    也可能是从 5000 个里挑的（很弱）。分母（送检数）原先只在 prepare() 阶段
    各源自己那行日志里出现过一次，被后面几千行检测进度冲得根本翻不到，
    所以在最后统一收口打一张表。

    顺带把两种"0 产出"分开：拉取失败的源要去修订阅地址，测了全灭的源是节点
    真的都死了。混在一列看会把"订阅挂了"误判成"节点质量差"，处置方向正好相反。
    """
    submitted = {}
    for node in all_nodes:
        key = node.get('subscription')
        submitted[key] = submitted.get(key, 0) + 1
    latencies = {}
    for node in available:
        latencies.setdefault(node.get('subscription'), []).append(float(node.get('latency', 0)))

    rows = []
    for site in sites:
        if site.data is None:
            # 拉取失败：分母是 0，命中率无从计算，不能和"全灭"并列
            rows.append({'name': site.name, 'fetched': None, 'sub': 0,
                         'ok': 0, 'rate': None, 'med': None})
            continue
        sub = submitted.get(site.name, 0)
        lats = latencies.get(site.name, [])
        # 必须查 isinstance：yaml.load 拿到的可能不是字典（订阅返回一段纯文本或
        # 数组时就是），此处 .get 会抛 AttributeError。而这张表打在写文件【之前】，
        # 一次崩溃会把整轮几分钟的检测结果连同 output.yaml 一起赔掉。
        proxies = site.data.get('proxies') if isinstance(site.data, dict) else None
        rows.append({
            'name': site.name,
            'fetched': len(proxies or []),
            'sub': sub,
            'ok': len(lats),
            'rate': (len(lats) / sub) if sub else None,
            'med': _median(lats),
        })

    # 命中率降序，其次合格数降序。没有分母的（拉取失败、送检 0）沉到表尾。
    rows.sort(key=lambda r: (r['rate'] is None, -(r['rate'] or 0), -r['ok'], r['name']))

    widths = (14, 8, 8, 7, 10, 11)
    log("")
    log("─" * sum(widths))
    log(_cell('订阅源', widths[0]) + _cell('抓取', widths[1], True)
        + _cell('送检', widths[2], True) + _cell('合格', widths[3], True)
        + _cell('命中率', widths[4], True) + _cell('延迟中位', widths[5], True))
    log("─" * sum(widths))
    for r in rows:
        fetched = '拉取失败' if r['fetched'] is None else str(r['fetched'])
        rate = '—' if r['rate'] is None else f"{r['rate'] * 100:.2f}%"
        med = '—' if r['med'] is None else f"{r['med']:.0f}ms"
        log(_cell(r['name'], widths[0]) + _cell(fetched, widths[1], True)
            + _cell(r['sub'], widths[2], True) + _cell(r['ok'], widths[3], True)
            + _cell(rate, widths[4], True) + _cell(med, widths[5], True))
    log("─" * sum(widths))

    total_fetched = sum(r['fetched'] for r in rows if r['fetched'] is not None)
    total_sub = sum(r['sub'] for r in rows)
    total_ok = sum(r['ok'] for r in rows)
    all_lats = [lat for lats in latencies.values() for lat in lats]
    log(_cell('合计', widths[0]) + _cell(total_fetched, widths[1], True)
        + _cell(total_sub, widths[2], True) + _cell(total_ok, widths[3], True)
        + _cell(f"{(total_ok / total_sub * 100) if total_sub else 0:.2f}%", widths[4], True)
        + _cell('—' if not all_lats else f"{_median(all_lats):.0f}ms", widths[5], True))
    dead = [r['name'] for r in rows if r['fetched'] is not None and r['ok'] == 0]
    lost = [r['name'] for r in rows if r['fetched'] is None]
    if dead:
        log(f"零产出（测了全灭）{len(dead)} 个：{', '.join(dead)}")
    if lost:
        log(f"零产出（订阅没拉到，节点未进检测）{len(lost)} 个：{', '.join(lost)}")


# ─────────────────────────────
# NodeFilter：根据节点原始名称(_orig_name)对黑白名单进行过滤
class NodeFilter:
    def __init__(self, inclusion, exclusion):
        self.inclusion = inclusion or []
        self.exclusion = exclusion or []

    def apply(self, nodes):
        def get_name(node):
            return str(node.get('_orig_name') or node.get('name') or '').lower()

        def get_server(node):
            # 必须走 or '' 而不是 .get('server', '')：默认值只在键不存在时生效，
            # 订阅里写成 "server:"（键在、值为 None）会拿到 None，
            # None.lower() 抛的 AttributeError 会从 prepare 一路冒到 main，
            # 结果整个订阅源被丢弃 —— 一个坏节点带走 ANAERSUB 的 2592 个。
            return str(node.get('server') or '').lower()

        # 黑名单过滤：若节点名称或server字段中包含排除关键词，则过滤
        if self.exclusion:
            nodes = [node for node in nodes if not any(kw.lower() in get_name(node) or kw.lower() in get_server(node) for kw in self.exclusion)]
        # 白名单过滤：若设置包含关键词，则保留满足其一的节点
        if self.inclusion:
            nodes = [node for node in nodes if any(kw.lower() in get_name(node) or kw.lower() in get_server(node) for kw in self.inclusion)]
        return nodes


# ─────────────────────────────
# BatchValidator：一次子进程调用测完全部节点
#
# 旧版对每个节点单独启动一次 latency.exe。实测该程序光启动就要 382ms
# （32.8MB 二进制 + 整个 mihomo 引擎初始化），4790 个节点等于 30 分钟纯启动开销，
# 而且外层线程池被限制在 cpu_count//2 = 8 个并发。现在只启动一次进程，
# 并发交给 Go 侧的 goroutine。
class BatchValidator:
    def __init__(self, concurrency=TEST_CONCURRENCY, timeout_ms=TEST_TIMEOUT_MS,
                 threshold_ms=LATENCY_THRESHOLD, test_url=TEST_URL):
        self.concurrency = max(1, int(concurrency))
        self.timeout_ms = int(timeout_ms)
        self.threshold_ms = threshold_ms
        self.test_url = test_url
        here = os.path.dirname(os.path.abspath(__file__))
        self.go_bin = os.path.join(here, 'latency.exe' if os.name == 'nt' else 'latency')

    def _payload(self, nodes):
        payload = []
        for idx, node in enumerate(nodes):
            # id 必须是 enumerate 的下标，validate 靠它做 nodes[rid] 回查。
            # 跳过的节点会自动落进"没有返回结果"的告警里，不会被算成合格。
            try:
                port = int(node['port'])
            except (TypeError, ValueError):
                log(f"[检测] 跳过 port 非法的节点："
                    f"{node.get('_orig_name', '?')} port={node.get('port')!r}")
                continue
            # name 和 server 必须显式 str()。latency.go 的 ProxyConfig 把这两个
            # 声明成 string，而 decodeConfigs 是对整个数组做一次 json.Unmarshal，
            # 任何一个元素类型不符就整批拒绝。2026-08-12 实测：VPNFA 里 3 个节点
            # 的 name 在 YAML 里写成裸数字（1 / 3 / 5334），被解析成 int，
            # 于是 22605 个节点全军覆没、一个结果都没回来。port 的 int() 已经是
            # 同一类问题的历史补丁（40 个节点的 port 是 '443' 这种字符串）。
            payload.append({
                "id": idx,
                "type": str(node['type']).lower(),
                "name": str(node.get('_orig_name', node.get('name', 'Unknown'))),
                "server": str(node['server']),
                "port": port,
                "auth": {k: v for k, v in node.items() if k not in INTERNAL_KEYS},
            })
        return payload

    def validate(self, nodes):
        if not nodes:
            return []
        if not os.path.isfile(self.go_bin):
            log(f"[检测] 找不到检测程序：{self.go_bin}")
            return []
        if self.timeout_ms <= self.threshold_ms:
            log(f"[检测] 警告：超时 {self.timeout_ms}ms 不大于门槛 {self.threshold_ms}ms，"
                f"会漏掉本该合格的节点")

        total = len(nodes)
        waves = max(1, math.ceil(total / self.concurrency))
        budget = waves * (self.timeout_ms / 1000.0) * 3 + 120

        env = os.environ.copy()
        env['LATENCY_CONCURRENCY'] = str(self.concurrency)
        env['LATENCY_TIMEOUT_MS'] = str(self.timeout_ms)
        env['LATENCY_URL'] = self.test_url

        log(f"[检测] {total} 个节点 / {self.concurrency} 并发 / 单节点超时 "
            f"{self.timeout_ms}ms / 约 {waves} 轮 / 兜底上限 {int(budget)}s")

        # payload 必须在启动子进程【之前】构造好。放在之后的话，一旦构造抛异常
        # （节点里有不可 JSON 序列化的值），子进程已经起来了、stdin 从没被写过也没
        # close，它会永远卡在 io.ReadAll(os.Stdin) 上，而兜底强杀的 Timer 还没创建，
        # 于是留下一个 33MB 的孤儿进程占着管道。
        payload = json.dumps(self._payload(nodes)).encode('utf-8')

        proc = subprocess.Popen(
            [self.go_bin],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env,
        )

        # 写 stdin 放到单独线程，是为了不让主线程卡在阻塞写上：子进程若启动即死
        # （exe 损坏、立刻 panic），这里的 write 会抛 BrokenPipe，而主线程仍能继续
        # 读 stdout、把那条 id:-1 的"整批失败"取出来。
        # 注：当前 latency.go 的第一句就是 io.ReadAll(os.Stdin)，读完才产出任何
        # stdout，所以"stdout 管道塞满导致互等"这条路暂时走不通——但别指望它永远这么写。
        def feed():
            try:
                proc.stdin.write(payload)
                proc.stdin.close()
            except Exception as exc:
                log(f"[检测] 写入子进程失败：{exc}")

        threading.Thread(target=feed, daemon=True).start()

        # stderr 同样要另起线程排空。Go 运行时若真的 panic，128 个 goroutine 的
        # 栈回溯可能超过 64KB 管道缓冲；等到 proc.wait() 之后再读就太晚了 ——
        # 子进程会卡在写 stderr 上不退出，这边卡在读 stdout 上，只能等兜底强杀。
        stderr_chunks = []

        def drain_err():
            try:
                stderr_chunks.append(proc.stderr.read())
            except Exception as exc:
                # stderr 是子进程 panic 时唯一的线索来源，读失败不能一个字不说
                log(f"[检测] 读取子进程 stderr 失败：{exc}")

        err_thread = threading.Thread(target=drain_err, daemon=True)
        err_thread.start()

        # 兜底：子进程万一卡死，下面的逐行读取会永久阻塞，必须有人来强杀
        killer = threading.Timer(budget, self._kill, args=(proc, budget))
        killer.daemon = True
        killer.start()

        results = {}
        completed = 0
        finished = False
        try:
            for raw in proc.stdout:
                line = raw.decode('utf-8', 'replace').strip()
                if not line:
                    continue
                try:
                    res = json.loads(line)
                except ValueError:
                    # 子进程若打印了非 JSON 内容，跳过而不是让整轮崩掉
                    log(f"[检测] 忽略非 JSON 输出：{line[:200]}")
                    continue
                if not isinstance(res, dict):
                    # "null" / "42" / '"x"' 都是合法 JSON 但没有 .get，
                    # 不挡这一手就会 AttributeError 冲出循环、整轮结果全丢
                    log(f"[检测] 忽略非对象 JSON 输出：{line[:200]}")
                    continue
                rid = res.get('id', -1)
                if rid == -1:
                    log(f"[检测] 整批失败：{res.get('error', '')}")
                    continue
                if not isinstance(rid, int) or not (0 <= rid < total) or rid in results:
                    continue

                results[rid] = res
                completed += 1
                node = nodes[rid]
                name = node.get('_orig_name', node.get('name', 'Unknown'))
                sub = node.get('subscription', 'Unknown')
                progress = f"[{completed}/{total}]"
                if res.get('success'):
                    lat = float(res.get('latency', 0))
                    verdict = "合格" if lat <= self.threshold_ms else f"超过 {self.threshold_ms}ms 门槛"
                    log(f"[{sub}] {progress} {name} 延迟 {lat:.1f}ms {verdict}")
                else:
                    log(f"[{sub}] {progress} {name} 不可用：{res.get('error', '')}")
            finished = True
        finally:
            killer.cancel()
            if not finished and proc.poll() is None:
                # 异常从读取循环里逃出去时，上面的 cancel 已经把兜底 Timer 撤了，
                # 而下面的 proc.wait() 也会被跳过 —— 再没人来收这个子进程
                log("[检测] 读取结果中断，强制结束检测子进程")
                try:
                    proc.kill()
                except Exception:
                    pass

        proc.wait()
        err_thread.join(timeout=5)
        err = b''.join(stderr_chunks).decode('utf-8', 'replace').strip()
        if err:
            log(f"[检测] 子进程 stderr：{err[:2000]}")

        missing = total - len(results)
        if missing:
            # 整批共用一个进程，进程提前死掉不该让整轮结果全丢，
            # 没拿到结果的按不可用处理并明确报出来
            log(f"[检测] 警告：{missing} 个节点没有返回结果"
                f"（子进程退出码 {proc.returncode}），按不可用处理")

        available = []
        for idx, node in enumerate(nodes):
            res = results.get(idx)
            if not res or not res.get('success'):
                continue
            lat = float(res.get('latency', 0))
            if lat > self.threshold_ms:
                continue
            node['latency'] = lat
            available.append(node)
        available.sort(key=lambda n: n.get('latency', float('inf')))
        log(f"[检测] 完成：{len(available)}/{total} 个节点合格")
        return available

    @staticmethod
    def _kill(proc, budget):
        if proc.poll() is None:
            log(f"[检测] 超过 {int(budget)}s 兜底上限，强制结束检测子进程")
            try:
                proc.kill()
            except Exception:
                pass


# ─────────────────────────────
# Site：加载订阅源，过滤节点。检测不再由 Site 各自发起，
# 而是六个源的节点汇总成一批统一测（旧版是一个源测完才轮到下一个）。
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
        headers = {"User-Agent": "ClashForAndroid/2.5.12"}
        last_err = None
        for attempt in range(1, FETCH_ATTEMPTS + 1):
            try:
                resp = requests.get(self.url, headers=headers, timeout=FETCH_TIMEOUT)
                resp.raise_for_status()
                # pyyaml 拒收 C1 控制字符等一批码位，引号内也不行，一个坏字符就让
                # 整个文件解析失败。2026-08-17 实测：Daily_Free 第 2574 行有个节点把
                # 🇨🇳 二次编码后塞进了 sni（一个广告链接），产生 4 个 U+009F/U+0087，
                # pyyaml 抛 ReaderError，4185 个节点（其中 3357 个能过协议白名单）整块
                # 丢失。而且这是必然失败：下面的重试白等 36 秒，第 100 次也是同一个错。
                #
                # 用 pyyaml 自己的 NON_PRINTABLE 清洗，范围和解析器拒收的范围严格一致，
                # 不靠手写字符类。干净文件走这里是纯空转（实测 KOOKER 清洗前后文本
                # 完全相同），所以不存在"本来能用、被清洗弄坏"的情况 —— 文件里只要有
                # 这类字符，不清就是整个源全丢。
                text, removed = YamlReader.NON_PRINTABLE.subn('', resp.text)
                if removed:
                    pos = YamlReader.NON_PRINTABLE.search(resp.text).start()
                    log(f"[{self.name}] 清掉 {removed} 个 YAML 不接受的字符"
                        f"（首个在第 {resp.text.count(chr(10), 0, pos) + 1} 行），"
                        f"不清掉整个订阅会解析失败")
                self.data = yaml.load(text, Loader=SafeLoader)
                if self.data and 'proxies' in self.data:
                    for node in self.data.get('proxies') or []:
                        node['_orig_name'] = node.get('name', 'Unknown')
                retried = f"（第 {attempt} 次尝试）" if attempt > 1 else ""
                log(f"[{self.name}] 成功获取订阅: "
                    f"{len((self.data or {}).get('proxies') or [])} 个节点{retried}")
                return
            except Exception as e:
                # 整块重试而不是只重试 requests：响应被截断时 yaml.load 才报错，
                # 那种情况重来一次同样能救回来。
                last_err = e
                self.data = None
                if attempt < FETCH_ATTEMPTS:
                    wait = FETCH_BACKOFF * attempt
                    log(f"[{self.name}] 第 {attempt}/{FETCH_ATTEMPTS} 次获取失败："
                        f"{e}，{wait}s 后重试")
                    time.sleep(wait)
        log(f"[{self.name}] 订阅获取失败（已尝试 {FETCH_ATTEMPTS} 次）: {last_err}")

    def _apply_type_whitelist(self, nodes):
        """协议初筛：丢掉 ALLOWED_TYPES 之外的节点。

        放在关键词过滤之前只是为了少干活 —— 关键词过滤要对每个节点的名称和
        地址各做 len(exclusion)+len(inclusion) 次子串查找，这里一次字典取值
        就能决定去留。两者都是"与"条件，先后顺序不影响最终留下的节点集合，
        只影响日志里那两个数字分别是谁筛完的。
        """
        if not ALLOWED_TYPES:
            return nodes
        kept = []
        dropped = {}
        for node in nodes:
            # 走 or '' 而不是 .get('type', '')：订阅里写成 "type:"（键在、值为
            # None）时默认值不生效，None.lower() 抛的 AttributeError 会一路冒到
            # main，整个源被丢掉 —— 和 NodeFilter 里 server 字段踩过的是同一个坑。
            kind = str(node.get('type') or '').strip().lower()
            if kind in ALLOWED_TYPES:
                kept.append(node)
            else:
                label = kind or '(无 type)'
                dropped[label] = dropped.get(label, 0) + 1
        if dropped:
            detail = ', '.join(f"{k} {v}" for k, v in
                               sorted(dropped.items(), key=lambda kv: (-kv[1], kv[0])))
            log(f"[{self.name}] 协议初筛丢弃 {sum(dropped.values())} 个"
                f"（{detail}），剩余 {len(kept)}")
        return kept

    def prepare(self):
        """只做本地过滤，不做检测。返回待检测的候选节点。"""
        if not self.data or 'proxies' not in self.data:
            log(f"[{self.name}] No proxies found")
            return []
        raw = self.data.get('proxies') or []
        filtered = self.filter.apply(self._apply_type_whitelist(raw))
        valid = [node for node in filtered
                 if all(field in node for field in Site.REQUIRED_FIELDS)]
        for node in valid:
            node['subscription'] = self.name
        log(f"[{self.name}] 过滤后剩余节点: {len(valid)} (原始: {len(raw)})")
        return valid

    def accept(self, tested):
        """接收属于本站点的检测结果，给节点名加订阅前缀。

        传入的切片已经按延迟升序 —— validate() 返回时排过，按订阅源分桶时
        保持了原顺序，所以这里不必再排一次。
        """
        self.nodes = list(tested)
        for node in self.nodes:
            orig = node.get('_orig_name', node.get('name', 'Unknown'))
            node['name'] = f"{self.name}-{orig}"
        log(f"[{self.name}] 节点检测完成，{len(self.nodes)} 个节点可用")

    def get_titles(self):
        return [node.get('name', 'Unknown') for node in self.nodes]


# ─────────────────────────────
def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python3 helper.py <sources_config> [output]")
        sys.exit(1)
    sources_file = sys.argv[1]
    if not os.path.isfile(sources_file):
        print(f"错误：配置文件 {sources_file} 不存在")
        sys.exit(1)
    try:
        with open(sources_file, "r", encoding="utf-8") as f:
            sites_config = yaml.load(f, Loader=SafeLoader)
            sites_config = sites_config.get('sources', [])
    except Exception as e:
        print(f"配置加载失败: {e}")
        sys.exit(1)
    # 用 abspath 和 BatchValidator 找 latency.exe 的方式保持一致，
    # 这样从任何工作目录调用脚本都能找到同目录的模板
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "template.yaml")
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

    # ── 拉取订阅（并发）。结果按 sources.yaml 里的顺序落位，
    #    让 output.yaml 里的分组顺序稳定，不随哪个源先拉完而变。
    slots = [None] * len(sites_config)
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as executor:
        futures = {executor.submit(Site, conf): i for i, conf in enumerate(sites_config)}
        for future in as_completed(futures):
            i = futures[future]
            try:
                slots[i] = future.result()
            except Exception as e:
                print(f"订阅源加载出现错误: {e}")
    sites = [s for s in slots if s is not None]

    # 检查订阅源名称唯一性（下面靠 name 把检测结果分回各源，重名会串）。
    # 必须把拉取失败的源也算进来：若 A、B 同名而 B 恰好拉取失败，只查成功的源
    # 就会放行，随后 B 会从 by_site 里领到 A 的那批节点，同一批节点被写两遍，
    # mihomo 直接报 "proxy xxx is the duplicate name" 拒绝加载。
    site_names = [site.name for site in sites]
    if len(site_names) != len(set(site_names)):
        dupes = sorted({n for n in site_names if site_names.count(n) > 1})
        print(f"错误: 订阅源的名称不唯一（重复：{', '.join(dupes)}），"
              f"请确保每个订阅源的 name 字段不同")
        sys.exit(1)

    failed = [site.name for site in sites if site.data is None]
    if failed:
        print(f"警告：{len(failed)}/{len(sites)} 个订阅源拉取失败："
              f"{', '.join(failed)}，这些源的节点全部缺失")

    # ── 阶段一：本地过滤，六个源全部做完再往下走
    all_nodes = []
    for site in sites:
        if site.data is not None:
            try:
                all_nodes.extend(site.prepare())
            except Exception as e:
                print(f"订阅源 {site.name} 过滤失败: {e}")

    # ── 阶段二：一次子进程，全部节点一起测
    available = BatchValidator().validate(all_nodes)

    # ── 阶段三：按订阅源把结果拆回去
    by_site = {}
    for node in available:
        by_site.setdefault(node.get('subscription'), []).append(node)
    for site in sites:
        # 拉取失败的源一个节点都没提交检测，不该打"检测完成，0 个可用"
        # —— 那会把"订阅拉不到"伪装成"节点全挂了"，排查时误导
        if site.data is None:
            continue
        site.accept(by_site.get(site.name, []))

    # 判断哪个源值得留在 sources.yaml 里，靠这张表，不靠上面那一串"N 个节点可用"
    log_source_stats(sites, all_nodes, available)

    proxy_count = 0
    for site in sites:
        if not site.nodes:
            continue
        config_template['proxies'] += site.nodes
        matched = [g for g in config_template['proxy-groups']
                   if g.get('name') == site.group]
        if not matched:
            # 不喊出来的话，这些节点会进 proxies 但不属于任何分组，
            # 在 Clash 里根本选不到 —— 测出来的合格节点静默作废
            print(f"警告：{site.name} 的目标代理组 {site.group} 不存在，"
                  f"{len(site.nodes)} 个节点不会出现在任何分组里")
        for group in matched:
            group['proxies'] += site.get_titles()
        proxy_count += len(site.nodes)

    output_file = sys.argv[2] if len(sys.argv) >= 3 else "output.yaml"

    # 零节点的配置 mihomo 会直接拒绝加载：代理组的 proxies 和 use 皆空时
    # adapter/outboundgroup/parser.go:96 返回 errMissProxy（COMPATIBLE 兜底只对
    # include-all-proxies 生效，我们用不上）。真写出去等于用一份坏文件覆盖掉
    # 上一份好的，而 commit.bat 不看退出码就 git add/commit/push，坏文件会被推上去。
    if proxy_count == 0:
        print(f"错误：没有任何可用节点，拒绝覆盖 {output_file}（保留上一份配置）")
        sys.exit(1)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(yaml.dump(config_template, default_flow_style=False, allow_unicode=True))
    except Exception as e:
        print(f"写入输出文件失败: {e}")
        sys.exit(1)

    print(f"已生成包含 {proxy_count} 个节点的配置文件：{output_file}")


if __name__ == "__main__":
    main()
