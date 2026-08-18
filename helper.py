#!/usr/bin/env python3
print("Script starting...")

import sys
import os
import json
import math
import base64
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
# 600ms = 及格线 500ms + 100ms 灰区缓冲：贴线的好节点偶尔探到 500-600ms
# 不至于被当死节点丢样本；600ms 以上反正淘汰，不值得等。
# 97% 的节点是死节点、每个都吃满这个超时 —— 这是最大的单项省时。
TEST_TIMEOUT_MS = 800
TEST_CONCURRENCY = 128
# 每个节点重复采样的轮数。抖动和成功率都需要多个样本才存在，等于 1 时两者都没有意义
# （抖动字段不会出现，成功率恒为 1/1）。
#
# 必须是【多轮独立进程】而不是一轮里对同一节点并发发多次请求：同一瞬间发出的请求
# 测的是同一个网络状态，测不出时间上的波动。每轮之间天然隔着一次完整的全池扫描
# （约 146s），正好是抖动需要的时间跨度。
#
# 代价是线性的：全池 17527 个节点每轮约 146 秒，3 轮约 7.5 分钟。
SAMPLE_PASSES = 3
# 端点选择：google.com 本体比 gstatic.com（Google 的 CDN 边缘）严得多。
# 2026-08-11 用同一批 22 个已知可用节点实测：gstatic 通过 16 个，google.com 只通过 9 个。
# 保留 google.com 是有意的 —— 能连 CDN 却连不上本体的节点实际浏览也用不了。
# 两者都正常返回 HTTP 204、不跳转，和"只认 2xx + 禁跟转发"的判定兼容。
TEST_URL = "http://www.google.com/generate_204"

# 协议白名单（初筛）。只有 type 落在这里的节点才会进入关键词过滤和测速，
# 其余在拉取后立刻丢弃。动机是省测速时间：免费订阅里明文的 http / socks5 量很大，
# 2026-08-12 那轮 output.yaml 的 69 个可用节点里就占了 19 个（27.5%）。
# 匹配方式是原样精确比对 —— "VLESS"、" vless" 都不能收（mihomo 对 type
# 精确匹配小写，实测大写报 unsupport proxy type），"hy2" 也不能，
# 后者 mihomo 本来也解析不了（adapter/parser.go 只认 ss / ssr / socks5 / http /
# vmess / vless / snell / trojan / hysteria / hysteria2 / wireguard / tuic /
# ssh / mieru，外加 direct / dns / reject 三个非订阅类型）。
# 改成空集合即关闭初筛，全部协议照旧送去测。
ALLOWED_TYPES = frozenset({'vless', 'trojan', 'vmess', 'hysteria2'})

# ── 协议配置校验（2026-08-18 从 clash-speedtest 实测搬来）──
# clash-speedtest 加载聚合配置时逐条报错：invalid REALITY short ID / invalid
# REALITY public key / unsupported xtls flow type / missing obfs password /
# unsupported security type。这些节点即使测速通过也进不了 mihomo 内核，
# 在测速前就筛掉，省测速时间。
#
# short-id：必须是 hex 字符串，且 hex→int→hex 回写后长度为 2/4/8/16/32。
#   回写检查能抓住 '09'（前导零）这类裸看合法、内核却拒绝的值。
# vless flow 判定等价 mihomo vless.go：len < 16 完全不校验；len >= 16 时截断
# 到 16 字符必须等于 xtls-rprx-vision（实测 'xtls-rprx-origin' 16 字符被拒、
# 'xtls-rprx-vision-udp443-udp443' 截断后通过、'none' 等短值通过）。
VLESS_FLOW_PREFIX = 'xtls-rprx-vision'
# vmess cipher 完整支持列表（sing-vmess client.go switch + 实测 aes-128-cfb 通过）。
# 注意缺失/空串也被拒（实测 key 'cipher' missing / unsupported security type）。
VMESS_CIPHER_ALLOWED = ('auto', 'none', 'zero', 'aes-128-cfb',
                        'aes-128-gcm', 'chacha20-poly1305')

def _vless_flow_ok(flow):
    if not isinstance(flow, str):
        return False  # mihomo mapstructure 严格模式：非字符串直接拒
    return len(flow) < 16 or flow.startswith(VLESS_FLOW_PREFIX)

def _mlkem_padding_ok(padding):
    """等价 mihomo encryption/common.go 的 ParsePadding：每段 a-b-c 数字，
    首段 a>=100 且 b,c>=35，偶数段 max(b,c) 总和 <=65553。"""
    if padding == '':
        return True
    max_len = 0
    for i, s in enumerate(padding.split('.')):
        x = s.split('-')
        if len(x) < 3 or not x[0] or not x[1] or not x[2]:
            return False
        try:
            y0, y1, y2 = int(x[0]), int(x[1]), int(x[2])
        except ValueError:
            return False
        if i == 0 and (y0 < 100 or y1 < 35 or y2 < 35):
            return False
        if i % 2 == 0:
            max_len += max(y1, y2)
    return max_len <= 65553

def _vless_encryption_ok(enc):
    """等价 mihomo transport/vless/encryption/factory.go 的 NewClient。

    ''/'none'/缺失 → 放行；否则必须是 mlkem768x25519plus.{native|xorpub|
    random}.{1rtt|0rtt}.<段>，其中至少一段 >= 20 字符的 RawURL base64 且
    解码为 32（X25519）或 1184（ML-KEM-768）字节 —— 全是短段会报
    "empty nfsPKeysBytes"；短段拼接后还要过 ParsePadding（a-b-c 数字格式）。
    实测 2026-08-18：真实订阅 26 个残缺值被 mihomo 拒。
    """
    if enc is None:
        return True
    s = str(enc)
    if s in ('', 'none'):
        return True
    parts = s.split('.')
    if len(parts) < 4 or parts[0] != 'mlkem768x25519plus':
        return False
    if parts[1] not in ('native', 'xorpub', 'random'):
        return False
    if parts[2] not in ('1rtt', '0rtt'):
        return False
    has_key = False
    paddings = []
    for r in parts[3:]:
        if len(r) < 20:
            paddings.append(r)
            continue
        if '=' in r:
            return False  # RawURLEncoding 拒 padding
        try:
            raw = base64.b64decode(r + '=' * (-len(r) % 4), altchars=b'-_')
        except Exception:
            return False
        if len(raw) not in (32, 1184):
            return False
        has_key = True
    if not has_key:
        return False
    return _mlkem_padding_ok('.'.join(paddings))

def _pyyaml_would_quote(s):
    """pyyaml safe_dump 会对这个字符串加引号吗（safe_load 能解析成非字符串即加）。"""
    if not s:
        return True
    try:
        return not isinstance(yaml.safe_load(s), str)
    except Exception:
        return True

def _yamlv2_int(s):
    """模拟 yaml.v2 对裸字符串的 int 判定（Go base-0 字面量 + 前导零十进制回退）。

    行为学实测：'09' → 9（八进制失败回退十进制）、'00' → 0、'010' → 8。
    """
    t = s.replace('_', '')
    neg = t[:1] == '-'
    body = t[1:] if t[:1] in '+-' else t
    if not body:
        return None
    try:
        if body[:2].lower() == '0b':
            v = int(body[2:], 2)
        elif body[:2].lower() == '0o':
            v = int(body[2:], 8)
        elif body[:2].lower() == '0x':
            v = int(body[2:], 16)
        elif len(body) > 1 and body[0] == '0':
            try:
                v = int(body, 8)
            except ValueError:
                v = int(body, 10)
        elif body[0] in '0123456789':
            v = int(body, 10)
        else:
            return None
    except ValueError:
        return None
    return -v if neg else v

def _reality_public_key_ok(pk):
    """等价 mihomo v1.19.19 reality.go：public-key 缺失 → 不校验（按普通 TLS 走）。

    非空时必须能 base64 无 padding（RawURLEncoding）解码且正好 32 字节。
    带 '=' 的标准带 padding 写法 mihomo 会拒（Raw 解码报错），这里也拒。
    """
    if pk is None:
        return True
    s = str(pk).strip()
    if not s:
        return True
    if '=' in s:
        return False
    try:
        raw = base64.b64decode(s + '=' * (-len(s) % 4), altchars=b'-_')
    except Exception:
        return False
    return len(raw) == 32

def _reality_short_id_ok(sid):
    """等价 mihomo 对 short-id 的判定（经 pyyaml 写 + yaml.v2 读的双序列化拟合）。

    行为学（27 个实测 case）：int 85 收 / int 9,0,255,65535,13871 拒；
    str '09' 裸写被 yaml.v2 读成 int 9 → 拒；'00' 被 pyyaml 加引号原样 → 收。
    终判：偶数位纯 hex 且解码字节数 ≤ 8（RealityMaxShortIDLen = 8）。
    """
    if sid is None:
        return True  # mihomo 对缺失 short-id 不校验（空 hex 解码 0 字节）
    if isinstance(sid, str):
        if _pyyaml_would_quote(sid):
            s_go = sid
        else:
            v = _yamlv2_int(sid)
            s_go = str(v) if v is not None else sid
    else:
        s_go = str(sid)
    if len(s_go) % 2 or not all(c in '0123456789abcdefABCDEF' for c in s_go):
        return False
    return len(s_go) // 2 <= 8

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

# 跨源去重（2026-08-18 第三次启用，规则来自聚合期决策）：
#   key = type|凭证（uuid/password/auth 首个非空），不看 server:port ——
#   免费池里同一组凭证被搬到无数 Cloudflare/中转 IP 上，测一个代表即可。
#   凭证全空时兜底 type|server|port。
# 前两次删除（01c881f 2025-02-18、后一次 2026-08-11）的共同前提是"重复只有
# 2.4%~9%、省时在噪声内"——那是在 6 个源、4790 个节点时实测的。现在 29 个源
# 66618 个送检节点里 type|凭证 重复占 84%（2026-08-18 实测，聚合源之间互相
# 抄：V2ray-Config 端点 99% 与其他源重叠、clashcode-nodes-meta 94%），
# 每轮约 5.5 万次重复测试纯浪费，前提已不成立。
# "同凭证不同端点、好坏并存"的顾虑当时也权衡过：免费池凭证复用极普遍，
# 全测一遍的边际收益远小于省下的时间，故按凭证合并、先到先得。
def dedup_key(node):
    cred = node.get('uuid') or node.get('password') or node.get('auth') or ''
    if cred:
        return (str(node.get('type') or ''), str(cred))
    return (str(node.get('type') or ''), str(node.get('server') or ''),
            node.get('port'))

def dedup_nodes(nodes):
    seen = set()
    kept = []
    for node in nodes:
        k = dedup_key(node)
        if k in seen:
            continue
        seen.add(k)
        kept.append(node)
    if len(kept) < len(nodes):
        log(f"[去重] {len(nodes)} -> {len(kept)}（省 {len(nodes) - len(kept)}，"
            f"同 type+凭证 只测首个代表，按 sources.yaml 先到先得）")
    return kept

# 构造 auth 时要从节点字典里剔掉的键。两类键的原因完全不同，别当成一类：
#   name / type / server / port        —— 是真正的代理参数，但 payload 里已经
#                                         单独给过了，留在 auth 里等于重复传
#   _orig_name / subscription /        —— 我们自己的记账字段，不是代理参数。
#   latency / success / jitter            这几个会一并写进 output.yaml，是历史
#                                         输出一直带着的，Clash 能容忍，保持原样
#
# success / jitter 必须在这里列出来，否则一旦有人把 output.yaml 里的节点再喂回
# 检测（或者将来 validate 被同一批节点调用两次），它们会作为未知代理参数传给
# mihomo，让本来正常的节点报"代理初始化失败"。当前流程里 payload 在写入这些
# 字段之前就构造好了，碰不到这个问题，但不能指望调用顺序永远不变。
INTERNAL_KEYS = ('name', '_orig_name', 'type', 'server', 'port',
                 'subscription', 'latency', 'success', 'jitter')


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


def _jitter(values):
    """抖动 = 相邻两次采样之差的绝对值的平均（RFC 3550 口径，mtr / iperf 用的就是它）。

    为什么不是"最大减最小"：后者只反映一次最坏的尖刺，一个节点稳定在 300ms 但
    有一次卡到 900ms，和一个节点在 300/600/900 之间来回跳，最大减最小都是 600，
    但前者可用、后者不可用。相邻差能把这两种区分开。

    values 是【成功样本】按采样轮次排好的延迟。中间失败的轮次不产生样本，也就是
    跨过失败点直接比较前后两次 —— 失败本身已经由成功率记录，不必在抖动里重复计一遍。

    只有一个成功样本时没有"相邻"可言，返回 None（调用方据此不写 jitter 字段）。
    """
    if len(values) < 2:
        return None
    return sum(abs(values[i] - values[i - 1])
               for i in range(1, len(values))) / (len(values) - 1)


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
    jitters = {}
    for node in available:
        latencies.setdefault(node.get('subscription'), []).append(float(node.get('latency', 0)))
        # 只成功一次的节点没有 jitter 字段，不能当 0 计入 —— 那会把最不稳的节点
        # 算成最稳的。缺值就是缺值，直接不参与这一列的统计。
        if 'jitter' in node:
            jitters.setdefault(node.get('subscription'), []).append(float(node['jitter']))

    rows = []
    for site in sites:
        if site.data is None:
            # 拉取失败：分母是 0，命中率无从计算，不能和"全灭"并列
            rows.append({'name': site.name, 'fetched': None, 'sub': 0,
                         'ok': 0, 'rate': None, 'med': None, 'jit': None})
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
            'jit': _median(jitters.get(site.name, [])),
        })

    # 命中率降序，其次合格数降序。没有分母的（拉取失败、送检 0）沉到表尾。
    rows.sort(key=lambda r: (r['rate'] is None, -(r['rate'] or 0), -r['ok'], r['name']))

    widths = (14, 8, 8, 7, 10, 11, 11)
    log("")
    log("─" * sum(widths))
    log(_cell('订阅源', widths[0]) + _cell('抓取', widths[1], True)
        + _cell('送检', widths[2], True) + _cell('合格', widths[3], True)
        + _cell('命中率', widths[4], True) + _cell('延迟中位', widths[5], True)
        + _cell('抖动中位', widths[6], True))
    log("─" * sum(widths))
    for r in rows:
        fetched = '拉取失败' if r['fetched'] is None else str(r['fetched'])
        rate = '—' if r['rate'] is None else f"{r['rate'] * 100:.2f}%"
        med = '—' if r['med'] is None else f"{r['med']:.0f}ms"
        jit = '—' if r['jit'] is None else f"{r['jit']:.0f}ms"
        log(_cell(r['name'], widths[0]) + _cell(fetched, widths[1], True)
            + _cell(r['sub'], widths[2], True) + _cell(r['ok'], widths[3], True)
            + _cell(rate, widths[4], True) + _cell(med, widths[5], True)
            + _cell(jit, widths[6], True))
    log("─" * sum(widths))

    total_fetched = sum(r['fetched'] for r in rows if r['fetched'] is not None)
    total_sub = sum(r['sub'] for r in rows)
    total_ok = sum(r['ok'] for r in rows)
    all_lats = [lat for lats in latencies.values() for lat in lats]
    all_jits = [j for js in jitters.values() for j in js]
    log(_cell('合计', widths[0]) + _cell(total_fetched, widths[1], True)
        + _cell(total_sub, widths[2], True) + _cell(total_ok, widths[3], True)
        + _cell(f"{(total_ok / total_sub * 100) if total_sub else 0:.2f}%", widths[4], True)
        + _cell('—' if not all_lats else f"{_median(all_lats):.0f}ms", widths[5], True)
        + _cell('—' if not all_jits else f"{_median(all_jits):.0f}ms", widths[6], True))
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
# BatchValidator：一次子进程调用测完全部节点，重复 SAMPLE_PASSES 轮取样
#
# 旧版对每个节点单独启动一次 latency.exe。实测该程序光启动就要 382ms
# （32.8MB 二进制 + 整个 mihomo 引擎初始化），4790 个节点等于 30 分钟纯启动开销，
# 而且外层线程池被限制在 cpu_count//2 = 8 个并发。现在一轮只启动一次进程，
# 并发交给 Go 侧的 goroutine；采样多少轮就启动多少次，那点启动开销可以忽略。
class BatchValidator:
    def __init__(self, concurrency=TEST_CONCURRENCY, timeout_ms=TEST_TIMEOUT_MS,
                 threshold_ms=LATENCY_THRESHOLD, test_url=TEST_URL,
                 passes=SAMPLE_PASSES):
        self.concurrency = max(1, int(concurrency))
        self.timeout_ms = int(timeout_ms)
        self.passes = max(1, int(passes))
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
        # payload 只构造一次、多轮共用，三个原因：
        #   1. id 是 nodes 的下标，必须在各轮之间完全一致。否则聚合时会把 A 轮某个
        #      节点的样本记到 B 节点头上，而这种错一声不响，结果全是假的。
        #   2. 必须在起子进程【之前】构造。放在之后的话，一旦构造抛异常（节点里有
        #      不可 JSON 序列化的值），子进程已经起来了、stdin 从没被写过也没 close，
        #      它会永远卡在 io.ReadAll(os.Stdin) 上，而兜底强杀的 Timer 还没创建，
        #      于是留下一个 33MB 的孤儿进程占着管道。
        #   3. 顺带避免"跳过 port 非法的节点"那行告警每轮重复打一遍。
        payload = json.dumps(self._payload(nodes)).encode('utf-8')

        log(f"[检测] {total} 个节点 / {self.concurrency} 并发 / 单节点超时 "
            f"{self.timeout_ms}ms / 重复采样 {self.passes} 轮")

        # samples[id] 是长度恒为 passes 的列表，按轮次顺序存 (是否成功, 延迟)。
        # 某轮没返回结果的按失败补位，长度才能恒定 —— 成功率的分母必须是采样轮数，
        # 不能是"拿到结果的轮数"，否则子进程中途死掉会让活下来的节点成功率虚高。
        samples = {i: [] for i in range(total)}
        for pass_no in range(1, self.passes + 1):
            results = self._run_pass(payload, nodes, pass_no)
            for rid in range(total):
                res = results.get(rid)
                ok = bool(res and res.get('success'))
                samples[rid].append((ok, float(res.get('latency') or 0) if ok else 0.0))

        available = []
        hist = {}
        for idx, node in enumerate(nodes):
            oks = [lat for ok, lat in samples[idx] if ok]
            hist[len(oks)] = hist.get(len(oks), 0) + 1
            if not oks:
                continue
            # latency 的口径从"单次采样"变成"成功样本的平均值"，门槛也按平均值判。
            # 只成功一次的节点，平均值就是那一次 —— 它照旧能合格，只是 success 字段
            # 会写成 1/3，你在 output.yaml 里一眼能看出它是靠运气过的。
            mean = sum(oks) / len(oks)
            if mean > self.threshold_ms:
                continue
            node['latency'] = round(mean, 1)
            node['success'] = f"{len(oks)}/{self.passes}"
            jitter = _jitter(oks)
            if jitter is not None:
                node['jitter'] = round(jitter, 1)
            available.append(node)
        available.sort(key=lambda n: n.get('latency', float('inf')))

        spread = ', '.join(f"{k}/{self.passes} 次成功 {hist[k]} 个"
                           for k in sorted(hist, reverse=True) if k)
        log(f"[检测] 采样分布（至少成功一次的节点）：{spread or '无'}")
        jits = [n['jitter'] for n in available if 'jitter' in n]
        log(f"[检测] 合格节点抖动中位数 "
            f"{'—' if not jits else format(_median(jits), '.1f') + 'ms'}"
            f"，其中 {len(available) - len(jits)} 个只成功一次、没有抖动值")
        log(f"[检测] 完成：{len(available)}/{total} 个节点合格")
        return available

    def _run_pass(self, payload, nodes, pass_no):
        """跑一轮采样：起一次 latency.exe 把全部节点测一遍，返回 {id: 原始结果}。

        这里刻意不做门槛判定、不排序、不写任何字段 —— 一轮的结果说明不了什么，
        判定要等 validate 收齐所有轮次之后统一做。
        """
        total = len(nodes)
        waves = max(1, math.ceil(total / self.concurrency))
        budget = waves * (self.timeout_ms / 1000.0) * 3 + 120

        env = os.environ.copy()
        env['LATENCY_CONCURRENCY'] = str(self.concurrency)
        env['LATENCY_TIMEOUT_MS'] = str(self.timeout_ms)
        env['LATENCY_URL'] = self.test_url

        log(f"[检测] 第 {pass_no}/{self.passes} 轮采样开始"
            f"（约 {waves} 波 / 兜底上限 {int(budget)}s）")

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
                progress = f"[{pass_no}/{self.passes}][{completed}/{total}]"
                if res.get('success'):
                    lat = float(res.get('latency', 0))
                    # 这里不再写"合格"：单轮结果不是最终判定，门槛要等各轮平均出来才算
                    over = "" if lat <= self.threshold_ms else f"（超过 {self.threshold_ms}ms 门槛）"
                    log(f"[{sub}] {progress} {name} 延迟 {lat:.1f}ms{over}")
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
            # 整批共用一个进程，进程提前死掉不该让这一轮结果全丢，
            # 没拿到结果的按不可用处理并明确报出来
            log(f"[检测] 警告：第 {pass_no} 轮有 {missing} 个节点没有返回结果"
                f"（子进程退出码 {proc.returncode}），按不可用处理")
        return results

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
            # 不做 lower/strip：mihomo 对 type 精确匹配小写，实测 'VLESS' 直接报
            # unsupport proxy type（2026-08-18），转小写放行会让 output.yaml 拒载。
            kind = str(node.get('type') or '')
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

    def _apply_protocol_validation(self, nodes):
        """协议配置校验：筛掉 mihomo 内核会拒绝加载的节点。

        与 _apply_type_whitelist 一样放在关键词过滤之前 —— 规则只查字段
        值，一次能定去留；且校验对个别字段做无害化（hysteria2 的 obfs
        残留空密码直接摘掉），做在关键词过滤前不会影响后面的逻辑。
        """
        kept = []
        dropped = {}
        for node in nodes:
            reason = None
            kind = str(node.get('type') or '').lower()
            # mihomo mapstructure 严格模式：port/server 值 None 等同字段缺失直接拒；
            # port 是 bool、tls 是字符串同样拒（实测 2026-08-18）
            if node.get('server') is None or node.get('port') is None:
                reason = 'server/port 值为空'
            elif isinstance(node.get('port'), bool):
                reason = 'port 是 bool'
            elif kind in ('vless', 'trojan', 'vmess') and node.get('tls') is not None \
                    and not isinstance(node.get('tls'), bool):
                reason = 'tls 非 bool'
            elif kind == 'vless' and node.get('uuid') is None:
                reason = 'vless 缺 uuid'
            elif kind == 'trojan' and node.get('password') is None:
                reason = 'trojan 缺 password'
            ro = node.get('reality-opts')
            if isinstance(ro, dict):
                if not _reality_public_key_ok(ro.get('public-key')):
                    reason = 'reality public-key 非法'
                elif not _reality_short_id_ok(ro.get('short-id')):
                    reason = 'reality short-id 非法'
            if reason is None and kind == 'vless':
                flow = node.get('flow')
                if flow is not None and not _vless_flow_ok(flow):
                    reason = f'flow {flow!r} 不受支持'
                elif not _vless_encryption_ok(node.get('encryption')):
                    reason = f'encryption {node.get("encryption")!r} 不受支持'
            if reason is None and kind == 'vmess':
                cipher = node.get('cipher')
                if not isinstance(cipher, str) or cipher.lower() not in VMESS_CIPHER_ALLOWED:
                    reason = f'vmess cipher {cipher!r} 不受支持'
            if reason is None and kind == 'hysteria2':
                obfs = node.get('obfs')
                obfs_pw = node.get('obfs-password')
                if obfs is None or str(obfs) in ('', 'none'):
                    # 无混淆：清掉空残留，避免 obfs-password 空字符串触发内核报错
                    node.pop('obfs', None)
                    if obfs_pw in (None, ''):
                        node.pop('obfs-password', None)
                elif str(obfs) == 'salamander':
                    if not obfs_pw:
                        reason = 'hysteria2 salamander 缺 obfs-password'
                else:
                    reason = f'hysteria2 obfs {obfs!r} 不受支持'
            if reason:
                dropped[reason] = dropped.get(reason, 0) + 1
            else:
                kept.append(node)
        if dropped:
            detail = ', '.join(f"{k} {v}" for k, v in
                               sorted(dropped.items(), key=lambda kv: (-kv[1], kv[0])))
            log(f"[{self.name}] 协议校验丢弃 {sum(dropped.values())} 个"
                f"（{detail}），剩余 {len(kept)}")
        return kept

    def prepare(self):
        """只做本地过滤，不做检测。返回待检测的候选节点。"""
        if not self.data or 'proxies' not in self.data:
            log(f"[{self.name}] No proxies found")
            return []
        raw = self.data.get('proxies') or []
        filtered = self.filter.apply(
            self._apply_protocol_validation(self._apply_type_whitelist(raw)))
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
        seen = {}
        for node in self.nodes:
            orig = node.get('_orig_name', node.get('name', 'Unknown'))
            name = f"{self.name}-{orig}"
            # 同源内不同节点可能共享原始名（内容不同所以没被去重），
            # mihomo 对重名直接拒绝加载，加序号后缀保命。
            if name in seen:
                seen[name] += 1
                name = f"{name}-{seen[name]}"
            else:
                seen[name] = 1
            node['name'] = name
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

    # ── 阶段一.5：跨源去重（在全部源 prepare 完之后、送检之前，
    #    这样 all_nodes / log_source_stats 的分母自动就是去重后的送检集合）
    all_nodes = dedup_nodes(all_nodes)

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
