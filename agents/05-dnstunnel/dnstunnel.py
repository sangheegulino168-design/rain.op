#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNSTunnel · DNS 隧道 / 数据渗出检测

rain.op 每日安全小 Agent 系列的第 5 个：**流量监测**方向。

做法：读取 DNS 查询日志（或内置演示流量），按二层域名聚合统计，
用 6 组启发式特征打分，输出 0–100 的疑似 DNS 隧道风险评分、
告警报告和 alerts.json。

日志行格式（空格分隔）：
    <时间戳> <客户端IP> <查询域名> <查询类型>
例如：
    2026-10-09T09:01:02 10.0.0.5 a8f3b2c9d1e4f5.tunnel.evil.example.com TXT

纯标准库，离线可运行。
"""
import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime

RARE_TYPES = {"TXT", "NULL", "CNAME"}          # 隧道常用记录类型
SCORE_HIGH, SCORE_SUSPICIOUS = 70, 40          # 分档阈值


# ---------- 工具函数 ----------

def shannon_entropy(s: str) -> float:
    """香农熵：base64 风格载荷通常熵很高（>4.5）"""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def base_domain(qname: str) -> str:
    """
    聚合粒度：域名越深取越多段。
    - 3 段及以下（www.baidu.com）→ 取后 2 段：baidu.com
    - 4 段及以上（xxx.tunnel.evil.example.com）→ 取后 3 段：tunnel.evil.example.com
    这样隧道/渗出用的攻击子域名不会和主站的正常流量混在一起。
    """
    parts = qname.lower().strip(".").split(".")
    keep = 3 if len(parts) >= 4 else 2
    return ".".join(parts[-keep:])


def leftmost(qname: str) -> str:
    """最左侧子域名（隧道载荷通常塞在这里）"""
    parts = qname.lower().strip(".").split(".")
    return parts[0] if parts else ""


# ---------- 解析 ----------

def parse_line(line: str):
    """解析一行日志 → (datetime|None, client_ip, qname, qtype)"""
    parts = line.strip().split()
    if len(parts) < 4:
        return None
    ts = None
    try:
        ts = datetime.fromisoformat(parts[0])
    except ValueError:
        pass
    return ts, parts[1], parts[2].strip(".").lower(), parts[3].upper()


# ---------- 特征与打分 ----------

def score_domain(domain, queries):
    """
    queries: 该域名下所有 (ts, client, qname, qtype) 记录
    返回 (score, details)
    """
    n = len(queries)
    lefts = [leftmost(q[2]) for q in queries]
    uniq_fqdn = len({q[2] for q in queries})
    types = Counter(q[3] for q in queries)
    labels_max = max((len(l) for l in lefts), default=0)
    labels_avg = sum(len(l) for l in lefts) / n if n else 0
    ent_avg = sum(shannon_entropy(l) for l in lefts) / n if n else 0
    rare_ratio = sum(types[t] for t in RARE_TYPES if t in types) / n if n else 0
    uniq_ratio = uniq_fqdn / n if n else 0
    clients = {q[1] for q in queries}

    # 每分钟峰值查询速率（按客户端聚合）
    per_min = Counter()
    for ts, client, _, _ in queries:
        if ts:
            per_min[(client, ts.strftime("%Y-%m-%dT%H:%M"))] += 1
    peak_rate = max(per_min.values(), default=0)

    score = 0
    hits = []  # 命中的启发式特征

    def add(pts, name, detail):
        nonlocal score
        score += pts
        hits.append(f"{name}: {detail}")

    if labels_max >= 40:
        add(30, "超长子域名", f"最长标签 {labels_max} 字符（疑似编码载荷）")
    elif labels_avg >= 20:
        add(15, "子域名偏长", f"平均标签 {labels_avg:.1f} 字符")
    if ent_avg >= 3.8 and labels_avg >= 10:
        add(20, "高熵载荷", f"子域名平均熵 {ent_avg:.2f}")
    if rare_ratio >= 0.5 and n >= 10:
        add(20, "异常记录类型", f"{rare_ratio:.0%} 查询使用 {sorted(RARE_TYPES & set(types))}")
    elif rare_ratio >= 0.2 and n >= 10:
        add(10, "异常记录类型", f"{rare_ratio:.0%} 查询使用 {sorted(RARE_TYPES & set(types))}")
    if uniq_ratio >= 0.8 and uniq_fqdn >= 10:
        add(20, "海量唯一子域名", f"{uniq_fqdn} 个不同 FQDN（疑似数据渗出）")
    if peak_rate >= 30:
        add(20, "查询速率爆发", f"单客户端峰值 {peak_rate} 次/分钟")
    elif peak_rate >= 10:
        add(10, "查询频率偏高", f"单客户端峰值 {peak_rate} 次/分钟")
    if n >= 50 and len(clients) <= 2:
        add(10, "集中来源", f"{n} 次查询只来自 {len(clients)} 个客户端")

    return min(score, 100), {
        "queries": n,
        "unique_fqdn": uniq_fqdn,
        "longest_label": labels_max,
        "avg_entropy": round(ent_avg, 2),
        "rare_type_ratio": round(rare_ratio, 2),
        "peak_per_min": peak_rate,
        "clients": sorted(clients)[:5],
        "hits": hits,
    }


def level(score: int) -> str:
    if score >= SCORE_HIGH:
        return "高危"
    if score >= SCORE_SUSPICIOUS:
        return "可疑"
    return "正常"


# ---------- 分析主流程 ----------

def analyze(lines):
    records = [r for r in (parse_line(l) for l in lines) if r]
    groups = defaultdict(list)
    for r in records:
        groups[base_domain(r[2])].append(r)

    results = []
    for domain, qs in groups.items():
        s, d = score_domain(domain, qs)
        results.append({"domain": domain, "score": s, "level": level(s), "details": d})
    results.sort(key=lambda x: -x["score"])
    return results, len(records)


def render(results, n_records):
    out = [f"共解析 {n_records} 条 DNS 查询日志",
           f"{'域名':<38}{'评分':<6}{'等级':<6}{'命中特征'}",
           "-" * 90]
    for r in results:
        out.append(f"{r['domain']:<38}{r['score']:<6}{r['level']:<6}{'; '.join(r['details']['hits']) or '—'}")
    return "\n".join(out)


# ---------- 演示流量生成 ----------

def _b64ish(rng_seed, length):
    import random
    rnd = random.Random(rng_seed)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
    return "".join(rnd.choice(alphabet) for _ in range(length))


def demo_lines():
    import random
    rnd = random.Random(20261009)
    base = datetime(2026, 10, 9, 9, 0, 0)
    lines = []

    def stamp(i):
        return (base + __import__("datetime").timedelta(seconds=i)).isoformat()

    # 1) 正常流量：A/AAAA 查询，短域名
    normal = ["www.baidu.com", "mail.google.com", "api.github.com",
              "update.microsoft.com", "login.taobao.com"]
    for i, d in enumerate(normal * 12):
        lines.append(f"{stamp(i*7)} 10.0.0.{2 + i % 8} {d} {'AAAA' if i % 3 == 0 else 'A'}")

    # 2) DNS 隧道流量：长 base64 子域名 + TXT，单客户端高频
    for i in range(80):
        payload = _b64ish(9000 + i, 52)
        lines.append(f"{stamp(400 + i * 3)} 10.0.0.99 {payload}.tunnel.evil.example.com TXT")

    # 3) 数据渗出：大量不同子域名，一次性查询
    for i in range(30):
        lines.append(f"{stamp(900 + i * 11)} 10.0.0.7 exfil{_b64ish(7000 + i, 24)}.leak.data.example.net A")

    # 4) 边缘干扰：合法长 TXT（SPF 记录查询），不应被高分
    for i in range(6):
        lines.append(f"{stamp(1200 + i * 40)} 10.0.0.3 example.com TXT")

    rnd.shuffle(lines)
    return sorted(lines)


# ---------- CLI ----------

def main():
    ap = argparse.ArgumentParser(description="DNSTunnel · DNS 隧道 / 数据渗出检测")
    ap.add_argument("--demo", action="store_true", help="演示模式：内置正常 + 隧道 + 渗出流量")
    ap.add_argument("--file", help="DNS 查询日志文件路径")
    ap.add_argument("--json", default="alerts.json", help="告警 JSON 输出路径（默认 alerts.json）")
    args = ap.parse_args()

    if args.demo:
        lines = demo_lines()
    elif args.file:
        with open(args.file, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    else:
        lines = sys.stdin.read().splitlines()
        if not lines:
            ap.error("请提供 --demo / --file，或通过管道输入日志")

    results, n = analyze(lines)
    print(render(results, n))

    alerts = [r for r in results if r["score"] >= SCORE_SUSPICIOUS]
    with open(args.json, "w", encoding="utf-8") as f:
        json.dump({"generated": datetime.now().isoformat(),
                   "threshold_suspicious": SCORE_SUSPICIOUS,
                   "alerts": alerts}, f, ensure_ascii=False, indent=2)
    print(f"\n告警 {len(alerts)} 个（≥{SCORE_SUSPICIOUS} 分）→ {args.json}")


if __name__ == "__main__":
    main()
