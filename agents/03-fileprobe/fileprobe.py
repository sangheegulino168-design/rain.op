#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FileProbe · 未授权文件读取探测检测

针对 CVE-2026-21589（Atlasssian 数据中心 8 款产品未认证任意文件读取，
CVSS 9.3）：攻击者知道确切文件名和路径即可读取 web 根目录下指定文件。

本工具分析 HTTP 访问日志（Combined Log Format），识别针对 Atlassian
产品的路径遍历 / 敏感文件探测 / 指纹扫描行为，按源 IP 聚合输出告警。

纯 Python 标准库，离线可运行。

用法：
    python fileprobe.py --demo                 # 一键演示：生成合成日志并检测
    python fileprobe.py -i access.log          # 检测自己的日志文件
    python fileprobe.py -i access.log -o alerts.json
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import unquote, urlsplit, parse_qsl

# ---------------------------------------------------------------- 规则库

# 路径遍历特征（匹配前会做最多 2 层 URL 解码，同时在原串上也匹配一次）
TRAVERSAL_RES = [
    re.compile(r"\.\./"),          # ../
    re.compile(r"\.\.\\\\"),       # ..\
    re.compile(r"\.\.%2f", re.I),  # ..%2f（单层编码残留）
    re.compile(r"\.\.%5c", re.I),
    re.compile(r"%c0%ae", re.I),   # overlong UTF-8 编码的 .
    re.compile(r"%c1%9c", re.I),   # overlong UTF-8 编码的 \
    re.compile(r"\.\.;"),          # ..;（Tomcat/Atlassian 常见绕过）
    re.compile(r"/\./"),           # /./ 混淆
]

# 敏感文件：文件名或路径片段（小写匹配）
SENSITIVE_FILES = [
    "web.xml", "server.xml", "context.xml", "webdefault.xml",
    "dbconfig.xml", "seraph-config.xml", "seraph-config.xml",
    "crowd.properties", "bitbucket.properties", "bamboo.cfg.xml",
    "atlassian-user.xml", "osuser.xml", "application.properties",
    "application.yml", "application.yaml", ".env",
    "/etc/passwd", "/etc/shadow", "win.ini", "system32",
    "id_rsa", "authorized_keys", ".git/head", ".git/config",
    "catalina.out", "atlassian-jira.log", "atlassian-confluence.log",
]

# 8 款受影响产品 + 通用 Atlassian 入口（用于指纹扫描判定）
ATLASSIAN_PRODUCTS = {
    "confluence": ["confluence", "wiki"],
    "jira-software": ["jira"],
    "jira-service-management": ["servicedesk", "customer"],
    "bitbucket": ["bitbucket", "stash"],
    "bamboo": ["bamboo"],
    "crowd": ["crowd"],
    "crucible": ["crucible"],
    "fisheye": ["fisheye"],
}
GENERIC_ENDPOINTS = ["rest", "plugins", "download", "s/", "rpc", "servlet"]

# 已知扫描器 UA（弱信号，仅作辅助）
SCANNER_UAS = [
    "nuclei", "goby", "xray", "sqlmap", "masscan", "zgrab",
    "nessus", "openvas", "nikto", "wpscan", "dirbuster",
    "gobuster", "feroxbuster", "httpx", "acunetix",
]

# 文件类查询参数
FILE_PARAMS = {"file", "path", "filename", "filepath", "template",
               "include", "page", "name", "doc", "download"}

# Combined Log Format
LOG_RE = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+)(?: HTTP/[\d.]+)?" '
    r"(\d{3}) (\S+)(?: \"[^\"]*\" \"([^\"]*)\")?"
)


# ---------------------------------------------------------------- 工具函数

def decode_multi(s, layers=2):
    """最多做 layers 层 URL 解码，返回 (解码后, 是否发生过解码)。"""
    cur, changed = s, False
    for _ in range(layers):
        nxt = unquote(cur)
        if nxt == cur:
            break
        cur, changed = nxt, True
    return cur, changed


def parse_line(line):
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    ip, ts_raw, method, target, status, size, ua = m.groups()
    try:
        ts = datetime.strptime(ts_raw.split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        ts = None
    parts = urlsplit(target)
    return {
        "ip": ip, "ts": ts, "method": method,
        "path": parts.path or "/", "query": parts.query or "",
        "status": int(status),
        "size": 0 if size == "-" else int(size),
        "ua": (ua or "").lower(),
    }


def match_traversal(text):
    """在原文和解码后文本上匹配路径遍历特征。"""
    decoded, _ = decode_multi(text)
    for rx in TRAVERSAL_RES:
        if rx.search(text) or rx.search(decoded):
            return True
    return False


def match_sensitive(path):
    """路径是否指向敏感文件。"""
    low = decode_multi(path)[0].lower()
    return any(sig in low for sig in SENSITIVE_FILES)


def match_file_param(query):
    """查询串里是否有 file/path 类参数携带可疑值。"""
    for k, v in parse_qsl(query, keep_blank_values=True):
        if k.lower() in FILE_PARAMS and v:
            val = decode_multi(v)[0]
            if (match_traversal(v) or match_traversal(val)
                    or val.startswith("/") or re.match(r"^[a-zA-Z]:", val)
                    or match_sensitive(val)):
                return k, v
    return None


def atlassian_context(path):
    """返回命中的产品名集合（用于指纹扫描判定）。"""
    low = path.lower()
    hits = set()
    for product, keys in ATLASSIAN_PRODUCTS.items():
        if any(f"/{k}" in low or low.startswith(f"/{k}")
               or f"/{k}/" in low for k in keys):
            hits.add(product)
    return hits


def classify_request(req):
    """对单条请求打标，返回命中规则列表。"""
    hits = []
    target = req["path"] + ("?" + req["query"] if req["query"] else "")
    if match_traversal(target):
        hits.append("traversal")
    if match_sensitive(req["path"]) or (
            req["query"] and match_sensitive(req["query"])):
        hits.append("sensitive_file")
    fp = match_file_param(req["query"])
    if fp:
        hits.append(f"file_param:{fp[0]}")
    if any(u in req["ua"] for u in SCANNER_UAS):
        hits.append("scanner_ua")
    return hits


# ---------------------------------------------------------------- 聚合告警

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


def aggregate(suspicious):
    """按源 IP 聚合，生成告警。"""
    by_ip = defaultdict(list)
    for req, hits in suspicious:
        by_ip[req["ip"]].append((req, hits))

    alerts = []
    for ip, items in sorted(by_ip.items()):
        rules = {h.split(":")[0] for _, hs in items for h in hs}
        statuses = [r["status"] for r, _ in items]
        products = set()
        for r, _ in items:
            products |= atlassian_context(r["path"])

        # 高危：敏感文件探测且返回 200（疑似成功读取）
        exploited = [r for r, hs in items
                     if "sensitive_file" in {h.split(":")[0] for h in hs}
                     and r["status"] == 200 and r["size"] > 0]
        if exploited:
            sev, title = "high", "疑似成功利用：未授权文件读取"
            detail = ("{} 个敏感文件请求返回 200（如 {}），可能已成功读取 "
                      "web 根目录下文件，请立即排查".format(
                          len(exploited), exploited[0]["path"][:80]))
        elif len(items) >= 3 or len(products) >= 2 or "traversal" in rules:
            sev, title = "medium", "Atlassian 产品文件探测/扫描"
            detail = ("{} 条可疑请求，命中规则 {}，覆盖产品/入口 {}；"
                      "多为路径遍历或敏感文件探测尝试".format(
                          len(items), sorted(rules) or "无",
                          sorted(products) or "通用"))
        else:
            sev, title = "low", "单次可疑文件探测"
            r0 = items[0][0]
            tgt0 = r0["path"] + ("?" + r0["query"] if r0["query"] else "")
            detail = "{} {} -> {}（{}）".format(
                r0["method"], tgt0[:100], r0["status"],
                ",".join(sorted(rules)))

        evidence_reqs = [
            {"ts": r["ts"].strftime("%Y-%m-%d %H:%M:%S") if r["ts"] else None,
             "method": r["method"],
             "target": (r["path"] + ("?" + r["query"] if r["query"] else ""))[:200],
             "status": r["status"], "size": r["size"], "rules": hs}
            for r, hs in items[:10]
        ]
        alerts.append({
            "type": "file_read_probe",
            "severity": sev,
            "title": title,
            "src_ip": ip,
            "detail": detail,
            "products": sorted(products),
            "request_count": len(items),
            "evidence": evidence_reqs,
        })
    alerts.sort(key=lambda a: SEVERITY_ORDER[a["severity"]], reverse=True)
    return alerts


def analyze(lines):
    total = 0
    suspicious = []
    for line in lines:
        if not line.strip():
            continue
        req = parse_line(line)
        if req is None:
            continue
        total += 1
        hits = classify_request(req)
        if hits:
            suspicious.append((req, hits))
    return total, aggregate(suspicious)


# ---------------------------------------------------------------- 输出

SEV_CN = {"high": "高危", "medium": "中危", "low": "低危"}


def print_report(total, alerts):
    bar = "=" * 56
    print(bar)
    print("FileProbe 文件读取探测检测报告 | 分析请求: {} 条".format(total))
    print(bar)
    if not alerts:
        print("\n未发现可疑的文件读取探测行为。")
        return
    print("\n发现 {} 条告警:\n".format(len(alerts)))
    for i, a in enumerate(alerts, 1):
        print("[{}] [{}] {}".format(i, SEV_CN[a["severity"]], a["title"]))
        print("  源 IP: {}".format(a["src_ip"]))
        print("  {}".format(a["detail"]))
        if a["evidence"]:
            e0 = a["evidence"][0]
            print("  示例: {} {} -> {}".format(
                e0["method"], e0["target"][:90], e0["status"]))
        print()


def main(argv=None):
    ap = argparse.ArgumentParser(description="FileProbe：检测 Atlassian 未授权文件读取探测")
    ap.add_argument("-i", "--input", help="访问日志文件（Combined Log Format）")
    ap.add_argument("-o", "--output", default="alerts.json", help="JSON 告警输出路径")
    ap.add_argument("--demo", action="store_true", help="演示模式：生成合成日志并检测")
    args = ap.parse_args(argv)

    if args.demo:
        from gen_sample import generate
        lines = generate()
        print("演示模式：已生成 {} 条合成访问日志（含正常流量 + 3 组攻击）\n".format(len(lines)))
    elif args.input:
        with open(args.input, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    else:
        ap.error("请指定 -i 日志文件，或使用 --demo 演示")

    total, alerts = analyze(lines)
    print_report(total, alerts)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)
    print("结构化告警已写入 {}".format(args.output))

    return 1 if any(a["severity"] == "high" for a in alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
