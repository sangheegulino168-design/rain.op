#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_sample.py · 生成 FileProbe 演示用的合成 HTTP 访问日志（Combined Log Format）。

场景：
  正常用户：浏览 Confluence / Jira 页面（无告警）
  攻击者 A（扫描器）：用 nuclei 式 UA 对 8 款 Atlassian 产品做路径遍历 + 敏感文件探测
  攻击者 B（定向利用）：构造 CVE-2026-21589 式文件读取请求，其中一条返回 200（疑似成功）
  攻击者 C（慢速试探）：少量 file= 参数探测，单次低危

用法：
    python gen_sample.py -o sample.log --seed 42
    python gen_sample.py   # 直接打印到 stdout，供 fileprobe --demo 内部调用
"""

import argparse
import random
from datetime import datetime, timedelta

NORMAL_PATHS = [
    ("/confluence/display/TEAM/Weekly+Sync", 200),
    ("/confluence/rest/api/content/12345", 200),
    ("/jira/browse/PROJ-1024", 200),
    ("/jira/rest/api/2/issue/PROJ-1024", 200),
    ("/bitbucket/projects/CORE/repos/api/browse", 200),
    ("/bamboo/browse/BUILD-PLAN-42", 200),
    ("/crowd/console/", 200),
    ("/s/abc123/_/download/batch/css/batch.css", 200),
    ("/favicon.ico", 200),
    ("/login.jsp", 200),
]

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

# 攻击者 A：扫描器式探测（nuclei UA，多产品 + 遍历 + 敏感文件）
ATTACKER_A = [
    ("/confluence/plugins/servlet/../..%2fWEB-INF/web.xml", 404),
    ("/jira/rest/api/2/..%2f..%2f..%2fetc%2fpasswd", 404),
    ("/bitbucket/plugins/servlet/download?file=../../../../etc/passwd", 400),
    ("/bamboo/download/..%c0%ae..%c0%ae/WEB-INF/web.xml", 404),
    ("/crowd/console/..;/WEB-INF/web.xml", 404),
    ("/crucible/plugins/servlet/../../dbconfig.xml", 404),
    ("/fisheye/plugins/servlet/download?path=/etc/passwd", 400),
    ("/rest/api/latest/..%252f..%252fseraph-config.xml", 404),
    ("/confluence/s/..%2f..%2fbitbucket.properties", 404),
    ("/jira/secure/..%5c..%5cwin.ini", 404),
    ("/bamboo/admin/..%2f..%2fapplication.properties", 404),
    ("/crowd/rest/usermanagement/1/../../crowd.properties", 404),
]

# 攻击者 B：定向利用（其中一条返回 200 + 正文，疑似成功读取）
ATTACKER_B = [
    ("/confluence/plugins/servlet/login?file=WEB-INF/web.xml", 404),
    ("/confluence/download/attachments/12345/..%2f..%2fWEB-INF%2fweb.xml", 200),
    ("/confluence/rest/api/content?file=../../../../etc/passwd", 400),
]

# 攻击者 C：慢速单次试探
ATTACKER_C = [
    ("/jira/plugins/servlet/mobile?file=seraph-config.xml", 404),
]


def fmt(ip, ts, method, target, status, size, ua, ref="-"):
    t = ts.strftime("%d/%b/%Y:%H:%M:%S +0800")
    return (f'{ip} - - [{t}] "{method} {target} HTTP/1.1" '
            f'{status} {size} "{ref}" "{ua}"')


def generate(seed=42, normal_users=6, reqs_per_user=14):
    rnd = random.Random(seed)
    base = datetime(2026, 10, 6, 14, 0, 0)
    lines = []
    t = base

    def tick(lo=2, hi=40):
        nonlocal_t = [t]
        def _tick():
            nonlocal_t[0] += timedelta(seconds=rnd.randint(lo, hi))
            return nonlocal_t[0]
        return _tick

    # 正常流量
    for u in range(normal_users):
        ip = f"10.1.5.{20 + u}"
        ua = rnd.choice(NORMAL_UAS)
        nxt = tick()
        for _ in range(reqs_per_user):
            path, st = rnd.choice(NORMAL_PATHS)
            size = rnd.randint(800, 60000) if st == 200 else rnd.randint(150, 900)
            lines.append(fmt(ip, nxt(), "GET", path, st, size, ua))

    # 攻击者 A：扫描器，短时间内密集探测
    nxt = tick(1, 4)
    ua_a = "nuclei/3.2.0"
    for path, st in ATTACKER_A:
        size = 5120 if st == 200 else rnd.randint(150, 900)
        lines.append(fmt("203.0.113.77", nxt(), "GET", path, st, size, ua_a))

    # 攻击者 B：定向利用
    nxt = tick(20, 90)
    ua_b = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
    for path, st in ATTACKER_B:
        size = 18432 if st == 200 else rnd.randint(150, 900)
        lines.append(fmt("198.51.100.23", nxt(), "GET", path, st, size, ua_b))

    # 攻击者 C：慢速试探
    nxt = tick(300, 900)
    for path, st in ATTACKER_C:
        lines.append(fmt("192.0.2.44", nxt(), "GET", path, st, 512, ua_b))

    # 按时间排序，还原真实日志顺序
    lines.sort(key=lambda ln: ln.split("[")[1].split("]")[0])
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", help="输出文件（缺省打印到 stdout）")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    lines = generate(seed=args.seed)
    text = "\n".join(lines) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"已生成 {len(lines)} 条日志 -> {args.output}")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
