#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
flowscan.py - 轻量流量异常检测小工具

读取 NetFlow 风格 CSV 流量日志，用启发式规则检测三种常见异常：
  1. port_scan  端口扫描：单源在短时间内探测同一目标的大量端口
  2. syn_flood  SYN Flood：单源对目标发起大量半开（仅 SYN）连接
  3. beaconing  内网 Beacon：内网主机以固定间隔规律外联（疑似 C2 心跳）

输出：控制台可读报告 + JSON 告警文件。
纯 Python 标准库，离线可运行。

用法:
    python flowscan.py --demo                  # 一键演示（生成样本并检测）
    python flowscan.py -i flows.csv            # 检测指定文件
    python flowscan.py -i flows.csv -o alerts.json --window 120
"""

import argparse
import csv
import ipaddress
import json
import statistics
import sys
from collections import defaultdict, deque

CSV_FIELDS = ["ts", "src_ip", "dst_ip", "src_port", "dst_port",
              "proto", "packets", "bytes", "tcp_flags"]


# ---------- 基础工具 ----------

def is_internal(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_syn_only(flags):
    f = (flags or "").upper()
    return "S" in f and "A" not in f


def load_flows(path):
    flows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            try:
                flows.append({
                    "ts": int(float(row["ts"])),
                    "src_ip": row["src_ip"].strip(),
                    "dst_ip": row["dst_ip"].strip(),
                    "src_port": int(row.get("src_port") or 0),
                    "dst_port": int(row.get("dst_port") or 0),
                    "proto": (row.get("proto") or "").upper(),
                    "packets": int(row.get("packets") or 0),
                    "bytes": int(row.get("bytes") or 0),
                    "tcp_flags": (row.get("tcp_flags") or "").upper(),
                })
            except (ValueError, KeyError, AttributeError):
                continue  # 跳过坏行
    flows.sort(key=lambda x: x["ts"])
    return flows


# ---------- 检测器 ----------

def detect_port_scan(flows, window=60, port_threshold=15):
    """同一 (src,dst) 在滑动窗口内触及的去重端口数超过阈值。"""
    alerts = []
    groups = defaultdict(list)
    for fl in flows:
        if fl["proto"] != "TCP":
            continue
        groups[(fl["src_ip"], fl["dst_ip"])].append(fl)

    for (src, dst), evs in groups.items():
        evs.sort(key=lambda e: e["ts"])
        win, port_cnt = deque(), defaultdict(int)
        best = (0, None, None)
        for e in evs:
            win.append(e)
            port_cnt[e["dst_port"]] += 1
            while win and e["ts"] - win[0]["ts"] > window:
                old = win.popleft()
                port_cnt[old["dst_port"]] -= 1
                if port_cnt[old["dst_port"]] == 0:
                    del port_cnt[old["dst_port"]]
            if len(port_cnt) > best[0]:
                best = (len(port_cnt), win[0]["ts"], e["ts"])
        if best[0] >= port_threshold:
            alerts.append({
                "type": "port_scan",
                "severity": "high",
                "src_ip": src,
                "dst_ip": dst,
                "detail": "在 %d 秒窗口内探测 %d 个不同端口" % (window, best[0]),
                "evidence": {"ports": best[0], "window_start": best[1],
                             "window_end": best[2]},
            })
    return alerts


def detect_syn_flood(flows, window=60, syn_threshold=100):
    """同一 (src,dst) 在滑动窗口内的纯 SYN 包数量超过阈值。"""
    alerts = []
    groups = defaultdict(list)
    for fl in flows:
        if fl["proto"] == "TCP" and is_syn_only(fl["tcp_flags"]):
            groups[(fl["src_ip"], fl["dst_ip"])].append(fl)

    for (src, dst), evs in groups.items():
        evs.sort(key=lambda e: e["ts"])
        win = deque()
        best = (0, None, None)
        for e in evs:
            win.append(e)
            while win and e["ts"] - win[0]["ts"] > window:
                win.popleft()
            if len(win) > best[0]:
                best = (len(win), win[0]["ts"], e["ts"])
        if best[0] >= syn_threshold:
            alerts.append({
                "type": "syn_flood",
                "severity": "high",
                "src_ip": src,
                "dst_ip": dst,
                "detail": "在 %d 秒窗口内发起 %d 个半开 SYN 连接" % (window, best[0]),
                "evidence": {"syn_count": best[0], "window_start": best[1],
                             "window_end": best[2]},
            })
    return alerts


def detect_beaconing(flows, min_beacons=6, max_cv=0.20,
                     min_interval=20, max_interval=7200):
    """内网主机 -> 外网 IP 的连接时间间隔高度规律，疑似 C2 心跳。"""
    alerts = []
    groups = defaultdict(list)
    for fl in flows:
        if is_internal(fl["src_ip"]) and not is_internal(fl["dst_ip"]):
            groups[(fl["src_ip"], fl["dst_ip"], fl["dst_port"])].append(fl["ts"])

    for (src, dst, dport), tss in groups.items():
        tss = sorted(set(tss))
        if len(tss) < min_beacons + 1:
            continue
        intervals = [b - a for a, b in zip(tss, tss[1:])]
        intervals = [i for i in intervals if i > 0]
        if len(intervals) < min_beacons:
            continue
        mean = statistics.mean(intervals)
        if not (min_interval <= mean <= max_interval):
            continue
        cv = statistics.stdev(intervals) / mean if mean else 999
        if cv <= max_cv:
            alerts.append({
                "type": "beaconing",
                "severity": "medium",
                "src_ip": src,
                "dst_ip": dst,
                "detail": "以约 %d 秒固定间隔外联 %s:%d（%d 次），疑似 C2 心跳"
                          % (round(mean), dst, dport, len(tss)),
                "evidence": {"interval_mean": round(mean, 1),
                             "interval_cv": round(cv, 3),
                             "connections": len(tss)},
            })
    return alerts


def analyze(flows, window=60):
    alerts = []
    alerts += detect_port_scan(flows, window=window)
    alerts += detect_syn_flood(flows, window=window)
    alerts += detect_beaconing(flows)
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    alerts.sort(key=lambda a: sev_rank.get(a["severity"], 9))
    return alerts


# ---------- 报告 ----------

SEV_CN = {"high": "高危", "medium": "中危", "low": "低危"}
TYPE_CN = {"port_scan": "端口扫描", "syn_flood": "SYN Flood 攻击",
           "beaconing": "内网 Beacon（疑似 C2 心跳）"}


def print_report(alerts, n_flows):
    print("=" * 56)
    print("FlowScan 流量异常检测报告  |  分析流量: %d 条" % n_flows)
    print("=" * 56)
    if not alerts:
        print("未发现异常。")
        return
    print("发现 %d 条告警:\n" % len(alerts))
    for i, a in enumerate(alerts, 1):
        print("[%d] [%s] %s" % (i, SEV_CN.get(a["severity"], a["severity"]),
                                TYPE_CN.get(a["type"], a["type"])))
        print("    源: %s  ->  目标: %s" % (a["src_ip"], a["dst_ip"]))
        print("    %s" % a["detail"])
        print()


def main(argv=None):
    ap = argparse.ArgumentParser(description="轻量流量异常检测")
    ap.add_argument("-i", "--input", help="输入 CSV 流量日志路径")
    ap.add_argument("-o", "--out", default="alerts.json",
                    help="JSON 告警输出路径（默认 alerts.json）")
    ap.add_argument("--window", type=int, default=60,
                    help="滑动窗口秒数（默认 60）")
    ap.add_argument("--demo", action="store_true",
                    help="一键演示：生成合成样本并检测")
    args = ap.parse_args(argv)

    if args.demo:
        import gen_sample
        flows = gen_sample.generate()
        print("演示模式：已生成 %d 条合成流量（含 3 种植入攻击）\n" % len(flows))
    elif args.input:
        flows = load_flows(args.input)
        print("已载入 %d 条流量记录: %s\n" % (len(flows), args.input))
    else:
        ap.error("请指定 -i 输入文件，或使用 --demo 演示模式")
        return 2

    alerts = analyze(flows, window=args.window)
    print_report(alerts, len(flows))

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(alerts, f, ensure_ascii=False, indent=2)
    print("JSON 告警已写入: %s" % args.out)
    return 0 if not [a for a in alerts if a["severity"] == "high"] else 1


if __name__ == "__main__":
    sys.exit(main())
