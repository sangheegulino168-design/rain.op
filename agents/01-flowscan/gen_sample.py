#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_sample.py - 合成 NetFlow 风格流量日志生成器

生成 CSV 流量日志，包含正常背景流量和三种植入的攻击样本：
  1. 端口扫描：单源对单目标的多个端口快速探测
  2. SYN Flood：大量只有 SYN 标志的半开连接
  3. Beaconing：内网主机以固定间隔外联（模拟 C2 心跳）

CSV 字段: ts,src_ip,dst_ip,src_port,dst_port,proto,packets,bytes,tcp_flags
  ts        - Unix 时间戳（秒）
  tcp_flags - TCP 标志组合，如 S / SA / A / F / R；UDP 为空

纯标准库，离线可运行。
用法:
    python gen_sample.py -o sample.csv --flows 2000 --seed 42
"""

import argparse
import csv
import random
import time

HEADER = ["ts", "src_ip", "dst_ip", "src_port", "dst_port",
          "proto", "packets", "bytes", "tcp_flags"]

INTERNAL_HOSTS = ["192.168.1.%d" % i for i in range(10, 45)]
WEB_SERVER = "10.0.0.5"
DNS_SERVER = "10.0.0.6"
EXTERNAL_IPS = ["93.184.216.34", "142.250.190.14", "151.101.1.69",
                "104.16.132.229", "8.8.8.8"]


def _row(ts, src, dst, sport, dport, proto, pkts, byt, flags):
    return {"ts": ts, "src_ip": src, "dst_ip": dst, "src_port": sport,
            "dst_port": dport, "proto": proto, "packets": pkts,
            "bytes": byt, "tcp_flags": flags}


def gen_normal(rng, base_ts, duration, count):
    """正常背景流量：Web/DNS/少量外联。"""
    flows = []
    for _ in range(count):
        ts = base_ts + rng.randint(0, duration)
        src = rng.choice(INTERNAL_HOSTS)
        kind = rng.random()
        if kind < 0.55:                      # 内网 Web 访问
            dst, dport, flags = WEB_SERVER, 80, "A"
        elif kind < 0.75:                     # DNS
            dst, dport, flags = DNS_SERVER, 53, ""
        elif kind < 0.90:                     # 外网 HTTPS
            dst, dport, flags = rng.choice(EXTERNAL_IPS), 443, "A"
        else:                                 # 外网 HTTP
            dst, dport, flags = rng.choice(EXTERNAL_IPS), 80, "A"
        proto = "UDP" if dport == 53 else "TCP"
        flows.append(_row(ts, src, dst, rng.randint(1024, 65535), dport,
                          proto, rng.randint(2, 60),
                          rng.randint(200, 90000), flags))
    return flows


def gen_port_scan(rng, base_ts):
    """攻击1：端口扫描 192.168.1.50 -> 10.0.0.5，30 秒内扫 40 个端口。"""
    flows, t0 = [], base_ts + 600
    ports = rng.sample(range(1, 1024), 40)
    for i, p in enumerate(ports):
        flows.append(_row(t0 + i, "192.168.1.50", WEB_SERVER,
                          40000 + i, p, "TCP",
                          1, 60, "S" if rng.random() < 0.8 else "R"))
    return flows


def gen_syn_flood(rng, base_ts):
    """攻击2：SYN Flood 192.168.1.60 -> 10.0.0.5:80，60 秒 300 个半开连接。"""
    flows, t0 = [], base_ts + 1500
    for i in range(300):
        flows.append(_row(t0 + rng.randint(0, 60), "192.168.1.60",
                          WEB_SERVER, rng.randint(1024, 65535), 80,
                          "TCP", 1, 60, "S"))
    return flows


def gen_beaconing(rng, base_ts):
    """攻击3：Beaconing 192.168.1.70 -> 45.155.204.9:443，每 120s 心跳一次。"""
    flows, t0 = [], base_ts + 2400
    for i in range(20):
        ts = t0 + i * 120 + rng.randint(-3, 3)
        flows.append(_row(ts, "192.168.1.70", "45.155.204.9",
                          rng.randint(30000, 50000), 443,
                          "TCP", rng.randint(3, 8),
                          rng.randint(400, 1500), "A"))
    return flows


def generate(seed=42, n_normal=1500, duration=3600):
    rng = random.Random(seed)
    base_ts = int(time.time()) - duration
    flows = gen_normal(rng, base_ts, duration, n_normal)
    flows += gen_port_scan(rng, base_ts)
    flows += gen_syn_flood(rng, base_ts)
    flows += gen_beaconing(rng, base_ts)
    flows.sort(key=lambda f: f["ts"])
    return flows


def write_csv(flows, path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=HEADER)
        w.writeheader()
        w.writerows(flows)


def main():
    ap = argparse.ArgumentParser(description="合成流量日志生成器（含攻击样本）")
    ap.add_argument("-o", "--output", default="sample_flows.csv")
    ap.add_argument("--flows", type=int, default=1500,
                    help="正常背景流量条数（默认 1500）")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    flows = generate(seed=args.seed, n_normal=args.flows)
    write_csv(flows, args.output)
    print("已生成 %d 条流量记录 -> %s" % (len(flows), args.output))
    print("植入攻击: 端口扫描 x1, SYN Flood x1, Beaconing x1")


if __name__ == "__main__":
    main()
