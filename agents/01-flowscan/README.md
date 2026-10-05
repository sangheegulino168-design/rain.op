# FlowScan · 轻量流量异常检测

`rain.op` 每日安全小 Agent 系列的第 1 个：**流量监测**方向。

用纯启发式规则（无机器学习、无外部依赖）分析 NetFlow 风格的流量日志，
检测三种常见网络异常。纯 Python 标准库，离线可运行。

## 功能

| 检测项 | 规则 | 严重度 |
|---|---|---|
| 端口扫描 `port_scan` | 单源在 60s 窗口内探测同一目标 ≥15 个端口 | 高危 |
| SYN Flood `syn_flood` | 单源在 60s 窗口内发起 ≥100 个半开 SYN 连接 | 高危 |
| 内网 Beacon `beaconing` | 内网主机以固定间隔（变异系数 <0.2）规律外联 ≥6 次 | 中危 |

## 快速开始

```bash
# 一键演示：生成合成流量（含 3 种植入攻击）并检测
python flowscan.py --demo

# 检测自己的流量文件
python flowscan.py -i flows.csv -o alerts.json

# 单独生成样本数据
python gen_sample.py -o sample.csv --flows 2000 --seed 42
```

## 输入格式

CSV，表头：`ts,src_ip,dst_ip,src_port,dst_port,proto,packets,bytes,tcp_flags`

- `ts`：Unix 时间戳（秒）
- `tcp_flags`：`S` / `SA` / `A` / `F` / `R` 等组合；UDP 留空

示例：

```csv
ts,src_ip,dst_ip,src_port,dst_port,proto,packets,bytes,tcp_flags
1727962800,192.168.1.50,10.0.0.5,40001,22,TCP,1,60,S
1727962801,192.168.1.50,10.0.0.5,40002,80,TCP,1,60,S
```

## 示例输出

```
========================================================
FlowScan 流量异常检测报告  |  分析流量: 1860 条
========================================================
发现 3 条告警:

[1] [高危] 端口扫描
    源: 192.168.1.50  ->  目标: 10.0.0.5
    在 60 秒窗口内探测 40 个不同端口

[2] [高危] SYN Flood 攻击
    源: 192.168.1.60  ->  目标: 10.0.0.5
    在 60 秒窗口内发起 300 个半开 SYN 连接

[3] [中危] 内网 Beacon（疑似 C2 心跳）
    源: 192.168.1.70  ->  目标: 45.155.204.9
    以约 120 秒固定间隔外联 45.155.204.9:443（20 次），疑似 C2 心跳
```

同时生成 `alerts.json`（结构化告警，便于下游 SIEM 接入）：

```json
[
  {
    "type": "port_scan",
    "severity": "high",
    "src_ip": "192.168.1.50",
    "dst_ip": "10.0.0.5",
    "detail": "在 60 秒窗口内探测 40 个不同端口",
    "evidence": {"ports": 40, "window_start": 1727962800, "window_end": 1727962839}
  }
]
```

## 参数

- `--window N`：滑动窗口秒数（默认 60），端口扫描 / SYN Flood 共用
- `-o FILE`：JSON 告警输出路径（默认 `alerts.json`）
- 退出码：有高危告警时返回 1，便于接入 cron / 流水线

## 局限与后续

- 启发式规则会有误报/漏报可能，阈值可按环境调优
- 后续可迭代：基线学习（按历史流量自适应阈值）、DNS 隧道检测、横向移动关联
