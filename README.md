# rain.op

每天一个网络安全小 Agent：RAG 与流量监测方向轮换，要么新做一个，要么迭代之前的不完善之处。

Every day, one tiny security agent: alternating between RAG and traffic-monitoring, either brand-new or an iteration on a previous one.

## Agent 索引 / Index

| # | 日期 | 名称 | 方向 | 说明 |
|---|---|---|---|---|
| 01 | 2026-10-05 | [FlowScan](agents/01-flowscan/) | 流量监测 | 轻量流量异常检测：端口扫描 / SYN Flood / 内网 Beacon，纯标准库，`--demo` 一键演示 |

## 目录约定

```
agents/<NN>-<name>/
  README.md      # 中文说明：用途、用法、示例输出
  *.py           # 实现（优先纯标准库、离线可运行）
```

## 运行要求

- Python 3.8+
- 无第三方依赖（除非该 agent 的 README 另有说明）
