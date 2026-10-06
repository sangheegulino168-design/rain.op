# rain.op —— 每日网络安全小 Agent

每天一个网络安全方向的小 agent，RAG 与流量监测两个方向交替。
每个 agent 独立目录、小而精、离线可运行（演示模式不依赖外部 API Key）。

## Agent 索引

| 编号 | 名称 | 一句话介绍 | 方向 |
|------|------|-----------|------|
| 01 | [FlowScan](agents/01-flowscan/) | 轻量流量异常检测：识别端口扫描、SYN Flood、内网 Beaconing，自带流量生成器做演示 | 流量监测 |
| 02 | [SecQA](agents/02-secqa/) | 离线安全知识问答：BM25 检索 + 抽取式回答，内置 24 条 Web/系统/应急知识，纯标准库 | RAG |

## 约定

- 每个 agent 在 `agents/NN-英文名/` 下自成一体，含中文 README、主程序、演示模式。
- 尽量只用 Python 标准库，保证 clone 下来就能跑。
