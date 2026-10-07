# FileProbe · 未授权文件读取探测检测

`rain.op` 每日安全小 Agent 系列的第 3 个：**流量监测**方向。

针对 **CVE-2026-21589**（CVSS 9.3）：Atlassian 数据中心 8 款产品
（Bitbucket、Confluence、Jira Software、Jira Service Management、
Bamboo、Crowd、Crucible、Fisheye）存在未认证任意文件读取漏洞，
攻击者知道确切文件名和路径即可读取 web 根目录下指定文件。

本工具分析 HTTP 访问日志（Combined Log Format），识别针对 Atlassian
产品的**路径遍历 / 敏感文件探测 / 指纹扫描**行为，按源 IP 聚合输出告警。
纯 Python 标准库，离线可运行。

## 检测规则

| 规则 | 说明 | 示例 |
|---|---|---|
| `traversal` | 路径遍历特征（含单/双层 URL 编码、`%c0%ae` overlong 编码、`..;` 绕过） | `..%2f..%2fWEB-INF/web.xml` |
| `sensitive_file` | 请求指向敏感文件（配置文件、密钥、系统文件） | `web.xml`、`dbconfig.xml`、`crowd.properties`、`/etc/passwd`、`.git/HEAD` |
| `file_param` | `file=`/`path=`/`filename=` 等参数携带遍历或绝对路径 | `download?file=../../../../etc/passwd` |
| `scanner_ua` | 已知扫描器 UA（nuclei、goby、xray、sqlmap…，辅助信号） | `nuclei/3.2.0` |

按源 IP 聚合定级：

| 严重度 | 条件 |
|---|---|
| 高危 | 敏感文件探测请求返回 **200** 且有正文 → 疑似已成功读取文件 |
| 中危 | ≥3 条可疑请求，或覆盖 ≥2 款产品/入口，或命中路径遍历 |
| 低危 | 单次可疑探测 |

## 快速开始

```bash
# 一键演示：生成合成日志（含正常流量 + 3 组攻击）并检测
python fileprobe.py --demo

# 检测自己的访问日志
python fileprobe.py -i /var/log/nginx/access.log -o alerts.json

# 单独生成示例日志
python gen_sample.py -o sample.log --seed 42
```

## 输入格式

Combined Log Format（Nginx / Apache 默认格式），例如：

```
203.0.113.77 - - [06/Oct/2026:14:02:11 +0800] "GET /confluence/plugins/servlet/../..%2fWEB-INF/web.xml HTTP/1.1" 404 512 "-" "nuclei/3.2.0"
```

## 示例输出

```
========================================================
FileProbe 文件读取探测检测报告 | 分析请求: 100 条
========================================================

发现 3 条告警:

[1] [高危] 疑似成功利用：未授权文件读取
  源 IP: 198.51.100.23
  1 个敏感文件请求返回 200（如 /confluence/download/attachments/12345/..%2f..%2fWEB-INF%2fweb.xml），可能已成功读取 web 根目录下文件，请立即排查

[2] [中危] Atlassian 产品文件探测/扫描
  源 IP: 203.0.113.77
  12 条可疑请求，命中规则 ['file_param', 'scanner_ua', 'sensitive_file', 'traversal']，覆盖产品/入口 ['bamboo', 'bitbucket', 'confluence', 'crowd', 'crucible', 'fisheye', 'jira-software']；多为路径遍历或敏感文件探测尝试

[3] [低危] 单次可疑文件探测
  源 IP: 192.0.2.44
  GET /jira/plugins/servlet/mobile?file=seraph-config.xml -> 404（file_param,sensitive_file）
```

同时生成 `alerts.json`（结构化告警，便于下游 SIEM 接入），包含每条可疑请求的
时间、方法、目标 URL、状态码和命中规则。

## 参数

- `-i FILE`：输入访问日志路径（与 `--demo` 二选一）
- `-o FILE`：JSON 告警输出路径（默认 `alerts.json`）
- `--demo`：演示模式，内置生成 100 条合成日志并检测
- 退出码：有高危告警时返回 1，便于接入 cron / 流水线

## 局限与后续

- 日志里看不到是否真的未认证：高危告警是"疑似成功"，需结合 WAF/应用日志二次确认
- 启发式规则可能漏掉全新绕过手法；`SENSITIVE_FILES` 清单可按实际资产补充
- 后续可迭代：基于历史基线的扫描行为学习、对 200 响应正文做关键字二次校验（如 `root:`）、多 IP 协同扫描关联
