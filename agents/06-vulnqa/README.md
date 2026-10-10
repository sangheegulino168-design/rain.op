# VulnQA 🕵️ 漏洞情报问答小助手

离线运行的漏洞情报问答 agent：用 **BM25 检索**内置的 20 条高危 CVE 知识库，
回答"这是什么漏洞、影响谁、怎么修"，输出结构化**漏洞情报卡片**。纯 Python 标准库，
clone 下来就能跑，不依赖任何外部 API。

方向：**RAG**（检索增强问答）

## 能做什么

- 🆔 **按编号精确查询**：`CVE-2021-44228` 直接命中知识库条目
- 🔍 **自然语言提问**：中文问句经分词（英文单词 + 中文字符二元组）后做 BM25 检索，
  领域通用词（漏洞/高危/修复…）自动过滤，编号/别名/产品/关键词字段加权
- 🃏 **情报卡片**：编号、别名、产品、类别、严重度、影响范围、漏洞描述、修复建议一目了然，
  另附相关漏洞引用 `[KB-xx]`
- 📚 **知识库**：20 条真实高危 CVE（Log4Shell、永恒之蓝、心脏滴血、ProxyLogon、
  Spring4Shell、ZeroLogon、BlueKeep、Dirty COW…），覆盖 RCE / 提权 / 信息泄露 / SQL 注入

## 怎么跑

```bash
cd agents/06-vulnqa

# 演示模式：自动回答 4 个示例问题
python vulnqa.py --demo

# 直接提问
python vulnqa.py "Log4Shell 怎么修复？"
python vulnqa.py "Exchange 有哪些高危漏洞？"
python vulnqa.py "提权漏洞有哪些"

# 按 CVE 编号精确查询（大小写不敏感）
python vulnqa.py --cve CVE-2021-44228

# 列出知识库全部 20 条漏洞
python vulnqa.py --list
```

需要 Python 3.8+，无第三方依赖（无 `requirements.txt`）。

## 示例输出

```
$ python vulnqa.py "Log4Shell 怎么修复？"

┌─ 漏洞情报卡 [KB-01]
│ 编号：CVE-2021-44228（Log4Shell）
│ 产品：Apache Log4j2
│ 类别：远程代码执行　严重度：严重 10.0
│ 影响：log4j-core 2.0-beta9 ~ 2.14.1（Java 生态大量组件间接依赖）
│ 描述：JNDI 注入漏洞：攻击者通过日志内容（如 ${jndi:ldap://...}）触发 Log4j2 解析，
│       下载并执行远程恶意类，实现远程代码执行。
│ 修复：升级到 Log4j 2.17.1+；临时缓解：设置 log4j2.formatMsgNoLookups=true 或删除 JndiLookup 类。
└─

相关漏洞：
  · CVE-2015-0235（GHOST 鬼影） [KB-11]
  · CVE-2021-26084（Confluence OGNL 注入） [KB-18]
```

## 实现要点

- `BM25`：极简实现（k1=1.2, b=0.75），判别字段（编号/别名/产品/类别/关键词）重复 3 次加权
- `STOPWORDS`：查询侧过滤领域通用词，避免"高危漏洞"这类泛词带偏检索
- 回答策略：CVE 编号正则精确匹配优先 → BM25 取 top-1 生成卡片 → 相关项（得分 > 0.4×top1）列引用；
  无命中时明确告知并提示 `--list`

## 局限

- 知识库是 20 条 CVE 的**摘要版**，CVSS 与影响范围以公开披露为准，生产环境请以 NVD/CNNVD 为准
- 抽取式回答基于固定字段模板，不做跨条目推理；查不到的编号会明确说"未收录"
