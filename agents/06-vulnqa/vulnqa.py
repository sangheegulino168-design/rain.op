#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulnQA — 离线漏洞情报问答小助手
================================
BM25 检索内置的 20 条高危 CVE 知识库，回答"这是什么漏洞、影响谁、怎么修"，
输出结构化的漏洞情报卡片，纯标准库，离线可运行。

用法:
    python vulnqa.py --demo                 # 演示模式：回答 4 个示例问题
    python vulnqa.py "Log4Shell 怎么修复？"  # 直接提问
    python vulnqa.py --cve CVE-2021-44228   # 按编号精确查询
    python vulnqa.py --list                 # 列出知识库全部漏洞
"""

import argparse
import math
import re
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# 知识库：20 条真实高危 CVE（摘要版，字段: 编号/别名/产品/类别/严重度/影响范围/描述/修复）
# ---------------------------------------------------------------------------
KB = [
    dict(id="CVE-2021-44228", alias="Log4Shell", product="Apache Log4j2", cat="远程代码执行",
         sev="严重 10.0", affected="log4j-core 2.0-beta9 ~ 2.14.1（Java 生态大量组件间接依赖）",
         desc="JNDI 注入漏洞：攻击者通过日志内容（如 ${jndi:ldap://...}）触发 Log4j2 解析，"
              "下载并执行远程恶意类，实现远程代码执行。",
         fix="升级到 Log4j 2.17.1+；临时缓解：设置 log4j2.formatMsgNoLookups=true 或删除 JndiLookup 类。",
         kw="log4shell log4j jndi ldap 注入 java 日志"),
    dict(id="CVE-2014-0160", alias="心脏滴血 Heartbleed", product="OpenSSL", cat="信息泄露",
         sev="高危 7.5", affected="OpenSSL 1.0.1 ~ 1.0.1f（含 1.0.2-beta）",
         desc="TLS 心跳扩展缺少边界检查，攻击者可每次读取服务端内存 64KB，多次请求可窃取私钥、"
              "会话 Cookie 等敏感数据。",
         fix="升级 OpenSSL 到 1.0.1g+；事后必须更换私钥并重新签发证书、强制用户改密码。",
         kw="heartbleed 心脏滴血 openssl tls 心跳 内存泄露"),
    dict(id="CVE-2017-0144", alias="永恒之蓝 EternalBlue", product="Windows SMBv1", cat="远程代码执行",
         sev="高危 8.1", affected="未安装 MS17-010 补丁的 Windows（XP~Server 2012）",
         desc="SMBv1 协议处理特制数据包时发生缓冲区溢出，无需认证即可远程执行代码，"
              "是 WannaCry 勒索蠕虫的传播武器。",
         fix="安装 MS17-010 安全更新；禁用 SMBv1（建议全面迁移 SMBv2/3）；内网隔离老旧主机。",
         kw="eternalblue 永恒之蓝 wannacry 勒索 smb 蠕虫"),
    dict(id="CVE-2021-26855", alias="ProxyLogon", product="Microsoft Exchange Server", cat="服务端请求伪造",
         sev="严重 9.8", affected="Exchange Server 2013 / 2016 / 2019（未打 2021-03 安全更新）",
         desc="SSRF 漏洞链：攻击者绕过认证访问后端 ECP 接口，结合反序列化/任意文件写入实现 RCE，"
              "常被用于投放 WebShell。",
         fix="立即安装对应版本的 Exchange 安全更新；检查服务器是否存在可疑 WebShell 并做应急响应。",
         kw="proxylogon exchange ssrf 邮件 webshell hafnium"),
    dict(id="CVE-2022-22965", alias="Spring4Shell", product="Spring Framework", cat="远程代码执行",
         sev="严重 9.8", affected="Spring Framework 5.2.x/5.3.x（JDK 9+，特定数据绑定场景）",
         desc="JDK 9+ 下 Spring 数据绑定可访问 ClassLoader，攻击者构造请求写入恶意类，"
              "在 Tomcat 等容器下实现远程代码执行。",
         fix="升级到 Spring 5.3.26+ / 6.0.8+；或设置 disallowedFields 限制 class.* 绑定。",
         kw="spring4shell spring java 数据绑定 classloader"),
    dict(id="CVE-2014-6271", alias="破壳 Shellshock", product="GNU Bash", cat="远程代码执行",
         sev="严重 9.8", affected="Bash 4.3 及更早版本（CGI、DHCP 客户端等调用 bash 的场景）",
         desc="Bash 解析环境变量中的函数定义时执行尾随命令，攻击者可通过 HTTP 头、"
              "DHCP 等向量远程执行任意命令。",
         fix="升级 Bash 到修复版本；检查 CGI 脚本等暴露面。",
         kw="shellshock 破壳 bash 环境变量 cgi"),
    dict(id="CVE-2019-0708", alias="BlueKeep", product="Windows 远程桌面 RDP", cat="远程代码执行",
         sev="严重 9.8", affected="Windows 7 / Server 2008 R2 / XP / 2003（RDP 服务暴露时）",
         desc="RDP 预认证阶段处理连接请求时发生问题，无需任何凭证即可远程执行代码，"
              "具备蠕虫化传播潜力。",
         fix="安装官方补丁；RDP 不直接暴露公网，启用网络级身份验证 NLA；老旧系统考虑升级。",
         kw="bluekeep rdp 远程桌面 蠕虫 预认证"),
    dict(id="CVE-2020-1472", alias="ZeroLogon", product="Windows Netlogon", cat="权限提升",
         sev="严重 10.0", affected="Windows Server 2008R2 ~ 2019 域控制器",
         desc="Netlogon 远程协议的加密认证存在缺陷，攻击者可在数秒内将域控机器账户密码置空，"
              "进而接管整个域。",
         fix="安装 2020-08 安全更新并开启强制模式；监控 Netlogon 安全通道异常事件。",
         kw="zerologon netlogon 域控 域 提权"),
    dict(id="CVE-2021-34527", alias="PrintNightmare", product="Windows 打印后台处理程序", cat="远程代码执行",
         sev="高危 8.8", affected="全版本 Windows（打印服务运行时）",
         desc="打印后台处理程序校验不足，普通用户可安装恶意驱动实现本地提权，"
              "特定配置下可远程执行代码。",
         fix="安装官方补丁；非打印服务器直接禁用 Print Spooler 服务；限制 Point and Print。",
         kw="printnightmare 打印 spooler 提权 驱动"),
    dict(id="CVE-2021-34473", alias="ProxyShell", product="Microsoft Exchange Server", cat="远程代码执行",
         sev="严重 9.8", affected="Exchange Server 2013 / 2016 / 2019（未打 2021-04/05 累积更新）",
         desc="ACL 绕过 + ECP 反序列化 + 任意文件写入的三段式利用链，无需认证即可在 "
              "Exchange 服务器上执行任意代码。",
         fix="安装 2021-04 或 2021-05 累积更新；排查 WebShell 与持久化后门。",
         kw="proxyshell exchange acl 反序列化 webshell"),
    dict(id="CVE-2015-0235", alias="GHOST 鬼影", product="glibc", cat="远程代码执行",
         sev="严重 10.0（旧评分体系）", affected="glibc 2.2 ~ 2.17（Linux 各发行版广泛受影响）",
         desc="gethostbyname 系列函数处理超长主机名时发生堆缓冲区溢出，"
              "可通过 DNS 相关调用路径远程触发。",
         fix="升级 glibc 到 2.18+；重启受影响服务。",
         kw="ghost 鬼影 glibc 堆溢出 gethostbyname dns"),
    dict(id="CVE-2017-5638", alias="Struts2 S2-045", product="Apache Struts2", cat="远程代码执行",
         sev="严重 10.0", affected="Struts 2.3.5 ~ 2.3.31、2.5 ~ 2.5.10",
         desc="Content-Type 头处理 Jakarta 文件上传时发生 OGNL 注入，攻击者发送特制请求头"
              "即可远程执行任意命令（Equifax 大规模数据泄露即源于此）。",
         fix="升级到 Struts 2.3.32 / 2.5.10.1+；检查是否已被入侵。",
         kw="struts2 s2-045 ognl equifax 上传 content-type"),
    dict(id="CVE-2019-19781", alias="Citrix 目录遍历", product="Citrix ADC / Gateway", cat="远程代码执行",
         sev="严重 9.8", affected="Citrix ADC 10.5/11.1/12.0/12.1、Gateway 12.1/13.0",
         desc="路径遍历漏洞允许未经认证的攻击者读取任意文件并写入 Web 目录，"
              "进而获取远程代码执行。",
         fix="升级到官方修复版本；检查设备是否被植入后门。",
         kw="citrix adc netscaler 目录遍历 vpn 网关"),
    dict(id="CVE-2020-5902", alias="F5 BIG-IP TMUI RCE", product="F5 BIG-IP", cat="远程代码执行",
         sev="严重 9.8", affected="BIG-IP 11.6.x ~ 15.1.x（管理界面暴露时）",
         desc="TMUI（管理界面）的目录遍历漏洞，攻击者可读取文件、上传 WebShell，"
              "直接控制负载均衡设备。",
         fix="升级到修复版本；管理界面禁止公网访问；按官方指引排查入侵痕迹。",
         kw="f5 big-ip tmui 目录遍历 负载均衡 webshell"),
    dict(id="CVE-2021-22205", alias="GitLab ExifTool RCE", product="GitLab CE/EE", cat="远程代码执行",
         sev="严重 10.0", affected="GitLab 11.9 ~ 13.8.8 / 13.9.6 / 13.10.3",
         desc="上传图片时 ExifTool 解析 DjVu 元数据触发命令注入，认证用户可借此在 "
              "GitLab 服务器上执行任意命令。",
         fix="升级到 13.8.8 / 13.9.6 / 13.10.3+；检查异常进程与定时任务。",
         kw="gitlab exiftool djvu 图片上传 命令注入"),
    dict(id="CVE-2022-30190", alias="Follina", product="Windows MSDT", cat="远程代码执行",
         sev="高危 7.8", affected="Windows 全版本（MSDT 协议处理器可用时）",
         desc="Office 文档通过 ms-msdt: 协议调用微软支持诊断工具，攻击者构造恶意文档"
              "诱导打开即可执行 PowerShell，实现 0day 钓鱼攻击。",
         fix="安装 2022-06 安全更新；曾用注册表禁用 ms-msdt 协议作为临时缓解。",
         kw="follina msdt office 钓鱼 powershell 0day"),
    dict(id="CVE-2023-34362", alias="MOVEit SQL 注入", product="Progress MOVEit Transfer", cat="SQL 注入",
         sev="严重 9.8", affected="MOVEit Transfer 2021.0.x / 2021.1.x / 2022.0.x / 2023.0.x",
         desc="文件传输应用的 SQL 注入漏洞，未经认证即可访问数据库并窃取文件，"
              "引发大规模供应链数据泄露事件（Cl0p 勒索团伙利用）。",
         fix="升级到修复版本；轮换相关凭证并做数据泄露影响评估。",
         kw="moveit sql注入 文件传输 供应链 cl0p 勒索"),
    dict(id="CVE-2021-26084", alias="Confluence OGNL 注入", product="Atlassian Confluence", cat="远程代码执行",
         sev="严重 9.8", affected="Confluence Server/Web 6.13.x ~ 7.12.x（特定版本）",
         desc="OGNL 表达式注入漏洞，未经认证的攻击者发送特制请求即可在 Confluence "
              "服务器上执行任意代码。",
         fix="升级到 7.4.17 / 7.11.6 / 7.12.5+；检查服务器入侵痕迹。",
         kw="confluence ognl 注入 wiki atlassian"),
    dict(id="CVE-2018-7600", alias="Drupalgeddon2", product="Drupal", cat="远程代码执行",
         sev="严重 9.8", affected="Drupal 7.x < 7.58、8.x < 8.5.1",
         desc="表单 API 缺少输入校验导致远程代码执行，无需认证，是 Drupalgeddon "
              "之后又一高危漏洞，常被用于挖矿与批量挂马。",
         fix="升级到 7.58 / 8.5.1+；检查网站文件完整性。",
         kw="drupalgeddon drupal cms 挂马 挖矿"),
    dict(id="CVE-2016-5195", alias="脏牛 Dirty COW", product="Linux 内核", cat="权限提升",
         sev="高危 7.8", affected="Linux 内核 2.6.22+（长达 9 年未修复）",
         desc="内存子系统处理写时复制（COW）时存在竞态条件，本地普通用户可写入只读内存映射，"
              "修改 /etc/passwd 等文件实现 root 提权。",
         fix="升级内核到修复版本；云主机/容器宿主机同样需要更新。",
         kw="dirtycow 脏牛 内核 提权 cow 竞态"),
]

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# 领域通用词：几乎每条漏洞描述里都有，判别力≈0，查询时直接忽略
STOPWORDS = {"漏洞", "高危", "严重", "危漏", "漏漏", "影响", "修复", "哪些",
             "什么", "怎么", "多少", "有没有", "有没", "没有", "介绍", "讲讲",
             "以及", "或者", "vulnerability", "cve"}

# ---------------------------------------------------------------------------
# 分词：英文单词 + 中文字符二元组，适配中英混合检索
# ---------------------------------------------------------------------------
def tokenize(text):
    text = text.lower()
    toks = []
    for w in re.findall(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", text):
        toks.append(w)
    cjk = re.findall(r"[\u4e00-\u9fff]", text)
    for a, b in zip(cjk, cjk[1:]):
        toks.append(a + b)
    return toks


class BM25:
    """极简 BM25（k1=1.2, b=0.75），纯标准库。"""

    def __init__(self, docs):
        self.docs = docs
        self.N = len(docs)
        self.doc_tf = [Counter(tokenize(d)) for d in docs]
        self.doc_len = [sum(c.values()) for c in self.doc_tf]
        self.avg_len = sum(self.doc_len) / self.N if self.N else 0
        df = Counter()
        for tf in self.doc_tf:
            for t in tf:
                df[t] += 1
        self.idf = {t: math.log(1 + (self.N - n + 0.5) / (n + 0.5))
                    for t, n in df.items()}

    def score(self, query):
        qtoks = [t for t in tokenize(query) if t not in STOPWORDS]
        if not qtoks:  # 全是通用词时回退到不过滤
            qtoks = tokenize(query)
        scores = []
        for i, tf in enumerate(self.doc_tf):
            s = 0.0
            dl = self.doc_len[i] or 1
            for t in qtoks:
                f = tf.get(t)
                if not f:
                    continue
                idf = self.idf.get(t, 0)
                s += idf * f * 2.2 / (f + 1.2 * (1 - 0.75 + 0.75 * dl / self.avg_len))
            scores.append(s)
        return scores


def entry_text(e):
    # 编号/别名/产品/类别/关键词是判别力最强的字段，重复 3 次加权
    head = " ".join([e["id"], e["alias"], e["product"], e["cat"], e["kw"]])
    body = " ".join([e["sev"], e["affected"], e["desc"]])
    return " ".join([head] * 3 + [body])


RETRIEVER = BM25([entry_text(e) for e in KB])


def find_by_cve(query):
    m = CVE_RE.search(query)
    if not m:
        return None
    cid = m.group(0).upper()
    for e in KB:
        if e["id"] == cid:
            return e
    return None


def retrieve(query, top_k=3):
    scores = RETRIEVER.score(query)
    ranked = sorted(range(len(KB)), key=lambda i: scores[i], reverse=True)
    return [(KB[i], scores[i]) for i in ranked[:top_k] if scores[i] > 0]


def card(e, cite=None):
    tag = " [{}]".format(cite) if cite else ""
    return (
        "┌─ 漏洞情报卡{0}\n"
        "│ 编号：{1}（{2}）\n"
        "│ 产品：{3}\n"
        "│ 类别：{4}　严重度：{5}\n"
        "│ 影响：{6}\n"
        "│ 描述：{7}\n"
        "│ 修复：{8}\n"
        "└─".format(tag, e["id"], e["alias"], e["product"], e["cat"],
                    e["sev"], e["affected"], e["desc"], e["fix"])
    )


def answer(query):
    """检索增强回答：精确编号优先，否则 BM25 取最相关条目生成情报卡。"""
    direct = find_by_cve(query)
    if direct:
        return card(direct, cite="精确匹配")

    hits = retrieve(query, top_k=3)
    if not hits:
        return ("知识库中没有找到与「{}」相关的漏洞。\n"
                "试试 --list 查看全部 20 条收录漏洞，或换关键词再问。".format(query))
    best, score = hits[0]
    out = [card(best, cite="KB-{:02d}".format(KB.index(best) + 1))]
    related = [e for e, _ in hits[1:] if _ > score * 0.4]
    if related:
        out.append("\n相关漏洞：")
        for e in related:
            out.append("  · {}（{}）{}"
                       .format(e["id"], e["alias"],
                               " [KB-{:02d}]".format(KB.index(e) + 1)))
    return "\n".join(out)


def list_kb():
    lines = ["知识库共收录 {} 条高危漏洞：".format(len(KB)), ""]
    for i, e in enumerate(KB, 1):
        lines.append("{:02d}. {}（{}）— {} / {}"
                     .format(i, e["id"], e["alias"], e["product"], e["sev"]))
    return "\n".join(lines)


def demo():
    questions = [
        "Log4Shell 是什么漏洞，影响哪些版本，怎么修复？",
        "永恒之蓝利用了什么协议，造成了什么危害？",
        "心脏滴血漏洞为什么叫这个名字，修复后还要注意什么？",
        "Exchange 有哪些高危漏洞？",
    ]
    print("=" * 60)
    print("VulnQA 演示模式：漏洞情报问答（知识库 20 条 CVE，离线运行）")
    print("=" * 60)
    for q in questions:
        print("\n❓ 问：{}".format(q))
        print(answer(q))
        print("-" * 60)


def main(argv=None):
    ap = argparse.ArgumentParser(description="VulnQA — 离线漏洞情报问答小助手")
    ap.add_argument("question", nargs="?", help="要问的漏洞问题")
    ap.add_argument("--demo", action="store_true", help="演示模式")
    ap.add_argument("--list", action="store_true", help="列出知识库全部漏洞")
    ap.add_argument("--cve", help="按 CVE 编号精确查询，如 CVE-2021-44228")
    args = ap.parse_args(argv)

    if args.demo or (not args.question and not args.list and not args.cve):
        demo()
    elif args.list:
        print(list_kb())
    elif args.cve:
        e = find_by_cve(args.cve)
        print(card(e, cite="精确匹配") if e
              else "知识库未收录 {}，试试 --list。".format(args.cve.upper()))
    else:
        print(answer(args.question))


if __name__ == "__main__":
    sys.exit(main())
