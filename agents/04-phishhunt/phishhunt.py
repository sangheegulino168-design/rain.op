#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PhishHunt -- 钓鱼邮件智能分析（RAG 方向）

流程：解析邮件 -> 特征提取 -> BM25 检索钓鱼特征知识库 -> 风险评分 ->
      输出判定、证据、知识库引用与处置建议。

纯 Python 标准库，离线可运行，无需 API Key。

用法：
    python phishhunt.py --demo                 # 内置 2 封样本邮件演示
    python phishhunt.py --file mail.txt        # 分析本地邮件文本
    python phishhunt.py --text "..."           # 直接分析一段文本
    cat mail.txt | python phishhunt.py         # 从 stdin 读取
"""
import argparse
import json
import math
import os
import re
import sys
from collections import Counter

BASE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- 分词 / BM25

def tokenize(text):
    """中英混合分词：英文/数字按词切，中文按字二元切。"""
    text = text.lower()
    toks = re.findall(r'[a-z0-9]+(?:[._-][a-z0-9]+)*', text)
    chars = re.findall(r'[\u4e00-\u9fff]', text)
    toks += [chars[i] + chars[i + 1] for i in range(len(chars) - 1)]
    return toks


class BM25:
    def __init__(self, docs, k1=1.5, b=0.75):
        self.docs = docs                      # 每条是分词后的 list
        self.k1, self.b = k1, b
        self.N = len(docs)
        self.avgdl = sum(len(d) for d in docs) / max(self.N, 1)
        df = Counter()
        for d in docs:
            for t in set(d):
                df[t] += 1
        self.idf = {t: math.log(1 + (self.N - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def score(self, query):
        q = tokenize(query)
        out = []
        for idx, d in enumerate(self.docs):
            dl = len(d)
            tf = Counter(d)
            s = 0.0
            for t in q:
                if t not in tf:
                    continue
                f = tf[t]
                s += self.idf.get(t, 0) * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
            out.append((s, idx))
        return sorted(out, reverse=True)

# ---------------------------------------------------------------- 邮件解析

HEADER_RE = re.compile(r'^(From|To|Subject|Reply-To|Date)\s*:\s*(.*)$', re.I)
URL_RE = re.compile(r'https?://[^\s<>"\'\u4e00-\u9fff]+', re.I)


def parse_mail(raw):
    headers, body, in_head = {}, [], True
    for line in raw.splitlines():
        m = HEADER_RE.match(line)
        if in_head and m:
            headers[m.group(1).lower()] = m.group(2).strip()
            continue
        if in_head and not line.strip():
            in_head = False
            continue
        in_head = False
        body.append(line)
    return headers, '\n'.join(body)


def extract_urls(text):
    urls = []
    for u in URL_RE.findall(text):
        urls.append(u.rstrip('.,;:!?）)】'))
    return urls


def domain_of(url):
    m = re.match(r'https?://([^/:\s]+)', url, re.I)
    return m.group(1).lower() if m else ''


def split_address(addr):
    """'显示名 <a@b.com>' -> (显示名, 地址)。"""
    m = re.match(r'^(.*?)\s*<([^<>]+)>\s*$', addr or '')
    if m:
        return m.group(1).strip().strip('"'), m.group(2).strip()
    return '', (addr or '').strip()

# ---------------------------------------------------------------- 域名分析

OFFICIAL = {'paypal.com', 'alipay.com', 'icbc.com.cn', 'qq.com', 'weixin.qq.com',
            'wechat.com', 'taobao.com', 'tmall.com', 'jd.com', 'apple.com',
            'microsoft.com', 'google.com', 'amazon.com', 'boc.cn', 'ccb.com',
            'abchina.com', 'cmbchina.com', '10086.cn', 'linkedin.com'}
BRANDS = ['paypal', 'alipay', 'icbc', 'wechat', 'taobao', 'tmall', 'jd',
          'apple', 'microsoft', 'google', 'amazon', 'boc', 'ccb', 'cmb', 'linkedin']
FREE_MAIL = {'gmail.com', 'qq.com', '163.com', '126.com', 'outlook.com',
             'hotmail.com', 'yahoo.com', 'foxmail.com', 'sina.com'}
SHORTENERS = {'bit.ly', 't.cn', 'tinyurl.com', 'goo.gl', 'is.gd', 'ow.ly',
              'rebrand.ly', 'cutt.ly', 'shorturl.at', 'dwz.cn', 'suo.im', 'mrw.so'}
ORG_WORDS = ['银行', '客服', '官方', '安全中心', '支付', '支付宝', '微信', '运营商', '移动', '联通', '电信']


def normalize_domain(d):
    d = d.lower()
    for a, b in (('0', 'o'), ('1', 'l'), ('5', 's'), ('-', '')):
        d = d.replace(a, b)
    return d


def is_official(d):
    d = d.lower()
    return d in OFFICIAL or any(d.endswith('.' + o) for o in OFFICIAL)


def brand_in_domain(d):
    norm = normalize_domain(d)
    for brand in BRANDS:
        if brand in norm and not is_official(d):
            return brand
    return None

# ---------------------------------------------------------------- 特征检测

def detect(headers, body):
    full = '\n'.join(v for v in headers.values()) + '\n' + body
    ev = []

    def add(name, weight, detail):
        ev.append({'name': name, 'weight': weight, 'detail': detail})

    # 1. 回复地址不一致
    from_name, from_addr = split_address(headers.get('from', ''))
    reply = headers.get('reply-to', '')
    if reply:
        _, reply_addr = split_address(reply)
        fd = from_addr.split('@')[-1].lower() if '@' in from_addr else ''
        rd = reply_addr.split('@')[-1].lower() if '@' in reply_addr else ''
        if fd and rd and fd != rd:
            add('reply_mismatch', 15,
                '发件地址 %s 与回复地址 %s 域名不一致' % (from_addr, reply_addr))

    # 2. 发件人冒充
    if from_addr:
        fd = from_addr.split('@')[-1].lower() if '@' in from_addr else ''
        if fd in FREE_MAIL and any(w in from_name for w in ORG_WORDS):
            add('from_spoof', 20,
                '发件人显示名"%s"冒充机构，实际发自免费邮箱 %s' % (from_name, from_addr))
        brand = brand_in_domain(fd) if fd else None
        if brand:
            add('from_spoof', 20,
                '发件域名 %s 含有品牌词"%s"但不是官方域名，疑似伪造' % (fd, brand))

    urls = extract_urls(full)

    # 3. 链接分析
    for u in urls:
        d = domain_of(u)
        if not d:
            continue
        if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', d):
            add('ip_url', 20, '链接使用裸 IP 地址直连：%s' % u[:80])
            continue
        base = d[4:] if d.startswith('www.') else d
        if base in SHORTENERS:
            add('short_url', 10, '使用短链接隐藏真实地址：%s' % u[:80])
            continue
        brand = brand_in_domain(d)
        if brand:
            add('typosquat_url', 25,
                '链接域名 %s 含有品牌词"%s"但非官方域名，疑似仿冒' % (d, brand))

    # 4. 紧迫性话术
    urg = [w for w in ['立即', '马上', '紧急', '最后期限', '24小时', '48小时',
                       '冻结', '停用', '注销', '过期', '逾期', '异常登录',
                       '验证身份', '点击验证', '承担法律责任']
           if w in full]
    if urg:
        add('urgency', 12, '含紧迫性/威胁话术：' + '、'.join(urg[:6]))

    # 5. 索取敏感信息
    cred = [w for w in ['登录密码', '支付密码', '短信验证码', '验证码', '银行卡号',
                        '身份证号', '安全码', 'CVV', '账号密码']
            if w in full]
    if cred and not re.search(r'(请.{0,6}修改密码|定期更换密码)', full):
        add('credential_ask', 25, '索取敏感信息：' + '、'.join(cred[:5]))

    # 6. 危险附件
    atts = re.findall(r'[\w\-.\u4e00-\u9fff]+\.(exe|scr|bat|cmd|js|vbs|vbe|jar|lnk|ps1|msi|docm|xlsm|xltm|zip|rar|7z)\b', full, re.I)
    if atts:
        add('bad_attachment', 25, '含危险类型附件：' + '、'.join(sorted(set(a.lower() for a in atts))[:5]))
    html_atts = re.findall(r'[\w\-.\u4e00-\u9fff]+\.html?\b', full, re.I)
    if html_atts:
        add('html_attachment', 15, '含 HTML 附件（可能内嵌钓鱼登录表单）：' + '、'.join(sorted(set(html_atts))[:3]))

    # 7. 泛化问候语
    if re.search(r'尊敬的(用户|客户|先生|女士)|亲爱的(用户|客户)|Dear (Customer|User|Sir|Madam)', full):
        add('generic_greeting', 5, '使用"尊敬的用户"类泛化问候语，未出现收件人实名')

    # 8. 中奖/利益诱饵
    bait = [w for w in ['恭喜中奖', '中奖', '免单', '高额补贴', '红包雨', '点击领取']
            if w in full]
    if bait:
        add('lottery_bait', 10, '含利益诱饵话术：' + '、'.join(bait[:4]))

    # 9. 财务社工
    fin = [w for w in ['发票', '对账单', '请付款', '尽快转账', '汇款至', '更换收款账号', '新账号']
           if w in full]
    if fin:
        add('invoice_finance', 8, '涉及财务操作话术：' + '、'.join(fin[:4]))

    # 10. 二维码
    if re.search(r'二维码|扫码|扫描.{0,4}二维码', full):
        add('qrcode', 8, '邮件内含二维码，要求扫码操作（绕过链接检测）')

    # 去重：同特征名只保留一条
    seen, uniq = set(), []
    for e in ev:
        if e['name'] not in seen:
            seen.add(e['name'])
            uniq.append(e)
    return uniq

# ---------------------------------------------------------------- 分析主流程

def load_kb(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def analyze(raw, kb, bm25, topk=2):
    headers, body = parse_mail(raw)
    evidences = detect(headers, body)

    # RAG：每条证据用 BM25 检索知识库，拿到解释与引用
    cites, seen_ids = [], set()
    for e in evidences:
        for score, idx in bm25.score(e['detail'])[:topk]:
            kb_id = kb[idx]['id']
            if kb_id not in seen_ids and score > 0:
                seen_ids.add(kb_id)
                cites.append({'id': kb_id, 'title': kb[idx]['title'],
                              'score': round(score, 2)})

    total = min(100, sum(e['weight'] for e in evidences) + (10 if len(evidences) >= 3 else 0))
    if total >= 70:
        verdict = ('高危', '极可能是钓鱼邮件，请勿点击/回复，按处置建议处理')
    elif total >= 35:
        verdict = ('可疑', '存在多项可疑特征，建议通过官方渠道独立核实后再操作')
    else:
        verdict = ('安全', '未检出明显钓鱼特征，仍建议保持基本警惕')

    advice = next(k for k in kb if k['id'] == 'ph-16')
    return {'headers': headers, 'evidences': evidences,
            'cites': cites, 'score': total, 'verdict': verdict,
            'advice': advice['text']}


def report(res, title='分析结果'):
    print('=== %s ===' % title)
    subj = res['headers'].get('subject', '(无主题)')
    frm = res['headers'].get('from', '(未知发件人)')
    print('发件人：%s\n主题：%s\n' % (frm, subj))
    print('风险评分：%d/100 —— %s：%s' % (res['score'], res['verdict'][0], res['verdict'][1]))
    evs = res['evidences']
    print('\n命中特征（%d）：' % len(evs))
    if not evs:
        print('  （无）')
    for i, e in enumerate(evs, 1):
        print('  %d. [%s] %s（权重 %d）' % (i, e['name'], e['detail'], e['weight']))
    print('\n知识库引用：')
    if not res['cites']:
        print('  （无）')
    for i, c in enumerate(res['cites'], 1):
        print('  [%d] %s《%s》(BM25 %s)' % (i, c['id'], c['title'], c['score']))
    if res['verdict'][0] != '安全':
        print('\n处置建议：\n%s\n' % res['advice'])
    else:
        print()

# ---------------------------------------------------------------- 演示样本

DEMO_PHISH = """From: 中国工商银行客服 <service@icbc-secure2026.com>
Reply-To: verify@icbc-verify.top
Subject: 【紧急】您的账户存在异常登录，24小时内未验证将冻结

尊敬的用户：

系统检测到您的网上银行账户今日凌晨在境外 IP（185.22.11.9）有异常登录尝试。
为保障资金安全，请在 24 小时内完成身份验证，否则账户将被暂时冻结。

请点击以下链接立即验证：
http://bit.ly/3xKc9vQ2

验证时需要输入您的登录密码、短信验证码及银行卡号。

中国工商银行 客户服务部
"""

DEMO_NORMAL = """From: 张伟 <zhangwei@company.com>
To: 全体成员
Subject: 本周五下午3点项目评审会通知

各位同事：

本周五（10月10日）下午 3 点在 3 楼会议室召开项目评审会，
请各组提前准备好演示材料。如有时间冲突请提前告知。

会议议程详见内网：https://intranet.company.com/meetings/2026-10-10

谢谢！
张伟
"""


def main():
    ap = argparse.ArgumentParser(description='PhishHunt —— 钓鱼邮件智能分析')
    ap.add_argument('--demo', action='store_true', help='用内置样本演示')
    ap.add_argument('--file', help='待分析的邮件文本文件')
    ap.add_argument('--text', help='直接分析一段邮件文本')
    ap.add_argument('--kb', default=os.path.join(BASE, 'kb.json'), help='知识库路径')
    args = ap.parse_args()

    kb = load_kb(args.kb)
    bm25 = BM25([tokenize(k['title'] + ' ' + k['text']) for k in kb])

    raws = []
    if args.demo:
        raws = [('样本 1：疑似"银行账户验证"邮件', DEMO_PHISH),
                ('样本 2：内部会议通知（正常邮件）', DEMO_NORMAL)]
    elif args.file:
        with open(args.file, encoding='utf-8') as f:
            raws = [('文件分析', f.read())]
    elif args.text:
        raws = [('文本分析', args.text)]
    elif not sys.stdin.isatty():
        raws = [('标准输入', sys.stdin.read())]
    else:
        ap.print_help()
        return

    for title, raw in raws:
        report(analyze(raw, kb, bm25), title)


if __name__ == '__main__':
    main()
