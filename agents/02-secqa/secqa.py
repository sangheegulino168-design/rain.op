#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecQA —— 离线网络安全知识问答小 agent（RAG 方向）

纯 Python 标准库实现，无需 API Key，完全离线可运行。

原理：BM25 检索 + 抽取式回答
  1. 把内置安全知识库（kb.json，24 个主题）做 BM25 建模；
  2. 对用户问题做同样的分词，检索最相关的知识块；
  3. 从最相关的块里抽取与问题最贴合的句子，拼成回答并标注引用。

用法：
    python secqa.py --ask "什么是 SQL 注入？如何防御？"
    python secqa.py --demo                      # 运行 4 个示例问题
    python secqa.py --ask "..." --topk 5        # 取回更多候选
    python secqa.py --ask "..." --kb other.json # 换自己的知识库
"""

import argparse
import json
import math
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KB = os.path.join(HERE, "kb.json")

_CJK_RE = re.compile(r"[\u4e00-\u9fff]")
_WORD_RE = re.compile(r"[A-Za-z0-9_]+")
_SENT_RE = re.compile(r"[^。！？；.!?;\n]+[。！？；.!?;\n]?")


def tokenize(text):
    """中英混合分词：英文/数字按词切，中文按字二元切。"""
    text = text.lower()
    toks = _WORD_RE.findall(text)
    chars = _CJK_RE.findall(text)
    toks.extend(a + b for a, b in zip(chars, chars[1:]))
    return toks


class BM25:
    """极简 BM25，k1=1.5, b=0.75，纯标准库。"""

    def __init__(self, docs, k1=1.5, b=0.75):
        self.k1, self.b = k1, b
        self.n = len(docs)
        self.tf = []
        self.doc_len = []
        df = Counter()
        for d in docs:
            toks = tokenize(d)
            c = Counter(toks)
            self.tf.append(c)
            self.doc_len.append(len(toks))
            for t in c:
                df[t] += 1
        self.avgdl = sum(self.doc_len) / self.n if self.n else 0
        self.idf = {
            t: math.log(1 + (self.n - f + 0.5) / (f + 0.5))
            for t, f in df.items()
        }

    def rank(self, query):
        """返回 [(得分, 文档下标)]，按得分降序。"""
        qtoks = tokenize(query)
        out = []
        for i in range(self.n):
            s = 0.0
            dl = self.doc_len[i] or 1
            for t in qtoks:
                idf = self.idf.get(t)
                if idf is None:
                    continue
                f = self.tf[i].get(t, 0)
                if not f:
                    continue
                denom = f + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
                s += idf * f * (self.k1 + 1) / denom
            out.append((s, i))
        out.sort(key=lambda x: x[0], reverse=True)
        return out


def index_text(chunk):
    """建索引用的文本：标题加权 x2，并混入标签，召回更准。"""
    title = chunk.get("title", "")
    tags = " ".join(chunk.get("tags", []))
    return "%s %s %s %s" % (title, title, tags, chunk["text"])


def split_sentences(text):
    return [s.strip() for s in _SENT_RE.findall(text) if s.strip()]


def sent_score(sent, qtoks):
    """句子与问题的词重叠度（简单计数）。"""
    stoks = set(tokenize(sent))
    return sum(1 for t in qtoks if t in stoks)


def load_kb(path):
    with open(path, encoding="utf-8") as f:
        kb = json.load(f)
    if not isinstance(kb, list) or not kb:
        raise ValueError("知识库格式错误：需要非空 JSON 数组")
    return kb


def build_answer(question, ranked, kb, topk=3, threshold=1.0, rel=0.4):
    """抽取式回答。返回 (回答正文, 引用列表)。

    rel：补充引用的相对得分门限，只保留得分 >= rel * 首位得分的块，
    避免把弱相关的块硬塞进回答。
    """
    hits = [(s, kb[i]) for s, i in ranked[:topk] if s > 0]
    if not hits or hits[0][0] < threshold:
        return ("抱歉，知识库里没有找到与这个问题相关的内容。\n"
                "换个问法试试，例如：什么是 SQL 注入？ / 如何防御 XSS？"), []
    top_score = hits[0][0]
    hits = [(s, c) for s, c in hits if s >= rel * top_score]

    qtoks = set(tokenize(question))
    body, cites = [], []
    for n, (score, chunk) in enumerate(hits, start=1):
        sents = split_sentences(chunk["text"])
        ranked_sents = sorted(sents, key=lambda s: sent_score(s, qtoks),
                              reverse=True)
        cites.append({"n": n, "id": chunk["id"], "title": chunk["title"],
                      "tags": chunk.get("tags", []),
                      "score": round(score, 2)})
        if n == 1:
            # 首位块取最贴合的 2 句，保证回答完整
            keep = ranked_sents[:2]
            body.append("".join(keep) + " [%d]" % n)
        elif ranked_sents and sent_score(ranked_sents[0], qtoks) > 0:
            body.append("补充：" + ranked_sents[0] + " [%d]" % n)
    return "\n".join(body), cites


def show(question, answer, cites):
    print("问题：%s\n" % question)
    print("回答：")
    print(answer)
    if cites:
        print("\n引用：")
        for c in cites:
            tags = "/".join(c["tags"]) if c["tags"] else "-"
            print("  [%d] %s《%s》  tags: %s  (BM25 得分 %s)"
                  % (c["n"], c["id"], c["title"], tags, c["score"]))


def main(argv=None):
    ap = argparse.ArgumentParser(description="SecQA：离线网络安全知识问答（BM25+RAG）")
    ap.add_argument("--ask", help="要问的问题")
    ap.add_argument("--demo", action="store_true", help="运行 4 个示例问题")
    ap.add_argument("--topk", type=int, default=3, help="取回知识块数量（默认 3）")
    ap.add_argument("--kb", default=DEFAULT_KB, help="知识库 JSON 路径")
    args = ap.parse_args(argv)

    try:
        kb = load_kb(args.kb)
    except (OSError, ValueError) as e:
        print("知识库加载失败：%s" % e, file=sys.stderr)
        return 1

    model = BM25([index_text(c) for c in kb])

    if args.demo:
        questions = [
            "什么是 SQL 注入？要怎么防御？",
            "XSS 有哪几种类型？如何防范？",
            "服务器中了勒索软件该怎么办？",
            "内网横向移动常用什么手法？怎么防？",
        ]
        print("=" * 68)
        print("SecQA 演示模式：知识库 %d 条，全程离线 BM25 检索，无网络请求"
              % len(kb))
        print("=" * 68)
        for i, q in enumerate(questions, 1):
            print("\n--- 示例 %d/%d " % (i, len(questions)) + "-" * 54)
            ranked = model.rank(q)
            answer, cites = build_answer(q, ranked, kb, topk=args.topk)
            show(q, answer, cites)
        print("\n" + "=" * 68)
        print("演示结束。用 --ask \"你的问题\" 自由提问。")
        return 0

    if args.ask:
        ranked = model.rank(args.ask)
        answer, cites = build_answer(args.ask, ranked, kb, topk=args.topk)
        show(args.ask, answer, cites)
        return 0

    ap.print_help()
    print("\n示例：python secqa.py --demo")
    return 0


if __name__ == "__main__":
    sys.exit(main())
