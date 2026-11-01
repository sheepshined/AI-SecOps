# -*- coding: utf-8 -*-
"""knowledge_context 单元测试：切词 / 加权 / 去重 / 输出契约。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from knowledge_context import (  # noqa: E402
    _tokenize, _extract_keywords, _score, _load_vuln_items,
    build_knowledge_context,
)


class TokenizeTests(unittest.TestCase):
    def test_long_chinese_split_into_bigrams(self):
        tokens = _tokenize('检测到针对终端发起的恶意代码通信行为')
        # 整段 20 字不应再作为单个 token 出现
        self.assertNotIn('检测到针对终端发起的恶意代码通信行为', tokens)
        # 全部为 2 字 bigram
        zh = [t for t in tokens if all('\u4e00' <= c <= '\u9fa5' for c in t)]
        self.assertTrue(zh)
        for t in zh:
            self.assertLessEqual(len(t), 4, f'中文 token 过长: {t}')

    def test_short_chinese_kept_whole(self):
        tokens = _tokenize('暴力破解')
        self.assertIn('暴力破解', tokens)

    def test_stopword_bigrams_filtered(self):
        # "检测到" 是停用词，bigram 切分后不应出现
        tokens = _tokenize('检测到恶意代码')
        self.assertNotIn('检测到', tokens)

    def test_english_and_ip_kept(self):
        tokens = _tokenize('apache2 192.168.1.1 SQL injection')
        self.assertIn('192.168.1.1', tokens)
        self.assertIn('apache2', tokens)


class ScoreTests(unittest.TestCase):
    def test_strong_feature_weighted_higher(self):
        items = [
            {'id': 'normal', 'text': 'brute force attack against service'},
            {'id': 'strong', 'text': 'brute force from 10.0.0.1 against service'},
        ]
        kws = ['brute', 'force', '10.0.0.1']
        scored = _score(items, kws, lambda x: x['text'])
        top_id = scored[0][1]['id']
        self.assertEqual(top_id, 'strong')
        self.assertEqual(scored[0][0], scored[1][0] + 3)

    def test_zero_hits_excluded(self):
        scored = _score([{'text': 'nothing relevant'}], ['qwer'], lambda x: x['text'])
        self.assertEqual(scored, [])


class VulnDedupTests(unittest.TestCase):
    def test_no_duplicate_cve_ids(self):
        kc_cache_clear = __import__('knowledge_context').clear_cache
        kc_cache_clear()
        items = _load_vuln_items()
        cves = [(v.get('cve_id') or '').strip().upper() for v in items]
        non_empty = [c for c in cves if c]
        self.assertEqual(len(non_empty), len(set(non_empty)),
                         '漏洞库条目存在重复 CVE')


class ContractTests(unittest.TestCase):
    def test_build_knowledge_context_contract(self):
        ctx = build_knowledge_context({
            'name': 'SQL注入攻击', 'attck': 'T1190',
            'description': '检测到针对 Web 应用的 SQL 注入尝试',
            'src_ip': '10.67.201.61',
        })
        for key in ('text', 'vuln_matches', 'library_matches', 'keywords'):
            self.assertIn(key, ctx)
        self.assertLessEqual(len(ctx['text']), 2500)

    def test_keywords_capped(self):
        big = {f'word{i}': i for i in range(200)}
        big['description'] = ' '.join(f'keyword{i}' for i in range(200))
        kws = _extract_keywords(big)
        self.assertLessEqual(len(kws), 60)


if __name__ == '__main__':
    unittest.main()
