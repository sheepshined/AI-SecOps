# -*- coding: utf-8 -*-
"""xdr_pipeline 单元测试：签名确定性 / 结论与置信度提取 / 加白预评分。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import xdr_pipeline as xp  # noqa: E402


class SignerTests(unittest.TestCase):
    def test_deterministic_signature(self):
        xp._sign_date_now = lambda: '20260928T000000Z'
        s = xp.AkskSigner('AK_TEST', 'SK_TEST')
        url = 'https://xdr.example.com:1443/api/xdr/v1/alerts/list'
        h1 = s.sign('POST', url, headers={'Content-Type': 'application/json'},
                    json_body={'page': 1, 'pageSize': 5})
        h2 = s.sign('POST', url, headers={'Content-Type': 'application/json'},
                    json_body={'page': 1, 'pageSize': 5})
        self.assertEqual(h1['Authorization'], h2['Authorization'])

    def test_body_change_changes_signature(self):
        xp._sign_date_now = lambda: '20260928T000000Z'
        s = xp.AkskSigner('AK_TEST', 'SK_TEST')
        url = 'https://xdr.example.com:1443/api/xdr/v1/alerts/list'
        h1 = s.sign('POST', url, headers={'Content-Type': 'application/json'},
                    json_body={'page': 1, 'pageSize': 5})
        h2 = s.sign('POST', url, headers={'Content-Type': 'application/json'},
                    json_body={'page': 1, 'pageSize': 6})
        self.assertNotEqual(h1['Authorization'], h2['Authorization'])


class ExtractTests(unittest.TestCase):
    def test_extract_ai_result_basic(self):
        self.assertEqual(xp.extract_ai_result('研判结果: 攻击成功'), '攻击成功')
        self.assertEqual(xp.extract_ai_result('研判结果：攻击失败'), '攻击失败')
        self.assertEqual(xp.extract_ai_result('研判结果: 尝试'), '尝试')

    def test_extract_ai_result_markdown(self):
        self.assertEqual(xp.extract_ai_result('**研判结果: 攻击成功**'), '攻击成功')
        self.assertEqual(xp.extract_ai_result('*研判结果：*攻击失败'), '攻击失败')

    def test_extract_ai_result_missing(self):
        self.assertEqual(xp.extract_ai_result('结论未知'), '')

    def test_extract_confidence(self):
        self.assertEqual(xp.extract_confidence('研判结果: 攻击成功\n置信度: 85'), 85)
        self.assertEqual(xp.extract_confidence('置信度：90%'), 90)
        self.assertIsNone(xp.extract_confidence('没有置信度'))
        self.assertIsNone(xp.extract_confidence('置信度: 250'), '越界值应返回 None')

    def test_confidence_in_prompt(self):
        req = xp.build_judgment_request({'name': 'x'}, chat_id='u1')
        self.assertIn('置信度', req['system_prompt'])


class WhitelistPreScoreTests(unittest.TestCase):
    RULES = [
        {'id': 'r1', 'enabled': True, 'src_ip': '10.0.0.1',
         'dst_ip': '', 'src_port': '', 'dst_port': '', 'name_pattern': ''},
        {'id': 'r2', 'enabled': True, 'src_ip': '', 'dst_ip': '192.168.100.200',
         'src_port': '', 'dst_port': '', 'name_pattern': 'SQL注入'},
        {'id': 'r3', 'enabled': False, 'src_ip': '8.8.8.8',
         'dst_ip': '', 'src_port': '', 'dst_port': '', 'name_pattern': ''},
    ]

    def test_src_ip_hit(self):
        item = {'srcIp': ['10.0.0.1'], 'dstIp': ['1.1.1.1'], 'name': '任意告警'}
        rule = xp._matches_whitelist(item, self.RULES)
        self.assertIsNotNone(rule)
        self.assertEqual(rule['id'], 'r1')

    def test_name_pattern_and_dst(self):
        hit = xp._matches_whitelist({'srcIp': ['9.9.9.9'], 'dstIp': ['192.168.100.200'],
                                     'name': '通用SQL注入攻击'}, self.RULES)
        self.assertEqual(hit['id'], 'r2')
        miss = xp._matches_whitelist({'srcIp': ['9.9.9.9'], 'dstIp': ['192.168.100.200'],
                                      'name': '暴力破解'}, self.RULES)
        self.assertIsNone(miss)

    def test_disabled_rule_ignored(self):
        self.assertIsNone(xp._matches_whitelist({'srcIp': ['8.8.8.8']}, self.RULES))

    def test_no_rules(self):
        self.assertIsNone(xp._matches_whitelist({'srcIp': ['1.2.3.4']}, []))
        self.assertIsNone(xp._matches_whitelist({'srcIp': ['1.2.3.4']}, None))


if __name__ == '__main__':
    unittest.main()
