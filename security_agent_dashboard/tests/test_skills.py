# -*- coding: utf-8 -*-
"""skills 单元测试：处置硬校验 / 技能识别。"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.pop('ALLOW_INTERNAL_BLOCK', None)

from skills import is_protected_ip, detect_skill  # noqa: E402


class ProtectedIpTests(unittest.TestCase):
    def test_private_blocked(self):
        for ip in ['192.168.1.1', '10.0.0.5', '172.16.0.9', '172.31.255.1']:
            self.assertTrue(is_protected_ip(ip), ip)

    def test_loopback_and_link_local(self):
        self.assertTrue(is_protected_ip('127.0.0.1'))
        self.assertTrue(is_protected_ip('169.254.1.1'))

    def test_public_allowed(self):
        for ip in ['8.8.8.8', '185.220.101.42', '203.78.5.11']:
            self.assertFalse(is_protected_ip(ip), ip)

    def test_invalid_ip_not_protected(self):
        self.assertFalse(is_protected_ip('not-an-ip'))
        self.assertFalse(is_protected_ip(''))
        self.assertFalse(is_protected_ip(None))

    def test_override_env(self):
        os.environ['ALLOW_INTERNAL_BLOCK'] = '1'
        try:
            self.assertFalse(is_protected_ip('192.168.1.1'))
        finally:
            os.environ.pop('ALLOW_INTERNAL_BLOCK', None)


class DetectSkillTests(unittest.TestCase):
    def test_ip_extraction(self):
        result = detect_skill('封禁 IP 1.2.3.4')
        self.assertTrue(result['matched'])
        self.assertEqual(result['params'].get('ip'), '1.2.3.4')

    def test_no_match(self):
        self.assertFalse(detect_skill('今天天气怎么样')['matched'])


if __name__ == '__main__':
    unittest.main()
