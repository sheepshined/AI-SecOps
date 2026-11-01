# -*- coding: utf-8 -*-
"""Flask 路由冒烟测试（需要本地 MySQL；不触发 XDR/LLM 真实调用）。

导入 app 前必须设置 DISABLE_XDR_SCHEDULER=1，否则 app.py 模块级
start_xdr_scheduler() 会在导入瞬间发起一次 50 条的真实拉取+研判。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ['DISABLE_XDR_SCHEDULER'] = '1'
os.environ.setdefault('DB_USER', 'qwet')
os.environ.setdefault('DB_PASSWORD', '123456')


def _db_reachable() -> bool:
    try:
        import db
        db.get_max_update_time()
        return True
    except Exception:
        return False


@unittest.skipUnless(_db_reachable(), '本地 MySQL 不可用，跳过路由测试')
class AppRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as app_module
        cls.app = app_module.app
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

    def test_stats_shape(self):
        r = self.client.get('/api/stats')
        self.assertEqual(r.status_code, 200)
        body = r.json
        for k in ('total', 'high', 'critical', 'open', 'false_positive', 'blocked'):
            self.assertIsInstance(body[k], int)
            self.assertGreaterEqual(body[k], 0)

    def test_alarms_shape(self):
        r = self.client.get('/api/alarms')
        self.assertEqual(r.status_code, 200)
        alarms = r.json
        self.assertIsInstance(alarms, list)
        for a in alarms[:3]:
            self.assertIn('id', a)
            self.assertIn('aiJudged', a)
            self.assertIn('severity', a)

    def test_block_internal_ip_rejected(self):
        before = len(self.client.get('/api/blocked').json)
        r = self.client.post('/api/blocked', json={'ip': '192.168.55.66', 'reason': '测试'})
        self.assertEqual(r.status_code, 400)
        self.assertIn('拒绝封禁', r.json.get('error', ''))
        after = len(self.client.get('/api/blocked').json)
        self.assertEqual(before, after, '内网 IP 不应进入封禁列表')

    def test_block_invalid_ip_still_rejected_by_param(self):
        r = self.client.post('/api/blocked', json={'reason': '无 ip'})
        self.assertEqual(r.status_code, 400)

    def test_whitelist_list(self):
        r = self.client.get('/api/whitelist')
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json, list)

    def test_alarm_status_validation(self):
        r = self.client.post('/api/alarms/NO-SUCH-ID/status', json={'status': 'closed'})
        self.assertEqual(r.status_code, 404)
        r = self.client.post('/api/alarms/NO-SUCH-ID/status', json={'status': 'bogus'})
        self.assertEqual(r.status_code, 400)


if __name__ == '__main__':
    unittest.main()
