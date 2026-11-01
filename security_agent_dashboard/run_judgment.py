import json
import os
import sys
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(__file__))
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

import db
from xdr_pipeline import run_pipeline

def main():
    # 重置研判状态，让所有告警都重新研判
    conn = db.get_conn(db.DB_NAME)
    cur = conn.cursor()
    cur.execute("UPDATE alerts SET ai_judged=0, verdict='', model_response='', request_json=NULL")
    conn.commit()
    conn.close()
    print('已重置所有告警的研判状态')

    xdr_cfg_path = os.path.join(os.path.dirname(__file__), 'data', 'xdr_config.json')
    with open(xdr_cfg_path, 'r', encoding='utf-8') as f:
        xdr_raw = json.load(f)
    xdr_cfg = {
        'xdr_base_url': xdr_raw.get('xdr_base_url'),
        'xdr_auth_code': xdr_raw.get('xdr_auth_code') or '',
        'xdr_access_key': xdr_raw.get('xdr_access_key'),
        'xdr_secret_key': xdr_raw.get('xdr_secret_key'),
        'request_timeout': xdr_raw.get('request_timeout', 60),
    }
    configs = json.load(open(os.path.join(os.path.dirname(__file__), 'data', 'assistant_config.json'), encoding='utf-8'))
    active = next((c for c in configs if c.get('active')), None)
    if not active:
        print('没有激活的模型配置')
        return

    start_time = int((datetime.now(timezone.utc) - timedelta(days=7)).timestamp())
    summary = run_pipeline(
        xdr_cfg,
        active,
        count=50,
        list_alerts_kwargs={'order_by': 'updateTime', 'order': 'desc', 'start_time': start_time},
        skip_uuids=set(),
    )
    print(json.dumps({
        'total_fetched': summary.get('total_fetched'),
        'total_success': summary.get('total_success'),
        'total_failed': summary.get('total_failed'),
    }, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
