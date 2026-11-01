import json
import os
from datetime import datetime, timezone
from typing import Any

import uuid

import mysql.connector

DB_HOST = os.environ.get('DB_HOST', '127.0.0.1')
DB_PORT = int(os.environ.get('DB_PORT', '3306'))
DB_USER = os.environ.get('DB_USER', 'root')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'itopsclaw-root')
DB_NAME = os.environ.get('DB_NAME', 'security_dashboard')


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def get_conn(database=None):
    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=database,
        charset='utf8mb4',
        use_unicode=True,
    )


def init_db():
    """初始化数据库与告警表"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS {DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
    cur.close()
    conn.close()

    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id VARCHAR(128) PRIMARY KEY,
            uuid VARCHAR(128),
            name VARCHAR(512),
            severity VARCHAR(32),
            severity_score INT,
            type VARCHAR(512),
            src_ip VARCHAR(64),
            target_ip VARCHAR(64),
            status VARCHAR(32) DEFAULT 'open',
            attck VARCHAR(128),
            ai_judged TINYINT(1) DEFAULT 0,
            verdict LONGTEXT,
            model_response LONGTEXT,
            proof_json LONGTEXT,
            request_json LONGTEXT,
            xdr_raw LONGTEXT,
            xdr_device VARCHAR(256),
            xdr_user VARCHAR(256),
            xdr_process VARCHAR(512),
            xdr_parent_process VARCHAR(512),
            xdr_command_line LONGTEXT,
            xdr_file_path LONGTEXT,
            xdr_network_connection VARCHAR(256),
            description LONGTEXT,
            attack_url LONGTEXT,
            response_status VARCHAR(16),
            first_time DATETIME,
            last_time DATETIME,
            update_time DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_status (status),
            INDEX idx_severity (severity),
            INDEX idx_ai_judged (ai_judged),
            INDEX idx_src_ip (src_ip),
            INDEX idx_update_time (update_time)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)
    for col, defn in [
        ('description', 'LONGTEXT'),
        ('attack_url', 'LONGTEXT'),
        ('response_status', 'VARCHAR(16)'),
        ('request_json', 'LONGTEXT'),
        ('ai_result', 'VARCHAR(32)'),
        ('ai_confidence', 'INT'),
    ]:
        try:
            # MySQL 不支持 ADD COLUMN IF NOT EXISTS（MariaDB 语法）；列已存在时抛 1060 被下方 except 吞掉
            cur.execute(f"ALTER TABLE alerts ADD COLUMN {col} {defn}")
        except Exception as e:
            print('[db] alter column warning:', e)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip VARCHAR(64) PRIMARY KEY,
            reason VARCHAR(512),
            time DATETIME,
            alarm VARCHAR(128),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS whitelist_rules (
            id VARCHAR(64) PRIMARY KEY,
            src_ip VARCHAR(64),
            dst_ip VARCHAR(64),
            src_port VARCHAR(16),
            dst_port VARCHAR(16),
            name_pattern VARCHAR(512),
            reason VARCHAR(512),
            enabled TINYINT(1) DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_src_ip (src_ip),
            INDEX idx_dst_ip (dst_ip),
            INDEX idx_name_pattern (name_pattern),
            INDEX idx_enabled (enabled)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """)
    conn.commit()
    cur.close()
    conn.close()



def map_severity(score: int | None) -> str:
    score = int(score or 0)
    if score >= 80:
        return 'critical'
    if score >= 60:
        return 'high'
    if score >= 30:
        return 'medium'
    return 'low'


def _to_dt(ts: Any) -> datetime | None:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc)
    except Exception:
        return None


def _safe_json(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return None


def record_from_xdr_result(result: dict) -> dict:
    """把 xdr_pipeline 单条结果转换成可写入 alerts 表的字典"""
    item = result.get('alert_item', {}) or {}
    src_list = item.get('srcIp') or []
    dst_list = item.get('dstIp') or []
    if isinstance(src_list, list) and src_list:
        src_ip = src_list[0]
    else:
        src_ip = src_list or ''
    if isinstance(dst_list, list) and dst_list:
        target_ip = dst_list[0]
    else:
        target_ip = dst_list or ''

    attck_list = item.get('attckTechnique') or []
    attck = ','.join(attck_list) if isinstance(attck_list, list) else str(attck_list)

    dev_source = item.get('devSourceName') or []
    device = dev_source[0] if isinstance(dev_source, list) and dev_source else item.get('hostIp') or ''
    engines = item.get('engineName') or []
    process = engines[0] if isinstance(engines, list) and engines else item.get('pname') or ''
    src_port_list = item.get('srcPort') or []
    dst_port_list = item.get('dstPort') or []
    src_port = src_port_list[0] if isinstance(src_port_list, list) and src_port_list else ''
    dst_port = dst_port_list[0] if isinstance(dst_port_list, list) and dst_port_list else ''
    network_connection = f"{src_ip}:{src_port} -> {target_ip}:{dst_port}" if (src_ip or target_ip) else ''

    return {
        'id': item.get('uuId') or result.get('uuid'),
        'uuid': item.get('uuId') or result.get('uuid'),
        'name': item.get('name', ''),
        'severity': map_severity(item.get('severity')),
        'severity_score': int(item.get('severity') or 0),
        'type': item.get('threatTypeDesc') or item.get('threatSubTypeDesc') or item.get('name', ''),
        'src_ip': src_ip,
        'target_ip': target_ip,
        'status': 'open',
        'attck': attck,
        'ai_judged': 1,
        'verdict': result.get('verdict') or '',
        'model_response': result.get('model_response') or '',
        'ai_result': result.get('ai_result') or '',
        'ai_confidence': result.get('ai_confidence'),
        'request_json': _safe_json(result.get('request')),
        'proof_json': _safe_json(result.get('proof')),
        'xdr_raw': _safe_json(item),
        'xdr_device': device,
        'xdr_user': 'N/A',
        'xdr_process': process,
        'xdr_parent_process': '',
        'xdr_command_line': item.get('pname') or '',
        'xdr_file_path': '',
        'xdr_network_connection': network_connection,
        'description': item.get('description', ''),
        'attack_url': _safe_json(item.get('url')),
        'response_status': str(item.get('respStatus', '')) if item.get('respStatus') is not None else '',
        'first_time': _to_dt(item.get('firstTime')),
        'last_time': _to_dt(item.get('lastTime')),
        'update_time': _to_dt(item.get('updateTime')),
    }


def record_from_sample(alarm: dict) -> dict:
    """把项目原有的示例告警转换成 alerts 表记录"""
    xdr = alarm.get('xdr', {}) or {}
    return {
        'id': alarm['id'],
        'uuid': alarm['id'],
        'name': alarm.get('type', ''),
        'severity': alarm.get('severity', 'low'),
        'severity_score': 0,
        'type': alarm.get('type', ''),
        'src_ip': alarm.get('src', ''),
        'target_ip': alarm.get('target', ''),
        'status': alarm.get('status', 'open'),
        'attck': alarm.get('attck', ''),
        'ai_judged': 1 if alarm.get('aiJudged') else 0,
        'verdict': alarm.get('verdict', ''),
        'model_response': alarm.get('model_response', ''),
        'ai_result': alarm.get('aiResult', alarm.get('ai_result', '')),
        'request_json': _safe_json(alarm.get('request')),
        'proof_json': None,
        'xdr_raw': _safe_json(xdr),
        'xdr_device': xdr.get('device', ''),
        'xdr_user': xdr.get('user', ''),
        'xdr_process': xdr.get('process', ''),
        'xdr_parent_process': xdr.get('parentProcess', ''),
        'xdr_command_line': xdr.get('commandLine', ''),
        'xdr_file_path': xdr.get('filePath', ''),
        'xdr_network_connection': xdr.get('networkConnection', ''),
        'description': alarm.get('description', ''),
        'attack_url': _safe_json(alarm.get('attack_url')),
        'response_status': alarm.get('response_status', ''),
        'first_time': None,
        'last_time': None,
        'update_time': None,
    }


def upsert_alarm(record: dict):
    """插入或更新单条告警"""
    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    fields = [
        'id', 'uuid', 'name', 'severity', 'severity_score', 'type',
        'src_ip', 'target_ip', 'status', 'attck', 'ai_judged',
        'verdict', 'model_response', 'ai_result', 'ai_confidence',
        'proof_json', 'request_json', 'xdr_raw',
        'xdr_device', 'xdr_user', 'xdr_process', 'xdr_parent_process',
        'xdr_command_line', 'xdr_file_path', 'xdr_network_connection',
        'description', 'attack_url', 'response_status',
        'first_time', 'last_time', 'update_time',
    ]
    placeholders = ', '.join(['%s'] * len(fields))
    updates = ', '.join([f"{f}=VALUES({f})" for f in fields if f != 'id'])
    sql = f"INSERT INTO alerts ({', '.join(fields)}) VALUES ({placeholders}) ON DUPLICATE KEY UPDATE {updates}"
    values = [record.get(f) for f in fields]
    cur.execute(sql, values)
    conn.commit()
    cur.close()
    conn.close()


def seed_sample_alarms(alarms: list):
    """如果表为空，把示例告警写入数据库"""
    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM alerts")
    count = cur.fetchone()[0]
    cur.close()
    conn.close()
    if count:
        return
    for alarm in alarms:
        upsert_alarm(record_from_sample(alarm))



def seed_sample_whitelist_rules():
    """如果缺少示例加白规则，则自动补齐。示例覆盖源 IP、目标 IP、名称模式等常见场景。"""
    sample_rules = [
        {
            'src_ip': '192.168.227.1',
            'reason': '示例：信任此源 IP 的内网测试流量',
            'enabled': True,
        },
        {
            'name_pattern': '通用SQL注入攻击',
            'reason': '示例：已知业务扫描器产生的误报',
            'enabled': True,
        },
        {
            'dst_ip': '192.168.10.45',
            'reason': '示例：内部蜜罐/靶机地址，告警无需处置',
            'enabled': True,
        },
        {
            'name_pattern': '终端恶意程序感染',
            'reason': '示例：测试环境终端，已确认无毒',
            'enabled': True,
        },
    ]
    existing = load_whitelist_rules()
    existing_signatures = {
        (r.get('src_ip') or '', r.get('dst_ip') or '', r.get('src_port') or '', r.get('dst_port') or '', r.get('name_pattern') or '')
        for r in existing
    }
    for rule in sample_rules:
        sig = (
            rule.get('src_ip') or '',
            rule.get('dst_ip') or '',
            rule.get('src_port') or '',
            rule.get('dst_port') or '',
            rule.get('name_pattern') or '',
        )
        if sig not in existing_signatures:
            add_whitelist_rule(rule)



def load_whitelist_rules() -> list:
    """加载所有告警加白规则"""
    conn = get_conn(DB_NAME)
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM whitelist_rules ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    for r in rows:
        for k in ['created_at', 'updated_at']:
            if isinstance(r.get(k), datetime):
                r[k] = r[k].strftime('%Y-%m-%d %H:%M:%S')
        r['enabled'] = bool(r.get('enabled', 1))
    return rows


def add_whitelist_rule(rule: dict) -> dict:
    """新增加白规则并返回规则对象"""
    rule_id = rule.get('id') or str(uuid.uuid4())
    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO whitelist_rules (id, src_ip, dst_ip, src_port, dst_port, name_pattern, reason, enabled)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            rule_id,
            rule.get('src_ip', '') or '',
            rule.get('dst_ip', '') or '',
            rule.get('src_port', '') or '',
            rule.get('dst_port', '') or '',
            rule.get('name_pattern', '') or '',
            rule.get('reason', '') or '',
            1 if rule.get('enabled', True) else 0,
        )
    )
    conn.commit()
    cur.close()
    conn.close()
    rule = dict(rule)
    rule['id'] = rule_id
    rule['enabled'] = bool(rule.get('enabled', True))
    return rule


def update_whitelist_rule(rule_id: str, updates: dict):
    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    fields = []
    values = []
    for k in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'name_pattern', 'reason', 'enabled']:
        if k in updates:
            fields.append(f"{k} = %s")
            if k == 'enabled':
                values.append(1 if updates[k] else 0)
            else:
                values.append(updates[k] or '')
    if not fields:
        cur.close()
        conn.close()
        return
    values.append(rule_id)
    cur.execute(f"UPDATE whitelist_rules SET {', '.join(fields)} WHERE id = %s", values)
    conn.commit()
    cur.close()
    conn.close()


def delete_whitelist_rule(rule_id: str):
    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    cur.execute("DELETE FROM whitelist_rules WHERE id = %s", (rule_id,))
    conn.commit()
    cur.close()
    conn.close()


def load_alarms(status: str | None = None, severity: str | None = None, q: str | None = None) -> list:
    """从数据库加载告警并转换为前端格式"""
    conn = get_conn(DB_NAME)
    cur = conn.cursor(dictionary=True)
    where = []
    params = []
    if status:
        where.append("status = %s")
        params.append(status)
    if severity:
        where.append("severity = %s")
        params.append(severity)
    if q:
        like = f"%{q}%"
        where.append("(id LIKE %s OR name LIKE %s OR type LIKE %s OR src_ip LIKE %s OR target_ip LIKE %s OR attck LIKE %s)")
        params.extend([like, like, like, like, like, like])
    sql = "SELECT * FROM alerts"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY update_time DESC, created_at DESC"
    cur.execute(sql, params)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [row_to_frontend(r) for r in rows]


def row_to_frontend(row: dict) -> dict:
    """把数据库行转换为前端期望的字典"""
    d = dict(row)
    for k in d:
        if isinstance(d[k], datetime):
            d[k] = d[k].strftime('%Y-%m-%d %H:%M:%S')
    d['src'] = d.pop('src_ip', '') or ''
    d['target'] = d.pop('target_ip', '') or ''
    d['aiJudged'] = bool(d.pop('ai_judged', 0))
    d['verdict'] = d.get('verdict') or ''
    d['model_response'] = d.get('model_response') or ''
    d['ai_result'] = d.get('ai_result') or ''
    request_json = d.pop('request_json', None)
    d['request'] = json.loads(request_json) if request_json else None
    proof_json = d.pop('proof_json', None)
    d['proof'] = json.loads(proof_json) if proof_json else None
    xdr_raw = d.pop('xdr_raw', None)
    if xdr_raw:
        try:
            d['xdr_raw'] = json.loads(xdr_raw)
        except Exception:
            d['xdr_raw'] = None
    # 组装前端需要的 xdr 对象
    d['xdr'] = {}
    key_map = {
        'xdr_device': 'device',
        'xdr_user': 'user',
        'xdr_process': 'process',
        'xdr_parent_process': 'parentProcess',
        'xdr_command_line': 'commandLine',
        'xdr_file_path': 'filePath',
        'xdr_network_connection': 'networkConnection',
    }
    for db_key, js_key in key_map.items():
        val = d.pop(db_key, '')
        if val:
            d['xdr'][js_key] = val
    d['time'] = d.get('update_time') or d.get('last_time') or d.get('created_at') or _now()
    d['attck'] = d.get('attck') or ''
    d['description'] = d.get('description') or ''
    attack_url_json = d.pop('attack_url', None)
    d['attack_url'] = json.loads(attack_url_json) if attack_url_json else []
    d['response_status'] = d.get('response_status') or ''
    # name 优先使用 XDR 原始告警名，缺失则用 type 兜底
    d['name'] = d.get('name') or d.get('type', '')
    return d


def get_alarm(alarm_id: str) -> dict | None:
    alarms = load_alarms()
    for a in alarms:
        if a['id'] == alarm_id:
            return a
    return None


def update_alarm_status(alarm_id: str, status: str):
    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    cur.execute("UPDATE alerts SET status = %s WHERE id = %s", (status, alarm_id))
    conn.commit()
    cur.close()
    conn.close()


def insert_xdr_results(summary: dict):
    """把 run_pipeline 返回的汇总结果安全地 upsert 到 alerts 表，不删除已有记录"""
    results = summary.get("results") or []
    if not results:
        return
    records = [record_from_xdr_result(r) for r in results]
    ids = [r["id"] for r in records if r.get("id")]
    if not ids:
        return

    # 保留已有非空研判结论和已加白状态，避免 XDR 重新导入后覆盖用户决策
    placeholders = ",".join(["%s"] * len(ids))
    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT id, verdict, model_response, status FROM alerts WHERE id IN (%s)" % placeholders, tuple(ids))
    existing_rows = {}
    for row in cur.fetchall():
        _id, _verdict, _model, _status = row
        existing_rows[_id] = {"verdict": _verdict, "model_response": _model or "", "status": _status}
    cur.close()
    conn.close()

    for rec in records:
        _id = rec.get("id")
        existing = existing_rows.get(_id) or {}
        if _id and not rec.get("verdict") and existing.get("verdict"):
            rec["verdict"] = existing["verdict"]
            rec["model_response"] = existing["model_response"] or rec.get("model_response", "")
        # 保留用户已加白的告警状态，防止 XDR 重新导入后回退
        if existing.get("status") == "false_positive":
            rec["status"] = "false_positive"
        upsert_alarm(rec)


def load_blocked() -> list:
    conn = get_conn(DB_NAME)
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM blocked_ips ORDER BY created_at DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    for r in rows:
        if isinstance(r.get('time'), datetime):
            r['time'] = r['time'].strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(r.get('created_at'), datetime):
            r['created_at'] = r['created_at'].strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(r.get('updated_at'), datetime):
            r['updated_at'] = r['updated_at'].strftime('%Y-%m-%d %H:%M:%S')
    return rows


def upsert_blocked(record: dict):
    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO blocked_ips (ip, reason, time, alarm)
        VALUES (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE reason=VALUES(reason), time=VALUES(time), alarm=VALUES(alarm)
    """, (record['ip'], record.get('reason', ''), record.get('time'), record.get('alarm', '')))
    conn.commit()
    cur.close()
    conn.close()


def delete_blocked(ip: str):
    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    cur.execute("DELETE FROM blocked_ips WHERE ip = %s", (ip,))
    conn.commit()
    cur.close()
    conn.close()


def get_max_update_time() -> datetime | None:
    """获取 alerts 表中最大的 update_time（UTC），用于增量拉取"""
    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT MAX(update_time) FROM alerts")
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row[0] if row and row[0] else None


def get_judged_uuids() -> set:
    """返回已 AI 研判的告警 uuid 集合"""
    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT id FROM alerts WHERE ai_judged = 1")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return set(r[0] for r in rows)


def delete_sample_alarms():
    """删除示例告警（ID 以 ALT- 开头），仅保留真实 XDR 告警"""
    conn = get_conn(DB_NAME)
    cur = conn.cursor()
    cur.execute("DELETE FROM alerts WHERE id LIKE BINARY 'ALT-%'")
    conn.commit()
    deleted = cur.rowcount
    cur.close()
    conn.close()
    return deleted
