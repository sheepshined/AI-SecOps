import json
import os
import re
import ipaddress
import db
import csv
import vuln_stats_skill

CONFIG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
SKILLS_FILE = os.path.join(CONFIG_DIR, 'skills_config.json')
IDENTITY_DB_FILE = os.path.join(CONFIG_DIR, 'identity_db.json')

IP_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')


def is_protected_ip(ip):
    """处置硬校验：判断 IP 是否属于受保护地址（内网/回环/链路本地/保留段）。

    封禁动作执行前必须经过本检查，防止把内网用户/网关/本机拉黑导致断网。
    设置环境变量 ALLOW_INTERNAL_BLOCK=1 可解除限制（演示内网靶机场景用）。
    """
    if not ip:
        return False
    if os.environ.get('ALLOW_INTERNAL_BLOCK', '') == '1':
        return False
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False  # 非 IP 交给上层参数校验处理
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def _default_skills():
    return [
        {
            "id": "ip_block",
            "name": "IP 封禁",
            "description": "封禁指定 IP 地址，可在聊天中直接触发。",
            "enabled": True,
            "trigger_keywords": ["封禁", "拉黑", "block", "阻断"],
            "handler": "block_ip",
            "params": [
                {"name": "ip", "type": "ip", "required": True, "description": "要封禁的 IP 地址"},
                {"name": "reason", "type": "string", "required": False, "description": "封禁原因"}
            ],
            "icon": "shield-ban"
        },
        {
            "id": "ip_identity",
            "name": "IP 查询姓名学号",
            "description": "根据 IP 查询对应用户的姓名、学号/工号等身份信息。",
            "enabled": True,
            "trigger_keywords": ["查询", "姓名", "学号", "身份", "工号"],
            "handler": "query_identity",
            "params": [
                {"name": "ip", "type": "ip", "required": True, "description": "要查询的 IP 地址"}
            ],
            "icon": "search"
        },
        {
            "id": "today_attacked_students",
            "name": "今日受攻击学生",
            "description": "查询今天哪些学生（IP）受到了攻击，结合 IP-ID 映射表返回姓名、学号、院系。",
            "enabled": True,
            "trigger_keywords": ["今天哪个学生受到了攻击", "今日受攻击学生", "今天受攻击", "受攻击学生", "今天被攻击", "今天哪些学生受到攻击", "受到了攻击", "受到了", "最近一周", "本周", "最近7天", "最近七天", "7天", "一周", "最近三天", "3天", "同学"],
            "handler": "today_attacked_students",
            "params": [],
            "icon": "alert-triangle"
        },
        {
            "id": "vuln_daily_stats",
            "name": "漏洞每日统计",
            "description": "回答每天拉取了多少漏洞，以及当前告警 AI 研判是否匹配到这些漏洞。",
            "enabled": True,
            "trigger_keywords": ["漏洞", "拉取", "CVE", "匹配", "研判", "每天", "统计", "获取"],
            "handler": "vuln_daily_stats",
            "params": [],
            "icon": "shield-alert"
        },
    ]


def _default_identity_db():
    return {
        "10.67.201.61": {"name": "张三", "student_id": "2021001001", "department": "计算机学院"},
        "10.0.1.52": {"name": "李四", "student_id": "2021001002", "department": "软件学院"},
        "203.78.5.11": {"name": "王五", "student_id": "2021001003", "department": "网络安全学院"},
        "185.220.101.42": {"name": "赵六", "student_id": "2021001004", "department": "电子工程学院"},
        "192.168.12.88": {"name": "孙七", "student_id": "2021001005", "department": "信息管理学院"},
        "10.0.4.21": {"name": "周八", "student_id": "2021001006", "department": "人工智能学院"},
        "10.0.2.19": {"name": "吴九", "student_id": "2021001007", "department": "网络空间安全学院"},
        "117.28.3.91": {"name": "郑十", "student_id": "2021001008", "department": "数据科学学院"}
    }


def _ensure_config_dir():
    if not os.path.isdir(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)


def load_skills():
    _ensure_config_dir()
    defaults = _default_skills()
    if not os.path.exists(SKILLS_FILE):
        with open(SKILLS_FILE, 'w', encoding='utf-8') as f:
            json.dump(defaults, f, ensure_ascii=False, indent=2)
    try:
        with open(SKILLS_FILE, 'r', encoding='utf-8') as f:
            existing = json.load(f)
    except Exception:
        existing = []
    existing_ids = {s.get("id") for s in existing}
    added = False
    for s in defaults:
        if s.get("id") not in existing_ids:
            existing.append(s)
            added = True
    if added:
        save_skills(existing)
    return existing


def save_skills(skills):
    _ensure_config_dir()
    with open(SKILLS_FILE, 'w', encoding='utf-8') as f:
        json.dump(skills, f, ensure_ascii=False, indent=2)


def load_identity_db():
    _ensure_config_dir()
    if not os.path.exists(IDENTITY_DB_FILE):
        with open(IDENTITY_DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(_default_identity_db(), f, ensure_ascii=False, indent=2)
    try:
        with open(IDENTITY_DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return _default_identity_db()


def save_identity_db(identity):
    """保存身份映射表"""
    _ensure_config_dir()
    with open(IDENTITY_DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(identity, f, ensure_ascii=False, indent=2)


def import_identity_from_csv(path):
    """从 CSV 导入 IP-身份信息，支持中英文表头"""
    rows = []
    key_map = {
        'ip': ['ip', 'IP', 'ip地址', 'IP地址', 'ip_addr', 'ip_address', '源ip', '目标ip', 'src_ip', 'dst_ip', 'host_ip'],
        'name': ['name', '姓名', '名字', 'user', '用户名'],
        'student_id': ['student_id', '学号', '工号', 'student_no', 'id'],
        'department': ['department', '院系', '部门', '学院', '班级', 'class']
    }
    with open(path, 'r', encoding='utf-8', errors='ignore', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            item = {}
            for target_key, candidates in key_map.items():
                for c in candidates:
                    if c in row:
                        item[target_key] = row[c].strip()
                        break
            if item.get('ip') and item.get('name'):
                rows.append(item)
    return rows


def update_identity_db_from_csv(path):
    """把 CSV 中的 IP-身份映射合并到 identity_db.json，返回导入条数"""
    rows = import_identity_from_csv(path)
    if not rows:
        return 0
    identity = load_identity_db()
    count = 0
    for row in rows:
        ip = row['ip']
        identity[ip] = {
            'name': row['name'],
            'student_id': row.get('student_id', ''),
            'department': row.get('department', '')
        }
        count += 1
    save_identity_db(identity)
    return count


def _today_start_str():
    import datetime
    return datetime.datetime.now().strftime('%Y-%m-%d 00:00:00')


def _parse_days_from_text(text):
    """根据用户问题中的时间词解析查询天数，默认今天"""
    if not text:
        return 1
    text = text.lower()
    if any(k in text for k in ['最近一周', '本周', '最近7天', '最近七天', '7天', '一周']):
        return 7
    if any(k in text for k in ['最近三天', '最近3天', '3天']):
        return 3
    return 1


def _build_attacked_students_reasoning(start_str, victim_count, total_alerts, days=1):
    """生成受攻击学生技能的思考过程说明（支持今天/最近N天）"""
    date = start_str.split()[0]
    desc = "今天" if days <= 1 else f"最近 {days} 天"
    lines = [
        "【思考过程】",
        f"1. 首先确定查询时间范围为{desc}（{date} 00:00:00）到现在；",
        f"2. 从 alerts 表中查询 created_at 或 update_time 在该范围内的告警，共找到 {total_alerts} 条记录；",
        "3. 提取这些告警的 target_ip，即受攻击终端 IP，忽略空值；",
        "4. 用 target_ip 到身份映射表 data/identity_db.json 中反查学生身份信息（姓名、学号、院系）；",
        f"5. 按学生/终端聚合其遭遇的所有告警名称，最终得到 {victim_count} 名受攻击学生；",
        "6. 仅返回 identity_db.json 中存在映射关系的学生；未映射的 target_ip 不计入。",
    ]
    return "\n".join(lines)


def query_today_attacked_students(user_text=''):
    """查询今天/最近N天受攻击的学生（根据 target_ip 在 identity_db 中匹配）"""
    days = _parse_days_from_text(user_text)
    import datetime as _dt
    now = _dt.datetime.now()
    start_dt = now - _dt.timedelta(days=days - 1)
    start_dt = start_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    start = start_dt.strftime('%Y-%m-%d %H:%M:%S')
    desc = "今天" if days <= 1 else f"最近 {days} 天"
    conn = db.get_conn(db.DB_NAME)
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """SELECT id, name, severity, src_ip, target_ip, status, description, created_at, update_time
        FROM alerts
        WHERE (created_at >= %s OR update_time >= %s)
        ORDER BY update_time DESC, created_at DESC""",
        (start, start)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    # 将 datetime 字段序列化为字符串，避免 JSON 输出失败
    for row in rows:
        for k, v in row.items():
            if isinstance(v, __import__('datetime').datetime):
                row[k] = v.strftime('%Y-%m-%d %H:%M:%S')

    identity = load_identity_db()
    victims = {}
    for row in rows:
        target_ip = row.get('target_ip') or ''
        if not target_ip:
            continue
        info = identity.get(target_ip)
        if not info:
            continue
        if target_ip not in victims:
            victims[target_ip] = {'identity': info, 'alerts': []}
        victims[target_ip]['alerts'].append(row)

    if not victims:
        return {
            "ok": True,
            "message": f"{desc}暂无学生受攻击记录。\n\n" + _build_attacked_students_reasoning(start, 0, len(rows), days),
            "data": []
        }

    lines = []
    for ip, v in victims.items():
        info = v['identity']
        alert_names = [f"「{a.get('name', '')}」" for a in v['alerts']]
        lines.append(
            f"• {info.get('name')}（{info.get('student_id')}，{info.get('department')}），IP {ip}："
            f"{', '.join(alert_names)}"
        )
    return {
        "ok": True,
        "message": f"{desc}共有 {len(victims)} 名学生受到攻击：\n" + "\n".join(lines) + "\n\n" + _build_attacked_students_reasoning(start, len(victims), len(rows), days),
        "data": victims
    }


def _extract_ip(text):
    m = IP_RE.search(text)
    return m.group(1) if m else None


def detect_skill(text, skills=None):
    if skills is None:
        skills = load_skills()
    text = text or ''
    ip = _extract_ip(text)
    for skill in skills:
        if not skill.get('enabled'):
            continue
        for kw in skill.get('trigger_keywords', []):
            if kw in text:
                params = {}
                for p in skill.get('params', []):
                    if p.get('type') == 'ip':
                        if ip:
                            params[p['name']] = ip
                    else:
                        # 简单字符串参数暂不支持自动提取
                        pass
                missing = [p['name'] for p in skill.get('params', []) if p.get('required') and p['name'] not in params]
                return {
                    "matched": not missing,
                    "skill": skill,
                    "params": params,
                    "missing": missing,
                    "trigger": kw
                }
    return {"matched": False}


def _now_str():
    return __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def fake_firewall_block(ip, reason):
    """模拟深信服防火墙封禁 IP 接口"""
    return {
        "ok": True,
        "message": f"深信服防火墙已封禁 IP {ip}（原因：{reason}）",
        "ip": ip,
        "action": "block",
        "vendor": "Sangfor",
        "time": _now_str()
    }


def execute_skill(skill, params):
    """执行技能，返回 {ok, message, error, ...}。"""
    handler = skill.get('handler')
    # 校验必填参数
    for p in skill.get('params', []):
        if p.get('required') and not params.get(p['name']):
            return {"ok": False, "error": f"缺少必填参数：{p.get('description') or p['name']}"}

    if handler == 'block_ip':
        ip = params.get('ip')
        if is_protected_ip(ip):
            return {"ok": False,
                    "error": f"拒绝封禁：{ip} 属于内网/受保护地址，处置动作已被硬校验拦截"
                             f"（如确需封禁内网靶机，设置环境变量 ALLOW_INTERNAL_BLOCK=1）"}
        reason = params.get('reason') or '智能助理技能封禁'
        result = fake_firewall_block(ip, reason)
        if result.get('ok'):
            record = {'ip': ip, 'reason': reason, 'time': _now_str(), 'alarm': params.get('alarm', '')}
            db.upsert_blocked(record)
        return result

    if handler == 'query_identity':
        ip = params.get('ip')
        identity = load_identity_db().get(ip)
        if identity:
            return {
                "ok": True,
                "message": f"IP {ip} 对应身份信息：{identity.get('name')}（{identity.get('student_id')}），{identity.get('department')}。",
                "data": identity
            }
        return {"ok": False, "error": f"未找到 IP {ip} 的身份信息。"}

    if handler == 'today_attacked_students':
        return query_today_attacked_students(user_text=params.get('user_text', ''))

    if handler == 'vuln_daily_stats':
        return vuln_stats_skill.execute_vuln_daily_stats()

    return {"ok": False, "error": f"未知技能 handler：{handler}"}
