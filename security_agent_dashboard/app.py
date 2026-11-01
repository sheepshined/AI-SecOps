from flask import Flask, render_template, jsonify, request, send_from_directory, send_file
from llm_client import call_openai_compatible
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
import atexit
import json, os, uuid, threading, time
import requests
import re
import socket, ssl

def _normalize_attck_id(tech_id):
    """将 ATT&CK ID 标准化为纯技术 ID 列表，支持逗号分隔和 TAxxxx. 前缀。"""
    if not tech_id:
        return []
    ids = [s.strip() for s in str(tech_id).split(',') if s.strip()]
    result = []
    for raw in ids:
        raw = re.sub(r'^TA\d{4}\.', '', raw)
        m = re.search(r'T\d+(?:\.\d+)?$', raw)
        result.append(m.group(0) if m else raw)
    return result
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from xdr_pipeline import run_pipeline
import db
import skills
import vuln_updater

import vuln_scheduler
import vuln_stats_skill
import knowledge_context as kc

# 把 vuln_scheduler 的函数暴露给本模块中的路由使用
_start_vuln_update = vuln_scheduler.start_update
_vuln_update_status = vuln_scheduler.update_status
_vuln_scheduler_public_status = vuln_scheduler.public_status
_load_vuln_scheduler_config = vuln_scheduler.load_config
_save_vuln_scheduler_config = vuln_scheduler.save_config
_apply_vuln_scheduler_config = vuln_scheduler.apply_config
_ensure_vuln_scheduler_alive = vuln_scheduler.ensure_scheduler_alive

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

@app.after_request
def _set_no_cache_headers(response):
    """开发阶段禁止浏览器/中间件缓存所有响应，避免静态资源更新后页面仍用旧文件。"""
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

_SAMPLE_ALARMS = [
    { 'id': 'ALT-20260821-001', 'severity': 'critical', 'type': '恶意代码通信', 'src': '185.220.101.42', 'target': 'web-prod-03', 'time': '2026-08-21 10:23:18', 'status': 'open', 'attck': 'T1071.001', 'aiJudged': True, 'xdr': { 'device': 'WKS-007', 'user': 'CORP/zhangsan', 'process': 'svchost.exe', 'commandLine': 'svchost.exe -k netsvcs -p -s BITS', 'filePath': 'C:/Windows/Temp/svchost.exe', 'parentProcess': 'explorer.exe', 'networkConnection': '185.220.101.42:443' }},
    { 'id': 'ALT-20260821-002', 'severity': 'high', 'type': '暴力破解', 'src': '192.168.12.88', 'target': 'vpn-gateway', 'time': '2026-08-21 10:15:02', 'status': 'open', 'attck': 'T1110', 'aiJudged': True, 'xdr': { 'device': 'VPN-GW-01', 'user': 'admin', 'process': 'sshd', 'commandLine': '/usr/sbin/sshd -D', 'filePath': '/var/log/auth.log', 'parentProcess': 'systemd', 'networkConnection': '192.168.12.88:22' }},
    { 'id': 'ALT-20260821-003', 'severity': 'high', 'type': '异常流量峰值', 'src': '203.78.5.11', 'target': 'api-gateway', 'time': '2026-08-21 09:48:36', 'status': 'blocked', 'attck': 'T1498', 'aiJudged': False, 'xdr': { 'device': 'API-GW-02', 'user': 'N/A', 'process': 'nginx', 'commandLine': 'nginx: worker process', 'filePath': '/var/log/nginx/access.log', 'parentProcess': 'nginx', 'networkConnection': '203.78.5.11:80' }},
    { 'id': 'ALT-20260821-004', 'severity': 'medium', 'type': '可疑脚本执行', 'src': '10.0.4.21', 'target': 'workstation-07', 'time': '2026-08-21 09:12:55', 'status': 'open', 'attck': 'T1059.003', 'aiJudged': True, 'xdr': { 'device': 'WKS-007', 'user': 'CORP/lisi', 'process': 'powershell.exe', 'commandLine': 'powershell -enc SQBFAF... (base64)', 'filePath': 'C:/Users/lisi/AppData/Local/Temp/payload.ps1', 'parentProcess': 'chrome.exe', 'networkConnection': '10.0.4.21:8443' }},
    { 'id': 'ALT-20260821-005', 'severity': 'medium', 'type': '权限提升尝试', 'src': '10.0.2.19', 'target': 'dc-01', 'time': '2026-08-21 08:56:41', 'status': 'false_positive', 'attck': 'T1078', 'aiJudged': True, 'xdr': { 'device': 'DC-01', 'user': 'CORP/admin', 'process': 'mimikatz.exe', 'commandLine': 'mimikatz.exe "lsadump::sam"', 'filePath': 'C:/Windows/System32/mimikatz.exe', 'parentProcess': 'cmd.exe', 'networkConnection': '10.0.2.19:445' }},
    { 'id': 'ALT-20260821-006', 'severity': 'low', 'type': '策略变更', 'src': '10.0.1.5', 'target': 'firewall-01', 'time': '2026-08-21 08:30:12', 'status': 'closed', 'attck': '', 'aiJudged': False, 'xdr': { 'device': 'FW-01', 'user': 'admin', 'process': 'firewall-config', 'commandLine': 'apply policy update', 'filePath': '/etc/firewall/rules.conf', 'parentProcess': 'web-console', 'networkConnection': '10.0.1.5:443' }},
    { 'id': 'ALT-20260821-007', 'severity': 'critical', 'type': '数据外联', 'src': '45.142.214.76', 'target': 'db-server-02', 'time': '2026-08-21 07:45:09', 'status': 'open', 'attck': 'T1041', 'aiJudged': True, 'xdr': { 'device': 'DB-SRV-02', 'user': 'sa', 'process': 'sqlservr.exe', 'commandLine': 'sqlservr.exe -sMSSQLSERVER', 'filePath': 'C:/Program Files/Microsoft SQL Server/MSSQL/Binn/sqlservr.exe', 'parentProcess': 'services.exe', 'networkConnection': '45.142.214.76:443' }},
    { 'id': 'ALT-20260821-008', 'severity': 'high', 'type': '横向移动', 'src': '10.0.3.44', 'target': 'file-server', 'time': '2026-08-21 07:21:33', 'status': 'open', 'attck': 'T1021.002', 'aiJudged': True, 'xdr': { 'device': 'FILE-SRV-01', 'user': 'CORP/wangwu', 'process': 'wmic.exe', 'commandLine': 'wmic /node:file-server process call create "cmd.exe /c whoami"', 'filePath': 'C:/Windows/System32/wbem/wmic.exe', 'parentProcess': 'cmd.exe', 'networkConnection': '10.0.3.44:135' }},
    { 'id': 'ALT-20260821-009', 'severity': 'medium', 'type': 'WebShell 上传', 'src': '117.28.3.91', 'target': 'cms-front', 'time': '2026-08-21 06:58:17', 'status': 'blocked', 'attck': 'T1505.003', 'aiJudged': True, 'xdr': { 'device': 'CMS-FRONT-01', 'user': 'www-data', 'process': 'apache2', 'commandLine': '/usr/sbin/apache2 -k start', 'filePath': '/var/www/html/upload/shell.php', 'parentProcess': 'apache2', 'networkConnection': '117.28.3.91:8080' }},
    { 'id': 'ALT-20260821-010', 'severity': 'low', 'type': 'USB 设备接入', 'src': '10.0.5.32', 'target': 'workstation-12', 'time': '2026-08-21 06:12:50', 'status': 'open', 'attck': 'T1091', 'aiJudged': False, 'xdr': { 'device': 'WKS-012', 'user': 'CORP/zhaoliu', 'process': 'explorer.exe', 'commandLine': 'explorer.exe', 'filePath': 'E:/autorun.exe', 'parentProcess': 'userinit.exe', 'networkConnection': '10.0.5.32:0' }}
]


# 为示例告警补充 AI 研判请求/响应数据，用于前端展示完整研判链路
for _a in _SAMPLE_ALARMS:
    if not _a.get('aiJudged'):
        continue
    _type = _a.get('type', '')
    _alert_summary = f"告警ID: {_a['id']}\n类型: {_type}\n源IP: {_a['src']}\n目标: {_a['target']}\nATT&CK: {_a.get('attck', 'N/A')}\nXDR上下文: {_a['xdr']}"
    _base_request = {
        "system_prompt": "你是安全运营专家。请根据以下深信服XDR告警举证数据，判断该告警的性质，给出威胁等级、攻击类型、ATT&CK技术（如有）、处置建议，并以简洁中文返回。",
        "messages": [
            {"role": "system", "content": "你是安全运营专家。请根据以下深信服XDR告警举证数据，判断该告警的性质，给出威胁等级、攻击类型、ATT&CK技术（如有）、处置建议，并以简洁中文返回。"},
            {"role": "user", "content": "告警举证数据：\n\n" + _alert_summary}
        ],
        "chat_id": _a['id'].lower().replace('-', ''),
        "model_config": {"temperature": 0.3, "provider": "deepseek", "model": "deepseek-chat"}
    }
    _a['request'] = _base_request
    if _type == '恶意代码通信':
        _a['verdict'] = '高度可疑：终端 WKS-007 通过非标准端口与已知 C2 节点 185.220.101.42:443 通信，疑似恶意下载器回连，建议立即封禁外联 IP 并隔离终端。'
        _a['model_response'] = """## 研判结论
- **威胁等级**：高危
- **攻击类型**：恶意代码通信（C2 回连）
- **ATT&CK**：T1071.001 Application Layer Protocol: Web Protocols
- **处置建议**：
  1. 立即在防火墙封禁 185.220.101.42；
  2. EDR 隔离 WKS-007，终止 svchost.exe 异常进程；
  3. 提取 BITS 作业文件进行逆向分析；
  4. 核查 zhangsan 账号近期操作。"""
    elif _type == '暴力破解':
        _a['verdict'] = '确认攻击：外部 IP 192.168.12.88 对 VPN-GW-01 SSH 服务发起高频暴力破解，触发 T1110，建议封禁源 IP 并启用多因素认证。'
        _a['model_response'] = """## 研判结论
- **威胁等级**：高危
- **攻击类型**：暴力破解（远程访问凭证窃取）
- **ATT&CK**：T1110 Brute Force
- **处置建议**：
  1. 在 VPN 网关封禁 192.168.12.88；
  2. 检查 admin 账户是否被成功登录；
  3. 强制受影响用户修改密码并启用 MFA；
  4. 回顾 auth.log 中同网段其他源 IP。"""
    elif _type == '异常流量峰值':
        _a['verdict'] = '高度可疑：203.78.5.11 对 api-gateway 产生异常流量峰值，疑似应用层 DDoS（T1498），已自动触发封禁。'
        _a['model_response'] = """## 研判结论
- **威胁等级**：高危
- **攻击类型**：应用层拒绝服务攻击
- **ATT&CK**：T1498 Network Denial of Service
- **处置建议**：
  1. 已联动防火墙封禁 203.78.5.11；
  2. 检查 api-gateway 连接数与 QPS，必要时扩容；
  3. 在 WAF 开启速率限制与 Bot 识别；
  4. 分析请求指纹，补充 CC 防护规则。"""
    elif _type == '可疑脚本执行':
        _a['verdict'] = '高度可疑：CORP/lisi 在 WKS-007 上执行 base64 编码 PowerShell 命令，疑似无文件攻击或下载器，建议终止进程并隔离终端。'
        _a['model_response'] = """## 研判结论
- **威胁等级**：高危
- **攻击类型**：可疑脚本执行 / 无文件攻击
- **ATT&CK**：T1059.003 Windows Command Shell / PowerShell
- **处置建议**：
  1. 立即终止 powershell.exe 进程；
  2. EDR 隔离 WKS-007；
  3. 解码 base64 payload 并分析其 C2 与行为；
  4. 核查 lisi 账号是否被盗用。"""
    elif _type == '权限提升尝试':
        _a['verdict'] = '经复核，mimikatz.exe 为公司安全团队授权的渗透测试工具，且 DC-01 在授权窗口期内，判定为误报。'
        _a['model_response'] = """## 研判结论
- **威胁等级**：低（已判定为误报）
- **攻击类型**：凭证转储（授权测试）
- **ATT&CK**：T1078 Valid Accounts
- **处置建议**：
  1. 该告警对应授权渗透测试窗口，无实际风险；
  2. 标记为误报并关闭告警；
  3. 在平台记录授权编号，便于审计。"""
    elif _type == '数据外联':
        _a['verdict'] = '严重：DB-SRV-02 的 sa 账号通过 sqlservr.exe 向外部 IP 45.142.214.76:443 发起大量外联，疑似数据外泄，建议立即断网、隔离数据库并审计近期查询。'
        _a['model_response'] = """## 研判结论
- **威胁等级**：严重
- **攻击类型**：数据外泄 / 渗透外联
- **ATT&CK**：T1041 Exfiltration Over C2 Channel
- **处置建议**：
  1. 立即阻断 DB-SRV-02 的外联流量；
  2. 隔离数据库服务器，暂停 sa 账号使用；
  3. 审计近 7 天数据库导出、备份与查询日志；
  4. 保存网络流量包，进行数据泄露范围评估。"""
    elif _type == '横向移动':
        _a['verdict'] = '高度可疑：CORP/wangwu 使用 wmic.exe 在 file-server 上远程创建进程，典型 WMI 横向移动（T1021.002），建议隔离源终端并核查账号。'
        _a['model_response'] = """## 研判结论
- **威胁等级**：高危
- **攻击类型**：横向移动（WMI 远程命令执行）
- **ATT&CK**：T1021.002 Remote Services: SMB/Windows Admin Shares
- **处置建议**：
  1. 隔离 FILE-SRV-01 与源终端 WKS-007；
  2. 核查 wangwu 账号是否被盗用；
  3. 禁用不必要的 WMI/135 端口访问；
  4. 检查 file-server 是否存在新增计划任务或服务。"""
    elif _type == 'WebShell 上传':
        _a['verdict'] = '确认：CMS-FRONT-01 上传目录出现 shell.php，攻击源 117.28.3.91，已联动封禁。建议清理 WebShell、修复上传漏洞并全面查杀。'
        _a['model_response'] = """## 研判结论
- **威胁等级**：高危
- **攻击类型**：WebShell 上传 / Web 应用入侵
- **ATT&CK**：T1505.003 Server Software Component: Web Shell
- **处置建议**：
  1. 已封禁 117.28.3.91；
  2. 删除 /var/www/html/upload/shell.php 并修复上传白名单；
  3. 全面查杀 CMS-FRONT-01，检查是否存在持久化后门；
  4. 审查 apache2 访问日志，定位入侵入口。"""
    elif _type == 'USB 设备接入':
        _a['verdict'] = '低危：WKS-012 检测到 USB 设备接入并执行 autorun.exe，需确认是否为公司授权设备。'
        _a['model_response'] = """## 研判结论
- **威胁等级**：低
- **攻击类型**：可移动介质执行
- **ATT&CK**：T1091 Replication Through Removable Media
- **处置建议**：
  1. 联系用户 zhaoliu 确认 USB 设备来源；
  2. 如非授权，隔离 WKS-012 并查杀 autorun.exe；
  3. 建议组策略禁用自动播放。"""
    else:
        _a['verdict'] = 'AI 研判完成：该告警存在一定的异常特征，建议结合上下文进一步分析。'
        _a['model_response'] = '## 研判结论\n- **威胁等级**：中危\n- **处置建议**：请结合 ATT&CK 映射与 XDR 上下文进一步分析。'

_SAMPLE_BLOCKED = [
    { 'ip': '203.78.5.11', 'reason': 'DDoS 攻击源', 'time': '2026-08-21 09:50:00', 'alarm': 'ALT-20260821-003' },
    { 'ip': '117.28.3.91', 'reason': 'WebShell 上传源', 'time': '2026-08-21 07:00:00', 'alarm': 'ALT-20260821-009' }
]

ASSETS = [
    { 'id': 'AST-XYC-001', 'name': '新余学院官网', 'domain': 'www.xyc.edu.cn', 'url': 'https://www.xyc.edu.cn', 'ip': '10.0.1.10', 'port': 443, 'status': 'active', 'waf': '启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'normal', 'waf_http_status': 403, 'ssl_days': 62, 'ssl_days_left': 62, 'response_time_ms': 128, 'last_seen': '2026-08-21 09:00:00' },
    { 'id': 'AST-XYC-002', 'name': '文学与传媒学院', 'domain': 'wxy.xyc.edu.cn', 'url': 'https://wxy.xyc.edu.cn', 'ip': '10.0.1.11', 'port': 443, 'status': 'active', 'waf': '启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'normal', 'waf_http_status': 403, 'ssl_days': 58, 'ssl_days_left': 58, 'response_time_ms': 156, 'last_seen': '2026-08-21 09:00:00' },
    { 'id': 'AST-XYC-003', 'name': '外国语学院', 'domain': 'wgy.xyc.edu.cn', 'url': 'https://wgy.xyc.edu.cn', 'ip': '10.0.1.12', 'port': 443, 'status': 'active', 'waf': '启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'normal', 'waf_http_status': 403, 'ssl_days': 71, 'ssl_days_left': 71, 'response_time_ms': 142, 'last_seen': '2026-08-21 08:55:00' },
    { 'id': 'AST-XYC-004', 'name': '经济与管理学院', 'domain': 'jjxy.xyc.edu.cn', 'url': 'https://jjxy.xyc.edu.cn', 'ip': '10.0.1.13', 'port': 443, 'status': 'active', 'waf': '启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'normal', 'waf_http_status': 403, 'ssl_days': 45, 'ssl_days_left': 45, 'response_time_ms': 98, 'last_seen': '2026-08-21 08:50:00' },
    { 'id': 'AST-XYC-005', 'name': '机电工程学院', 'domain': 'jdxy.xyc.edu.cn', 'url': 'https://jdxy.xyc.edu.cn', 'ip': '10.0.1.14', 'port': 443, 'status': 'active', 'waf': '启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'normal', 'waf_http_status': 403, 'ssl_days': 52, 'ssl_days_left': 52, 'response_time_ms': 187, 'last_seen': '2026-08-21 08:45:00' },
    { 'id': 'AST-XYC-006', 'name': '数学与计算机学院', 'domain': 'sxxy.xyc.edu.cn', 'url': 'https://sxxy.xyc.edu.cn', 'ip': '10.0.1.15', 'port': 443, 'status': 'active', 'waf': '未启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'abnormal', 'waf_http_status': 200, 'ssl_days': 39, 'ssl_days_left': 39, 'response_time_ms': 210, 'last_seen': '2026-08-21 08:40:00' },
    { 'id': 'AST-XYC-007', 'name': '新能源科学与工程学院', 'domain': 'xny.xyc.edu.cn', 'url': 'https://xny.xyc.edu.cn', 'ip': '10.0.1.16', 'port': 443, 'status': 'abnormal', 'waf': '启用', 'business_status': 'abnormal', 'business_http_status': 503, 'business_status_code': 200, 'waf_status': 'normal', 'waf_http_status': 403, 'ssl_days': 33, 'ssl_days_left': 33, 'response_time_ms': 2450, 'last_seen': '2026-08-21 08:35:00' },
    { 'id': 'AST-XYC-008', 'name': '建筑工程学院', 'domain': 'jzxy.xyc.edu.cn', 'url': 'https://jzxy.xyc.edu.cn', 'ip': '10.0.1.17', 'port': 443, 'status': 'active', 'waf': '启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'normal', 'waf_http_status': 403, 'ssl_days': 66, 'ssl_days_left': 66, 'response_time_ms': 134, 'last_seen': '2026-08-21 08:30:00' },
    { 'id': 'AST-XYC-009', 'name': '医学院', 'domain': 'yxy.xyc.edu.cn', 'url': 'https://yxy.xyc.edu.cn', 'ip': '10.0.1.18', 'port': 443, 'status': 'active', 'waf': '启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'normal', 'waf_http_status': 403, 'ssl_days': 28, 'ssl_days_left': 28, 'response_time_ms': 119, 'last_seen': '2026-08-21 08:25:00' },
    { 'id': 'AST-XYC-010', 'name': '艺术学院', 'domain': 'ysxy.xyc.edu.cn', 'url': 'https://ysxy.xyc.edu.cn', 'ip': '10.0.1.19', 'port': 443, 'status': 'active', 'waf': '启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'normal', 'waf_http_status': 403, 'ssl_days': 54, 'ssl_days_left': 54, 'response_time_ms': 167, 'last_seen': '2026-08-21 08:20:00' },
    { 'id': 'AST-XYC-011', 'name': '体育学院', 'domain': 'tyxy.xyc.edu.cn', 'url': 'https://tyxy.xyc.edu.cn', 'ip': '10.0.1.21', 'port': 443, 'status': 'active', 'waf': '启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'normal', 'waf_http_status': 403, 'ssl_days': 14, 'ssl_days_left': 14, 'response_time_ms': 145, 'last_seen': '2026-08-21 08:15:00' },
    { 'id': 'AST-XYC-012', 'name': '马克思主义学院', 'domain': 'marx.xyc.edu.cn', 'url': 'https://marx.xyc.edu.cn', 'ip': '10.0.1.22', 'port': 443, 'status': 'active', 'waf': '启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'normal', 'waf_http_status': 403, 'ssl_days': 88, 'ssl_days_left': 88, 'response_time_ms': 132, 'last_seen': '2026-08-21 08:10:00' },
    { 'id': 'AST-XYC-013', 'name': '国际教育学院', 'domain': 'gjjy.xyc.edu.cn', 'url': 'https://gjjy.xyc.edu.cn', 'ip': '10.0.1.23', 'port': 443, 'status': 'active', 'waf': '启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'normal', 'waf_http_status': 403, 'ssl_days': 95, 'ssl_days_left': 95, 'response_time_ms': 121, 'last_seen': '2026-08-21 08:05:00' },
    { 'id': 'AST-XYC-014', 'name': '护理与康复学院', 'domain': 'hlxy.xyc.edu.cn', 'url': 'https://hlxy.xyc.edu.cn', 'ip': '10.0.1.24', 'port': 443, 'status': 'warning', 'waf': '未启用', 'business_status': 'normal', 'business_http_status': 200, 'business_status_code': 200, 'waf_status': 'abnormal', 'waf_http_status': 200, 'ssl_days': 21, 'ssl_days_left': 21, 'response_time_ms': 198, 'last_seen': '2026-08-21 08:00:00' }
]

def now_str():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


WHITELIST_RULES = []


def refresh_alarms():
    global ALARMS
    ALARMS = db.load_alarms()
    _apply_whitelist_to_alarms()


def refresh_whitelist_rules():
    global WHITELIST_RULES
    WHITELIST_RULES = db.load_whitelist_rules()


def _parse_connection(network_connection, src, target):
    """从 network_connection 字符串解析源/目的端口。
    支持两种格式：'src:port -> dst:port' 或 'src:port'。"""
    src_port = ''
    dst_port = ''
    if not network_connection:
        return src_port, dst_port
    parts = [p.strip() for p in network_connection.split('->')]
    if len(parts) == 2:
        left, right = parts
        if left.startswith(src) and ':' in left:
            src_port = left.split(':')[-1]
        if right.startswith(target) and ':' in right:
            dst_port = right.split(':')[-1]
    elif len(parts) == 1:
        part = parts[0]
        if part.startswith(src) and ':' in part:
            src_port = part.split(':')[-1]
    return src_port, dst_port


def _alarm_matches_rule(alarm, rule):
    """判断单条告警是否命中某条加白规则。空字段表示任意。"""
    if not rule.get('enabled'):
        return False
    xdr = alarm.get('xdr') or {}
    src_port, dst_port = _parse_connection(
        xdr.get('networkConnection', ''),
        alarm.get('src', ''),
        alarm.get('target', '')
    )
    if rule.get('src_ip') and alarm.get('src') != rule['src_ip']:
        return False
    if rule.get('dst_ip') and alarm.get('target') != rule['dst_ip']:
        return False
    if rule.get('src_port') and src_port != rule['src_port']:
        return False
    if rule.get('dst_port') and dst_port != rule['dst_port']:
        return False
    if rule.get('name_pattern'):
        name = alarm.get('name') or alarm.get('type') or ''
        if rule['name_pattern'] not in name:
            return False
    return True


def _apply_whitelist_to_alarms():
    """对所有已加载告警应用加白规则，并同步数据库状态。"""
    global ALARMS
    updated_ids = []
    for alarm in ALARMS:
        matched_rule = None
        for rule in WHITELIST_RULES:
            if _alarm_matches_rule(alarm, rule):
                matched_rule = rule
                break
        if matched_rule:
            if alarm.get('status') != 'false_positive':
                db.update_alarm_status(alarm['id'], 'false_positive')
                updated_ids.append(alarm['id'])
            alarm['status'] = 'false_positive'
            alarm['whitelisted'] = True
            alarm['whitelist_rule_id'] = matched_rule['id']
            alarm['whitelist_reason'] = matched_rule.get('reason', '') or '命中加白规则'
        else:
            if alarm.get('status') == 'false_positive':
                db.update_alarm_status(alarm['id'], 'pending')
                updated_ids.append(alarm['id'])
                alarm['status'] = 'pending'
            alarm['whitelisted'] = False
            alarm.pop('whitelist_rule_id', None)
            alarm.pop('whitelist_reason', None)
    return updated_ids


_ATTACK_TECHNIQUES = {}

def _load_attack_techniques():
    global _ATTACK_TECHNIQUES
    path = os.path.join(os.path.dirname(__file__), 'static', 'data', 'attack_subtechniques.json')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        _ATTACK_TECHNIQUES = {item['id']: item for item in data if item.get('id')}
    except Exception as e:
        print('加载 ATT&CK 映射失败:', e)
        _ATTACK_TECHNIQUES = {}

def enrich_attck_info(alarm):
    """根据 alarm['attck'] 关联 ATT&CK 映射，生成 attck_info。支持逗号分隔与 TAxxxx. 前缀。"""
    if not alarm or not isinstance(alarm, dict):
        return alarm
    raw = alarm.get('attck', '')
    if not raw:
        alarm['attck_info'] = None
        return alarm
    norm_ids = _normalize_attck_id(raw)
    if not norm_ids:
        alarm['attck_info'] = None
        return alarm
    alarm['attck'] = ','.join(norm_ids)
    infos = []
    tactics_set = set()
    for nid in norm_ids:
        info = _ATTACK_TECHNIQUES.get(nid)
        if info:
            infos.append(info)
            tactics_set.update(info.get('tactics') or [])
    if not infos:
        alarm['attck_info'] = None
        return alarm
    primary = infos[0]
    alarm['attck_info'] = {
        'id': primary.get('id', norm_ids[0]),
        'name': primary.get('name', ''),
        'nameZh': primary.get('nameZh', ''),
        'tactics': sorted(tactics_set),
        'parentId': primary.get('parentId', ''),
        'parentName': primary.get('parentName', ''),
        'parentNameZh': primary.get('parentNameZh', ''),
        'techniques': norm_ids
    }
    return alarm


# 初始化数据库、清理示例告警、添加示例加白规则、加载封禁列表
db.init_db()
db.delete_sample_alarms()
db.seed_sample_whitelist_rules()
ALARMS = db.load_alarms()
WHITELIST_RULES = db.load_whitelist_rules()
_apply_whitelist_to_alarms()
BLOCKED = []
for b in _SAMPLE_BLOCKED:
    if not any(x['ip'] == b['ip'] for x in BLOCKED):
        db.upsert_blocked(b)
BLOCKED = db.load_blocked()
vuln_scheduler.apply_config()
_load_attack_techniques()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    total = len(ALARMS)
    high = sum(1 for a in ALARMS if a['severity'] in ('critical', 'high'))
    open_count = sum(1 for a in ALARMS if a['status'] == 'open')
    fp = sum(1 for a in ALARMS if a['status'] == 'false_positive')
    blocked = len(BLOCKED)
    critical = sum(1 for a in ALARMS if a['severity'] == 'critical')
    return jsonify({
        'total': total,
        'high': high,
        'critical': critical,
        'open': open_count,
        'false_positive': fp,
        'whitelisted': fp,
        'blocked': blocked
    })

@app.route('/api/alarms')
def api_alarms():
    status = request.args.get('status')
    severity = request.args.get('severity')
    q = request.args.get('q', '').lower()
    data = list(ALARMS)
    if status:
        data = [a for a in data if a['status'] == status]
    if severity:
        data = [a for a in data if a['severity'] == severity]
    if q:
        data = [a for a in data if q in ' '.join([a['id'], a['type'], a['src'], a['target'], a.get('attck','')]).lower()]
    return jsonify([enrich_attck_info(a) for a in data])


@app.route('/api/alarms/refresh', methods=['POST'])
def api_alarms_refresh():
    """立即从数据库重新加载告警列表到内存缓存"""
    try:
        refresh_alarms()
        return jsonify({
            'ok': True,
            'count': len(ALARMS),
            'first_id': ALARMS[0]['id'] if ALARMS else None,
            'first_ai_judged': ALARMS[0].get('aiJudged') if ALARMS else None
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 502

@app.route('/api/alarms/<alarm_id>')
def api_alarm(alarm_id):
    for a in ALARMS:
        if a['id'] == alarm_id:
            return jsonify(enrich_attck_info(dict(a)))
    return jsonify({'error': 'not found'}), 404

@app.route('/api/alarms/<alarm_id>/status', methods=['POST'])
def api_alarm_status(alarm_id):
    data = request.get_json(force=True) or {}
    new_status = data.get('status')
    allowed = {'open', 'blocked', 'false_positive', 'closed'}
    if new_status not in allowed:
        return jsonify({'error': 'invalid status'}), 400
    if db.get_alarm(alarm_id) is None:
        return jsonify({'error': 'not found'}), 404
    db.update_alarm_status(alarm_id, new_status)
    refresh_alarms()
    return jsonify(db.get_alarm(alarm_id))

@app.route('/api/alarms/<alarm_id>/block', methods=['POST'])
def api_alarm_block(alarm_id):
    a = db.get_alarm(alarm_id)
    if a is None:
        return jsonify({'error': 'not found'}), 404
    if skills.is_protected_ip(a.get('src')):
        return jsonify({'ok': False,
                        'error': f"拒绝封禁：{a.get('src')} 属于内网/受保护地址，处置动作已被硬校验拦截"
                                 f"（如确需封禁内网靶机，设置环境变量 ALLOW_INTERNAL_BLOCK=1）"}), 400
    if not any(b['ip'] == a['src'] for b in BLOCKED):
        record = {
            'ip': a['src'],
            'reason': '告警 {}: {}'.format(a['id'], a['type']),
            'time': now_str(),
            'alarm': a['id']
        }
        BLOCKED.append(record)
        db.upsert_blocked(record)
    db.update_alarm_status(alarm_id, 'blocked')
    refresh_alarms()
    return jsonify({'ok': True, 'alarm': db.get_alarm(alarm_id), 'blocked': BLOCKED})

def _add_whitelist_for_alarm(alarm_id: str, data: dict | None = None, default_reason: str = '手动加白'):
    """根据告警信息和请求数据创建加白规则，应用后刷新内存状态。"""
    alarm = db.get_alarm(alarm_id)
    if alarm is None:
        return None, jsonify({'error': 'not found'}), 404
    xdr = alarm.get('xdr') or {}
    src_port, dst_port = _parse_connection(
        xdr.get('networkConnection', ''),
        alarm.get('src', ''),
        alarm.get('target', '')
    )
    data = data or {}
    rule = {
        'src_ip': (data.get('src_ip') if data.get('src_ip') is not None else alarm.get('src', '')),
        'dst_ip': (data.get('dst_ip') if data.get('dst_ip') is not None else alarm.get('target', '')),
        'src_port': (data.get('src_port') if data.get('src_port') is not None else src_port),
        'dst_port': (data.get('dst_port') if data.get('dst_port') is not None else dst_port),
        'name_pattern': (data.get('name_pattern') if data.get('name_pattern') is not None else (alarm.get('name') or alarm.get('type', ''))),
        'reason': (data.get('reason') or default_reason).strip(),
        'enabled': bool(data.get('enabled', True)),
    }
    rule = {k: (v.strip() if isinstance(v, str) else v) for k, v in rule.items()}
    if not any([rule.get('src_ip'), rule.get('dst_ip'), rule.get('src_port'), rule.get('dst_port'), rule.get('name_pattern')]):
        return None, jsonify({'error': '无法构造加白规则：字段均为空'}), 400
    rule = db.add_whitelist_rule(rule)
    refresh_whitelist_rules()
    _apply_whitelist_to_alarms()
    refresh_alarms()
    return rule, None, None


@app.route('/api/alarms/<alarm_id>/false_positive', methods=['POST'])
def api_alarm_false_positive(alarm_id):
    data = request.get_json(force=True) or {}
    rule, resp, status = _add_whitelist_for_alarm(alarm_id, data, default_reason='手动标记误报')
    if resp is not None:
        return resp, status
    return jsonify({'ok': True, 'rule': rule, 'alarm': db.get_alarm(alarm_id)})


@app.route('/api/whitelist', methods=['GET'])
def api_whitelist():
    return jsonify(WHITELIST_RULES)


@app.route('/api/whitelist', methods=['POST'])
def api_whitelist_create():
    data = request.get_json(force=True) or {}
    rule = {
        'src_ip': (data.get('src_ip') or '').strip(),
        'dst_ip': (data.get('dst_ip') or '').strip(),
        'src_port': (data.get('src_port') or '').strip(),
        'dst_port': (data.get('dst_port') or '').strip(),
        'name_pattern': (data.get('name_pattern') or '').strip(),
        'reason': (data.get('reason') or '手动加白').strip(),
        'enabled': bool(data.get('enabled', True)),
    }
    if not any([rule['src_ip'], rule['dst_ip'], rule['src_port'], rule['dst_port'], rule['name_pattern']]):
        return jsonify({'error': '至少指定一个加白字段'}), 400
    rule = db.add_whitelist_rule(rule)
    refresh_whitelist_rules()
    _apply_whitelist_to_alarms()
    refresh_alarms()
    return jsonify({'ok': True, 'rule': rule})


@app.route('/api/whitelist/<rule_id>', methods=['PUT'])
def api_whitelist_update(rule_id):
    data = request.get_json(force=True) or {}
    updates = {}
    for k in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'name_pattern', 'reason', 'enabled']:
        if k in data:
            updates[k] = data[k]
    db.update_whitelist_rule(rule_id, updates)
    refresh_whitelist_rules()
    _apply_whitelist_to_alarms()
    refresh_alarms()
    return jsonify({'ok': True, 'rules': WHITELIST_RULES})


@app.route('/api/whitelist/<rule_id>', methods=['DELETE'])
def api_whitelist_delete(rule_id):
    db.delete_whitelist_rule(rule_id)
    refresh_whitelist_rules()
    _apply_whitelist_to_alarms()
    refresh_alarms()
    return jsonify({'ok': True, 'rules': WHITELIST_RULES})


@app.route('/api/alarms/<alarm_id>/whitelist', methods=['POST'])
def api_alarm_whitelist(alarm_id):
    data = request.get_json(force=True) or {}
    rule, resp, status = _add_whitelist_for_alarm(alarm_id, data, default_reason='从告警一键加白')
    if resp is not None:
        return resp, status
    affected = [a['id'] for a in ALARMS if a.get('whitelisted')]
    return jsonify({'ok': True, 'rule': rule, 'affected': affected})


@app.route('/api/blocked')
def api_blocked():
    return jsonify(BLOCKED)

@app.route('/api/blocked', methods=['POST'])
def api_block_ip():
    data = request.get_json(force=True) or {}
    ip = data.get('ip')
    reason = data.get('reason', '手动封禁')
    if not ip:
        return jsonify({'error': 'ip required'}), 400
    if skills.is_protected_ip(ip):
        return jsonify({'ok': False,
                        'error': f"拒绝封禁：{ip} 属于内网/受保护地址，处置动作已被硬校验拦截"
                                 f"（如确需封禁内网靶机，设置环境变量 ALLOW_INTERNAL_BLOCK=1）"}), 400
    if not any(b['ip'] == ip for b in BLOCKED):
        record = {'ip': ip, 'reason': reason, 'time': now_str(), 'alarm': '-'}
        BLOCKED.append(record)
        db.upsert_blocked(record)
    for a in ALARMS:
        if a['src'] == ip and a['status'] != 'false_positive':
            db.update_alarm_status(a['id'], 'blocked')
    refresh_alarms()
    return jsonify({'ok': True, 'blocked': BLOCKED})

@app.route('/api/blocked/<path:ip>', methods=['DELETE'])
def api_unblock_ip(ip):
    global BLOCKED
    BLOCKED = [b for b in BLOCKED if b['ip'] != ip]
    db.delete_blocked(ip)
    for a in ALARMS:
        if a['src'] == ip and a['status'] == 'blocked':
            db.update_alarm_status(a['id'], 'open')
    refresh_alarms()
    return jsonify({'ok': True, 'blocked': BLOCKED})


@app.route('/api/firewall/block', methods=['POST'])
def api_firewall_block():
    """伪造深信服防火墙封禁 IP 接口（演示用）"""
    data = request.get_json(force=True) or {}
    ip = data.get('ip', '').strip()
    reason = data.get('reason', '智能助理防火墙封禁').strip()
    if not ip:
        return jsonify({'ok': False, 'error': '缺少必填参数：IP 地址'}), 400
    if skills.is_protected_ip(ip):
        return jsonify({'ok': False,
                        'error': f"拒绝封禁：{ip} 属于内网/受保护地址，处置动作已被硬校验拦截"
                                 f"（如确需封禁内网靶机，设置环境变量 ALLOW_INTERNAL_BLOCK=1）"}), 400
    result = skills.fake_firewall_block(ip, reason)
    if result.get('ok'):
        record = {'ip': ip, 'reason': reason, 'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'alarm': ''}
        db.upsert_blocked(record)
        global BLOCKED
        BLOCKED = db.load_blocked()
    return jsonify(result)

@app.route('/api/assets')
def api_assets():
    return jsonify(ASSETS)

def probe_asset(url, expected_status=200, expected_waf=True, timeout=10):
    """对单个 Web 资产发起真实探测：正常请求验证业务是否在线，SQL 注入请求验证 WAF 是否生效。"""
    from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qs
    result = {
        'time': now_str(),
        'business_status': 'unknown',
        'business_http_status': None,
        'waf_status': 'unknown',
        'waf_http_status': None,
        'response_time_ms': None,
        'ssl_days_left': None,
        'message': '',
        'waf_detected': [],
    }

    url = (url or '').strip()
    if not url:
        result['business_status'] = 'abnormal'
        result['waf_status'] = 'abnormal'
        result['message'] = 'URL 为空'
        return result

    if not re.match(r'^https?://', url, re.I):
        url = 'https://' + url

    headers = {
        'User-Agent': 'Mozilla/5.0 (SecurityAssetProbe/1.0) AssetMonitor'
    }

    # 1. 正常业务探测
    start = time.time()
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
        elapsed = int((time.time() - start) * 1000)
        result['business_http_status'] = resp.status_code
        result['response_time_ms'] = elapsed
        if resp.status_code == expected_status:
            result['business_status'] = 'normal'
        else:
            result['business_status'] = 'abnormal'
    except requests.exceptions.Timeout:
        result['response_time_ms'] = int((time.time() - start) * 1000)
        result['business_status'] = 'abnormal'
        result['message'] = '业务请求超时'
    except requests.exceptions.ConnectionError as e:
        result['response_time_ms'] = int((time.time() - start) * 1000)
        result['business_status'] = 'abnormal'
        result['message'] = '业务连接失败'
    except Exception as e:
        result['response_time_ms'] = int((time.time() - start) * 1000)
        result['business_status'] = 'abnormal'
        result['message'] = '业务请求异常：' + str(e)

    # 2. HTTPS 证书有效期探测（默认上下文校验失败时回退到不校验，匹配 requests verify=False）
    if url.lower().startswith('https://'):
        ssl_err = None
        for ctx in (ssl.create_default_context(), ssl._create_unverified_context()):
            try:
                parsed = urlsplit(url)
                host = parsed.hostname
                port = parsed.port or 443
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        not_after = cert.get('notAfter')
                        if not_after:
                            not_after = re.sub(r'\s+', ' ', not_after).strip()
                            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            result['ssl_days_left'] = (expiry - datetime.now(timezone.utc)).days
                            break
            except Exception as e:
                ssl_err = e
        if result['ssl_days_left'] is None and ssl_err:
            print('[probe_asset] SSL 证书提取失败:', ssl_err)

    # 3. SQL 注入探测（验证 WAF 是否拦截）
    scheme, netloc, path, query, fragment = urlsplit(url)
    if not path:
        path = '/'
    params = parse_qs(query)
    params['id'] = "1' OR '1'='1"
    params['sqli_probe'] = ['1']
    sqli_query = urlencode(params, doseq=True)
    sqli_url = urlunsplit((scheme, netloc, path, sqli_query, fragment))

    waf_vendor_markers = ['cloudflare', 'aws', 'amazon', 'aliyun', 'tencent',
                          'sucuri', 'akamai', 'imperva', 'fortinet', 'modsecurity',
                          'f5', 'bigip', '防火墙', 'waf', 'security']
    waf_block_markers = ['blocked', 'block', '403 forbidden', 'access denied',
                         'denied', 'forbidden', '拦截', 'captcha', 'challenge',
                         'error 1006', 'attention required']
    waf_block_statuses = {403, 406, 408, 429, 496, 499}
    try:
        resp_sqli = requests.get(sqli_url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
        result['waf_http_status'] = resp_sqli.status_code
        body = (resp_sqli.text or '')[:2048]
        body_lower = body.lower()
        result['waf_detected'] = [m for m in waf_vendor_markers if m in body_lower]
        blocked = resp_sqli.status_code in waf_block_statuses or any(m in body_lower for m in waf_block_markers)
        if not expected_waf:
            result['waf_status'] = 'normal'
        elif blocked:
            result['waf_status'] = 'normal'  # WAF 成功拦截 SQL 注入
        else:
            result['waf_status'] = 'abnormal'  # WAF 未拦截 SQL 注入
    except requests.exceptions.Timeout:
        result['waf_http_status'] = None
        result['waf_status'] = 'abnormal' if expected_waf else 'normal'
    except requests.exceptions.ConnectionError:
        result['waf_http_status'] = None
        result['waf_status'] = 'abnormal' if expected_waf else 'normal'
    except Exception as e:
        result['waf_http_status'] = None
        result['waf_status'] = 'abnormal' if expected_waf else 'normal'
        result['message'] = (result['message'] + ' / WAF 探测异常：' + str(e)).strip(' /')

    if not result['message']:
        result['message'] = '业务 HTTP {} / WAF HTTP {} / 响应 {}ms'.format(
            result['business_http_status'] or '-',
            result['waf_http_status'] or '-',
            result['response_time_ms'] or '-'
        )
    return result

@app.route('/api/assets/probe', methods=['POST'])
def api_asset_probe():
    """单资产真实探测接口"""
    data = request.get_json(force=True) or {}
    url = data.get('url', '').strip()
    expected_status = data.get('expected_status') or data.get('business_status_code') or 200
    expected_waf = data.get('expected_waf', True)
    try:
        expected_status = int(expected_status)
    except (TypeError, ValueError):
        expected_status = 200
    if not url:
        return jsonify({'ok': False, 'error': '缺少 URL'}), 400
    result = probe_asset(url, expected_status=expected_status, expected_waf=bool(expected_waf))
    return jsonify({'ok': True, 'result': result})

@app.route('/api/assets/batch-probe', methods=['POST'])
def api_asset_batch_probe():
    """批量资产真实探测接口"""
    data = request.get_json(force=True) or {}
    items = data.get('assets', [])
    if not isinstance(items, list):
        return jsonify({'ok': False, 'error': 'assets 必须是数组'}), 400
    results = []
    for asset in items:
        if not asset.get('enabled', True):
            continue
        url = (asset.get('url') or '').strip()
        if not url:
            continue
        expected_status = asset.get('expected_status') or asset.get('business_status_code') or 200
        expected_waf = asset.get('expected_waf', True)
        try:
            expected_status = int(expected_status)
        except (TypeError, ValueError):
            expected_status = 200
        res = probe_asset(url, expected_status=expected_status, expected_waf=bool(expected_waf))
        res['id'] = asset.get('id')
        results.append(res)
    return jsonify({'ok': True, 'results': results})

@app.route('/api/attack/stats')
def api_attack_stats():
    counts = {}
    for a in ALARMS:
        if a.get('attck'):
            counts[a['attck']] = counts.get(a['attck'], 0) + 1
    top = sorted(counts.items(), key=lambda x: -x[1])[:10]
    return jsonify({'counts': counts, 'top': top})


# 智能助理模型配置与对话代理
CONFIG_DIR = os.path.join(os.path.dirname(__file__), 'data')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'assistant_config.json')

# 资料库（知识库）配置
LIBRARY_DIR = os.path.join(os.path.dirname(__file__), 'data', 'library')
LIBRARY_INDEX = os.path.join(LIBRARY_DIR, 'index.json')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024



def ensure_config_dir():
    if not os.path.isdir(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)


def load_model_configs():
    ensure_config_dir()
    if not os.path.exists(CONFIG_FILE):
        return []
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def save_model_configs(configs):
    ensure_config_dir()
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(configs, f, ensure_ascii=False, indent=2)


def mask_key(key):
    if not key:
        return ''
    if len(key) <= 4:
        return '*' * len(key)
    return key[:4] + '****'




# ===== 资料库（知识库） =====

def ensure_library_dir():
    if not os.path.isdir(LIBRARY_DIR):
        os.makedirs(LIBRARY_DIR)


def load_library_index():
    ensure_library_dir()
    if not os.path.exists(LIBRARY_INDEX):
        return []
    try:
        with open(LIBRARY_INDEX, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def save_library_index(index):
    ensure_library_dir()
    with open(LIBRARY_INDEX, 'w', encoding='utf-8') as f:
        json.dump(index, f, ensure_ascii=False, indent=2)


def _extract_text_pdf(path):
    try:
        import pdfplumber
        with pdfplumber.open(path) as pdf:
            parts = []
            for page in pdf.pages:
                txt = page.extract_text()
                if txt:
                    parts.append(txt)
            return '\n'.join(parts)
    except Exception:
        return ''


def _extract_text_docx(path):
    try:
        import docx
        doc = docx.Document(path)
        return '\n'.join([p.text for p in doc.paragraphs])
    except Exception:
        return ''


def extract_text(path, filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext in ('.txt', '.md', '.json', '.csv', '.log', '.py', '.js', '.html', '.css', '.xml'):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return ''
    if ext == '.pdf':
        return _extract_text_pdf(path)
    if ext == '.docx':
        return _extract_text_docx(path)
    return ''


def _file_type_label(filename):
    ext = os.path.splitext(filename)[1].lower()
    mapping = {
        '.txt': '文本', '.md': 'Markdown', '.json': 'JSON', '.csv': 'CSV',
        '.pdf': 'PDF', '.docx': 'Word', '.doc': 'Word',
        '.py': 'Python', '.js': 'JS', '.html': 'HTML', '.css': 'CSS',
        '.xml': 'XML', '.log': '日志', '.yml': 'YAML', '.yaml': 'YAML'
    }
    return mapping.get(ext, '文件')


def _format_size(size):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} GB'


def _make_preview(text, length=300):
    if not text:
        return ''
    t = re.sub(r'\s+', ' ', text).strip()
    return t[:length] + ('...' if len(t) > length else '')


def save_library_file(file_storage):
    ensure_library_dir()
    original = secure_filename(file_storage.filename or 'unknown')
    if not original:
        original = 'unknown'
    uid = str(uuid.uuid4())[:12]
    ext = os.path.splitext(original)[1]
    stored_name = uid + (ext or '')
    stored_path = os.path.join(LIBRARY_DIR, stored_name)
    file_storage.save(stored_path)

    # 若是 CSV 且包含 IP-姓名映射，自动导入身份库
    imported = 0
    if ext.lower() == '.csv':
        try:
            imported = skills.update_identity_db_from_csv(stored_path)
            if imported:
                print(f'[library] imported {imported} identity rows from {original}', flush=True)
        except Exception as e:
            print('[library] identity csv import failed:', e, flush=True)

    size = os.path.getsize(stored_path)
    content = extract_text(stored_path, original)
    preview = _make_preview(content)

    item = {
        'id': uid,
        'name': original,
        'stored_name': stored_name,
        'type': _file_type_label(original),
        'size': size,
        'size_human': _format_size(size),
        'uploaded_at': now_str(),
        'preview': preview,
        'has_content': bool(content),
        'content_length': len(content),
        'identity_imported': imported if ext.lower() == '.csv' else 0
    }
    index = load_library_index()
    index.append(item)
    # 同时保存原始文本，便于 AI 研判与搜索
    content_path = os.path.join(LIBRARY_DIR, uid + '.content.txt')
    try:
        with open(content_path, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception:
        pass
    save_library_index(index)
    return item


def delete_library_file(uid):
    index = load_library_index()
    item = next((x for x in index if x['id'] == uid), None)
    if not item:
        return False
    index = [x for x in index if x['id'] != uid]
    save_library_index(index)
    for suffix in ['', '.content.txt']:
        p = os.path.join(LIBRARY_DIR, item['stored_name'] if not suffix else (uid + suffix))
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    return True


def search_library(q):
    q = q.lower().strip()
    if not q:
        return load_library_index()
    results = []
    for item in load_library_index():
        if q in item.get('name', '').lower() or q in item.get('preview', '').lower():
            results.append(item)
            continue
        content_path = os.path.join(LIBRARY_DIR, item['id'] + '.content.txt')
        if os.path.exists(content_path):
            try:
                with open(content_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                if q in content.lower():
                    results.append(item)
            except Exception:
                pass
    return results


def get_library_content(uid):
    item = next((x for x in load_library_index() if x['id'] == uid), None)
    if not item:
        return None
    content_path = os.path.join(LIBRARY_DIR, uid + '.content.txt')
    if os.path.exists(content_path):
        try:
            with open(content_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return ''
    return extract_text(os.path.join(LIBRARY_DIR, item['stored_name']), item['name'])


def library_summary():
    index = load_library_index()
    return {
        'count': len(index),
        'names': [x['name'] for x in index[:20]]
    }




def parse_command(text):
    t = text.strip()
    if t.startswith('{') and t.endswith('}'):
        try:
            return json.loads(t)
        except Exception:
            pass
    return None


def execute_command(cmd):
    action = cmd.get('action')
    if action == 'block_ip':
        ip = cmd.get('ip')
        if not ip:
            return None, '缺少 IP'
        if skills.is_protected_ip(ip):
            return None, (f"拒绝封禁：{ip} 属于内网/受保护地址，处置动作已被硬校验拦截"
                          f"（如确需封禁内网靶机，设置环境变量 ALLOW_INTERNAL_BLOCK=1）")
        if not any(b['ip'] == ip for b in BLOCKED):
            record = {'ip': ip, 'reason': '智能助理封禁', 'time': now_str(), 'alarm': '-'}
            BLOCKED.append(record)
            db.upsert_blocked(record)
        for a in ALARMS:
            if a['src'] == ip and a['status'] != 'false_positive':
                db.update_alarm_status(a['id'], 'blocked')
        refresh_alarms()
        return {'ok': True}, '已封禁 IP ' + ip
    if action == 'unblock_ip':
        ip = cmd.get('ip')
        if not ip:
            return None, '缺少 IP'
        BLOCKED[:] = [b for b in BLOCKED if b['ip'] != ip]
        db.delete_blocked(ip)
        for a in ALARMS:
            if a['src'] == ip and a['status'] == 'blocked':
                db.update_alarm_status(a['id'], 'open')
        refresh_alarms()
        return {'ok': True}, '已解封 IP ' + ip
    if action == 'false_positive':
        alarm_id = cmd.get('id')
        if not alarm_id:
            return None, '缺少告警 ID'
        if db.get_alarm(alarm_id) is None:
            return None, '未找到告警 ' + alarm_id
        db.update_alarm_status(alarm_id, 'false_positive')
        refresh_alarms()
        return {'ok': True}, '已将告警 ' + alarm_id + ' 加入加白' 
    if action == 'close_alarm':
        alarm_id = cmd.get('id')
        if not alarm_id:
            return None, '缺少告警 ID'
        if db.get_alarm(alarm_id) is None:
            return None, '未找到告警 ' + alarm_id
        db.update_alarm_status(alarm_id, 'closed')
        refresh_alarms()
        return {'ok': True}, '已关闭告警 ' + alarm_id
    if action == 'xdr_pipeline':
        count = int(cmd.get('count', 5))
        cfg = load_xdr_config()
        missing = []
        if not cfg.get('xdr_base_url'):
            missing.append('xdr_base_url')
        has_auth_code = bool(cfg.get('xdr_auth_code'))
        has_aksk = bool(cfg.get('xdr_access_key')) and bool(cfg.get('xdr_secret_key'))
        if not has_auth_code and not has_aksk:
            missing.append('xdr_auth_code 或 (xdr_access_key + xdr_secret_key)')
        if missing:
            return None, 'XDR 配置不完整，缺少: ' + ', '.join(missing)
        active = next((c for c in load_model_configs() if c.get('active')), None)
        if not active:
            return None, '没有激活的模型，请在智能助理配置中启用一个模型'
        try:
            summary = _xdr_fetch_once(count=count, force_full=True)
            ok = summary.get('total_success', 0)
            total = summary.get('total_fetched', 0)
            return {'ok': True, 'summary': summary}, f'已完成 XDR 研判：成功 {ok}/{total} 条，结果已保存到 pipeline_result.json'
        except Exception as e:
            return None, 'XDR 研判失败: ' + str(e)
    return None, '未知操作 ' + action


def build_system_prompt():
    stats = {
        'total': len(ALARMS),
        'high': sum(1 for a in ALARMS if a['severity'] in ('critical', 'high')),
        'critical': sum(1 for a in ALARMS if a['severity'] == 'critical'),
        'open': sum(1 for a in ALARMS if a['status'] == 'open'),
        'false_positive': sum(1 for a in ALARMS if a['status'] == 'false_positive'),
        'blocked': len(BLOCKED)
    }
    alarms = [{
        'id': a['id'],
        'severity': a['severity'],
        'type': a['type'],
        'status': a['status'],
        'src': a['src'],
        'target': a['target'],
        'attck': a.get('attck', '')
    } for a in ALARMS[:20]]
    context = json.dumps({
        'stats': stats,
        'alarms': alarms,
        'blocked': [{'ip': b['ip'], 'reason': b.get('reason', '')} for b in BLOCKED],
        'assets': ASSETS
    }, ensure_ascii=False, indent=2)
    return (
        '你是安全运营智能助理，当前平台实时数据如下。请用中文简洁专业地回答。'
        '如果用户要求执行操作（封禁IP、解封IP、告警加白、关闭告警），请只输出一个 JSON 命令对象，不要附加其他文字。可用动作：\n另外，资料库中包含学生身份映射表（CSV，字段：ip,name,student_id,department）。当用户询问哪些学生/同学/终端中毒、感染或中病毒时，请根据告警中的 src IP 从资料库中查找对应学生姓名、学号、院系，并直接回答学生姓名。\n'
        '{"action":"block_ip","ip":"x.x.x.x"}\n'
        '{"action":"unblock_ip","ip":"x.x.x.x"}\n'
        '{"action":"false_positive","id":"ALT-20260821-001"}\n'
        '{"action":"close_alarm","id":"ALT-20260821-001"}\n\n'
        '平台数据：\n' + context +
        '\n\n资料库（可用于 AI 研判）：\n' +
        json.dumps(library_summary(), ensure_ascii=False, indent=2) +
        '\n\n学生身份映射表（来自资料库，字段 ip,name,student_id,department）：\n' +
        (_load_student_identity_text() or '（未找到学生身份映射表）') +
        '\n\n漏洞库（可用于 AI 研判）：\n' +
        json.dumps(vuln_updater.get_vulnerability_summary(), ensure_ascii=False, indent=2)
    )


@app.route('/api/config/models', methods=['GET', 'POST'])
def api_config_models():
    if request.method == 'GET':
        configs = load_model_configs()
        safe = []
        for c in configs:
            c2 = dict(c)
            c2['api_key'] = mask_key(c2.get('api_key', ''))
            safe.append(c2)
        return jsonify(safe)
    data = request.get_json(force=True) or {}
    if not data.get('id'):
        data['id'] = str(uuid.uuid4())[:8]
    configs = load_model_configs()
    updated = False
    for c in configs:
        if c['id'] == data['id']:
            # 编辑时如果未重新填写 API Key，保留原 Key，避免前端遮蔽后误清空
            if not data.get('api_key') and c.get('api_key'):
                data['api_key'] = c['api_key']
            c.update(data)
            updated = True
            break
    if not updated:
        configs.append(data)
    if data.get('active'):
        for c in configs:
            if c['id'] != data['id']:
                c['active'] = False
    save_model_configs(configs)
    return jsonify(data)


@app.route('/api/config/models/<id>', methods=['DELETE'])
def api_delete_model_config(id):
    configs = [c for c in load_model_configs() if c['id'] != id]
    save_model_configs(configs)
    return jsonify({'ok': True})


@app.route('/api/config/active_model', methods=['GET'])
def api_active_model():
    for c in load_model_configs():
        if c.get('active'):
            return jsonify(c)
    return jsonify({})




# ═══════════════════════════════════════════════════
# 技能配置与执行
# ═══════════════════════════════════════════════════

@app.route('/api/skills', methods=['GET', 'POST'])
def api_skills():
    if request.method == 'GET':
        return jsonify(skills.load_skills())
    data = request.get_json(force=True) or {}
    if not data.get('id'):
        data['id'] = str(uuid.uuid4())[:8]
    if not data.get('name') or not data.get('handler'):
        return jsonify({'error': '缺少 name 或 handler'}), 400
    configs = skills.load_skills()
    updated = False
    for c in configs:
        if c['id'] == data['id']:
            c.update(data)
            updated = True
            break
    if not updated:
        configs.append(data)
    skills.save_skills(configs)
    return jsonify(data)


@app.route('/api/skills/<id>', methods=['PUT', 'DELETE'])
def api_skill(id):
    configs = skills.load_skills()
    idx = next((i for i, c in enumerate(configs) if c['id'] == id), -1)
    if idx < 0:
        return jsonify({'error': 'skill not found'}), 404
    if request.method == 'DELETE':
        configs.pop(idx)
        skills.save_skills(configs)
        return jsonify({'ok': True})
    data = request.get_json(force=True) or {}
    configs[idx].update(data)
    skills.save_skills(configs)
    return jsonify(configs[idx])


@app.route('/api/skills/detect', methods=['POST'])
def api_skills_detect():
    data = request.get_json(force=True) or {}
    text = data.get('text', '')
    result = skills.detect_skill(text)
    return jsonify(result)


@app.route('/api/skills/<id>/invoke', methods=['POST'])
def api_skill_invoke(id):
    cfg = next((c for c in skills.load_skills() if c['id'] == id), None)
    if not cfg:
        return jsonify({'error': 'skill not found'}), 404
    if not cfg.get('enabled'):
        return jsonify({'error': 'skill disabled'}), 400
    params = request.get_json(force=True) or {}
    result = skills.execute_skill(cfg, params)
    if result.get('ok') and cfg.get('handler') == 'block_ip':
        global BLOCKED
        BLOCKED = db.load_blocked()
        refresh_alarms()
    return jsonify(result)


@app.route('/api/assistant/chat', methods=['POST'])
def api_assistant_chat():
    data = request.get_json(force=True) or {}
    messages = data.get('messages', [])
    # 技能优先：最后一条用户消息命中已启用技能时直接执行
    last_user = ''
    for m in reversed(messages):
        if m.get('role') == 'user':
            last_user = m.get('content', '')
            break
    app.logger.warning('[DEBUG chat] messages=%s last_user=%r', messages, last_user)
    if last_user:
        detected = skills.detect_skill(last_user)
        app.logger.warning('[DEBUG chat] detected=%s', detected)
        if detected.get('matched'):
            skill = detected['skill']
            params = detected.get('params', {})
            params['user_text'] = last_user
            app.logger.warning('[DEBUG chat] params=%s', params)
            result = skills.execute_skill(skill, params)
            app.logger.warning('[DEBUG chat] result_msg_start=%s', result.get('message', '')[:80])
            if result.get('ok') and skill.get('handler') == 'block_ip':
                global BLOCKED
                BLOCKED = db.load_blocked()
                refresh_alarms()
            return jsonify({
                'reply': result.get('message') or result.get('error') or '执行失败',
                'skill': skill['id'],
                'ok': result.get('ok', False),
                'result': result
            })
        elif detected.get('skill') and detected.get('missing'):
            return jsonify({
                'reply': '请提供 ' + '、'.join(detected['missing']) + ' 后再执行该技能。',
                'skill': detected['skill']['id'],
                'ok': False
            })
    active = next((c for c in load_model_configs() if c.get('active')), None)
    if not active:
        return jsonify({'error': '没有激活的模型，请在助手里配置并启用一个模型'}), 400
    system_prompt = build_system_prompt()
    full_messages = [{'role': 'system', 'content': system_prompt}] + messages
    try:
        provider = active.get('provider', 'openai')
        if provider == 'minimax':
            active.setdefault('base_url', 'https://api.minimaxi.chat/v1')
            active.setdefault('model', 'abab6.5s-chat')
        elif provider == 'kimi':
            active.setdefault('base_url', 'https://api.moonshot.cn/v1')
            active.setdefault('model', 'moonshot-v1-8k')
        reply = call_openai_compatible(active, full_messages)
    except requests.exceptions.HTTPError as e:
        body = ''
        try:
            body = e.response.text[:500]
        except Exception:
            pass
        print('[DEBUG] upstream error', e.response.status_code if e.response else 'N/A', body, flush=True)
        detail = str(e)
        try:
            detail = e.response.json().get('error', {}).get('message', detail)
        except Exception:
            try:
                detail = e.response.json().get('error', detail)
            except Exception:
                pass
        return jsonify({'error': detail}), 502
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        print('[DEBUG] upstream network error', str(e), flush=True)
        return jsonify({'error': '模型服务网络连接失败或超时：' + str(e)}), 504
    except Exception as e:
        print('[DEBUG] assistant chat exception', str(e), flush=True)
        return jsonify({'error': str(e)}), 500
    cmd = parse_command(reply)
    if cmd:
        result, msg = execute_command(cmd)
        if result:
            return jsonify({'reply': msg, 'command': cmd, 'ok': True})
        return jsonify({'reply': msg, 'command': cmd, 'ok': False}), 400
    return jsonify({'reply': reply})




def _load_student_identity_text():
    """动态从资料库中查找并加载学生身份映射表文本。"""
    try:
        index = load_library_index()
        for item in index:
            name = item.get('name', '').lower()
            if 'student_identity' in name or '学生身份' in name:
                uid = item.get('id')
                if not uid:
                    continue
                path = os.path.join(LIBRARY_DIR, uid + '.content.txt')
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        return f.read()
    except Exception as e:
        print('[student_identity] load error:', e)
    return ''


def _parse_student_from_context(ctx: dict, ip: str) -> dict:
    """从 knowledge_context 召回的资料库文本中解析 IP 对应的学生身份。"""
    for doc in ctx.get("library_matches", []):
        text = doc.get("text") or doc.get("preview") or ""
        for line in text.splitlines():
            line = line.strip()
            if not line or ip not in line:
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 4 and parts[0] == ip:
                return {"name": parts[1], "student_id": parts[2], "department": parts[3]}
    return {}


def resolve_infected_students():
    """查询终端中毒/恶意软件类告警，并通过资料库 IP->学生身份映射解析学生姓名。"""
    kc.clear_cache()
    # 命中这些关键词即视为终端感染/恶意软件告警
    malware_keywords = ["恶意", "病毒", "木马", "malware", "远控", "感染", "中毒", "可疑进程", "c2"]
    alarms = db.load_alarms()
    infected = []
    seen = set()
    for a in alarms:
        text = " ".join([
            a.get("name", ""),
            a.get("type", ""),
        ]).lower()
        if not any(k in text for k in malware_keywords):
            continue
        src_ip = a.get("src", "")
        if not src_ip or src_ip in seen:
            continue
        seen.add(src_ip)
        alert_data = {
            "message": "成功",
            "code": "Success",
            "data": {
                "srcIp": [src_ip],
                "dstIp": [a.get("target", "")],
                "description": a.get("description", ""),
                "alertName": a.get("name", ""),
            }
        }
        ctx = kc.build_knowledge_context(alert_data, top_library=10)
        student = _parse_student_from_context(ctx, src_ip)
        infected.append({
            "alarm_id": a["id"],
            "ip": src_ip,
            "name": a.get("name", ""),
            "type": a.get("type", ""),
            "student_name": student.get("name", ""),
            "student_id": student.get("student_id", ""),
            "department": student.get("department", ""),
        })
    return infected


@app.route('/api/assistant/infected_students', methods=['GET'])
def api_infected_students():
    return jsonify(resolve_infected_students())



@app.route('/api/library', methods=['GET'])
def api_library_list():
    return jsonify(load_library_index())


@app.route('/api/library/upload', methods=['POST'])
def api_library_upload():
    if 'file' not in request.files:
        return jsonify({'error': '未提供文件'}), 400
    f = request.files['file']
    if not f or not f.filename:
        return jsonify({'error': '未选择文件'}), 400
    try:
        item = save_library_file(f)
        return jsonify(item)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/library/<uid>')
def api_library_download(uid):
    item = next((x for x in load_library_index() if x['id'] == uid), None)
    if not item:
        return jsonify({'error': 'not found'}), 404
    return send_from_directory(LIBRARY_DIR, item['stored_name'], download_name=item['name'], as_attachment=True)


@app.route('/api/library/<uid>/content')
def api_library_content(uid):
    content = get_library_content(uid)
    if content is None:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'id': uid, 'content': content})


@app.route('/api/library/<uid>', methods=['DELETE'])
def api_library_delete(uid):
    if delete_library_file(uid):
        return jsonify({'ok': True})
    return jsonify({'error': 'not found'}), 404


@app.route('/api/library/search')
def api_library_search():
    q = request.args.get('q', '')
    return jsonify(search_library(q))


@app.route('/api/library/<uid>/analyze', methods=['POST'])
def api_library_analyze(uid):
    active = next((c for c in load_model_configs() if c.get('active')), None)
    if not active:
        return jsonify({'error': '没有激活的模型，请在助手里配置并启用一个模型'}), 400
    content = get_library_content(uid)
    if content is None:
        return jsonify({'error': '资料不存在'}), 404
    if not content.strip():
        return jsonify({'error': '该文件无法提取文本，无法 AI 研判'}), 400
    item = next((x for x in load_library_index() if x['id'] == uid), None)
    prompt = (
        '你是一位安全运营专家。请对以下资料进行专业研判，提炼核心要点、潜在风险、 actionable 建议。'
        '资料名称：' + (item['name'] if item else uid) + '\n\n资料内容：\n' + content[:12000]
    )
    try:
        messages = [{'role': 'system', 'content': prompt}]
        reply = call_openai_compatible(active, messages)
        return jsonify({'reply': reply})
    except Exception as e:
        return jsonify({'error': str(e)}), 502




# ═══════════════════════════════════════════════════
# 漏洞库（多源 CVE 更新）
# ═══════════════════════════════════════════════════

@app.route('/api/vulns/sources', methods=['GET'])
def api_vulns_sources():
    """列出支持的漏洞数据源。"""
    return jsonify(vuln_updater.get_available_sources())


@app.route('/api/vulns/update', methods=['POST'])
def api_vulns_update():
    """触发后台漏洞库更新。立即返回任务状态，实际更新在后台线程执行。"""
    data = request.get_json(force=True) or {}
    sources = data.get('sources')
    days = data.get('days')
    if sources is not None and not isinstance(sources, list):
        return jsonify({'error': 'sources 必须是字符串数组'}), 400
    if days is not None and not isinstance(days, int):
        return jsonify({'error': 'days 必须是整数'}), 400
    ok, info = _start_vuln_update(sources=sources, days=days)
    if not ok:
        return jsonify({'error': info}), 409
    return jsonify({'started': True, 'sources': info.get('sources'), 'days': info.get('days'), 'started_at': info.get('started_at')})


@app.route('/api/vulns/update/status', methods=['GET'])
def api_vulns_update_status():
    """获取当前后台漏洞库更新任务状态。"""
    return jsonify(_vuln_update_status())


@app.route('/api/vulns/scheduler/status', methods=['GET'])
def api_vulns_scheduler_status():
    """获取漏洞库自动更新调度器状态。调用前先看门狗自检。"""
    _ensure_vuln_scheduler_alive()
    return jsonify(_vuln_scheduler_public_status())


@app.route('/api/vulns/scheduler/config', methods=['GET'])
def api_vulns_scheduler_config_get():
    """读取漏洞库自动更新配置。"""
    return jsonify(_load_vuln_scheduler_config())


@app.route('/api/vulns/scheduler/config', methods=['POST'])
def api_vulns_scheduler_config_post():
    """保存漏洞库自动更新配置并立即生效。"""
    data = request.get_json(force=True) or {}
    cfg = _load_vuln_scheduler_config()
    if 'enabled' in data and isinstance(data['enabled'], bool):
        cfg['enabled'] = data['enabled']
    if 'interval_seconds' in data and isinstance(data['interval_seconds'], int) and data['interval_seconds'] >= 60:
        cfg['interval_seconds'] = data['interval_seconds']
    if 'selected_sources' in data and isinstance(data['selected_sources'], list):
        cfg['selected_sources'] = data['selected_sources']
    _save_vuln_scheduler_config(cfg)
    _apply_vuln_scheduler_config()
    return jsonify(cfg)


@app.route('/api/vulns/scheduler/restart', methods=['POST'])
def api_vulns_scheduler_restart():
    """手动触发调度器健康检查/重启。"""
    _ensure_vuln_scheduler_alive()
    return jsonify(_vuln_scheduler_public_status())


@app.route('/api/vulns/library', methods=['GET'])
def api_vulns_library():
    """列出已同步到本地的漏洞库文档。"""
    return jsonify(vuln_updater.list_vulnerability_library())


@app.route('/api/vulns/library/<uid>', methods=['GET'])
def api_vulns_library_download(uid):
    item = next((x for x in vuln_updater.list_vulnerability_library() if x['id'] == uid), None)
    if not item:
        return jsonify({'error': 'not found'}), 404
    return send_from_directory(LIBRARY_DIR, item['stored_name'], download_name=item['name'], as_attachment=True)


@app.route('/api/vulns/library/<uid>/content', methods=['GET'])
def api_vulns_library_content(uid):
    content = vuln_updater.get_vulnerability_content(uid)
    if content is None:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'id': uid, 'content': content})


@app.route('/api/vulns/library/<uid>', methods=['DELETE'])
def api_vulns_library_delete(uid):
    if vuln_updater.delete_vulnerability_document(uid):
        return jsonify({'ok': True})
    return jsonify({'error': 'not found'}), 404


@app.route('/api/vulns/library/<uid>/analyze', methods=['POST'])
def api_vulns_library_analyze(uid):
    """对漏洞库文档进行 AI 研判。"""
    active = next((c for c in load_model_configs() if c.get('active')), None)
    if not active:
        return jsonify({'error': '没有激活的模型，请在助手里配置并启用一个模型'}), 400
    content = vuln_updater.get_vulnerability_content(uid)
    if content is None:
        return jsonify({'error': '漏洞资料不存在'}), 404
    if not content.strip():
        return jsonify({'error': '该文件无法提取文本，无法 AI 研判'}), 400
    item = next((x for x in vuln_updater.list_vulnerability_library() if x['id'] == uid), None)
    prompt = (
        '你是一位安全漏洞分析专家。请对以下漏洞库资料进行专业研判，提炼：'
        '1) 新增/近期高危漏洞清单；2) 受影响产品/版本；3) 可利用性与在野利用情况；4) 处置建议（补丁、缓解、检测规则方向）。'
        '资料名称：' + (item['name'] if item else uid) + '\n\n资料内容：\n' + content[:12000]
    )
    try:
        messages = [{'role': 'system', 'content': prompt}]
        reply = call_openai_compatible(active, messages)
        return jsonify({'reply': reply})
    except Exception as e:
        return jsonify({'error': str(e)}), 502

@app.route('/api/vulns/daily-stats', methods=['GET'])
def api_vulns_daily_stats():
    '''返回漏洞库每日拉取数量，并关联告警 AI 研判匹配情况。'''
    try:
        return jsonify(vuln_stats_skill.build_daily_stats())
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ═══════════════════════════════════════════════════
# XDR 告警研判流水线
# ═══════════════════════════════════════════════════

XDR_CONFIG_FILE = os.path.join(CONFIG_DIR, 'xdr_config.json')


def load_xdr_config():
    if not os.path.isdir(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
    if not os.path.exists(XDR_CONFIG_FILE):
        return {}
    try:
        with open(XDR_CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_xdr_config(config):
    if not os.path.isdir(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
    with open(XDR_CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


@app.route('/api/xdr/config', methods=['GET', 'POST'])
def api_xdr_config():
    allowed = {'xdr_base_url', 'xdr_auth_code', 'xdr_access_key', 'xdr_secret_key', 'request_timeout'}
    sensitive = {'xdr_auth_code', 'xdr_access_key', 'xdr_secret_key'}
    if request.method == 'GET':
        cfg = load_xdr_config()
        safe = {k: cfg.get(k, '') for k in allowed}
        for k in sensitive:
            if safe.get(k):
                safe[k] = mask_key(safe[k])
        return jsonify(safe)
    data = request.get_json(force=True) or {}
    cfg = load_xdr_config()
    for key in allowed:
        val = data.get(key)
        if val is not None:
            # 编辑时若未重新填写密钥（返回掩码），保留原值
            if key in sensitive and cfg.get(key) and '****' in str(val):
                continue
            cfg[key] = val
    # 清理已废弃的 fastgpt 字段
    for old in ('fastgpt_endpoint', 'fastgpt_api_key'):
        cfg.pop(old, None)
    save_xdr_config(cfg)
    safe = {k: cfg.get(k, '') for k in allowed}
    for k in sensitive:
        if safe.get(k):
            safe[k] = mask_key(safe[k])
    return jsonify(safe)


@app.route('/api/xdr/pipeline', methods=['POST'])
def api_xdr_pipeline():
    data = request.get_json(force=True) or {}
    count = int(data.get('count', 5))
    output_path = data.get('output')
    cfg = load_xdr_config()
    missing = []
    if not cfg.get('xdr_base_url'):
        missing.append('xdr_base_url')
    has_auth_code = bool(cfg.get('xdr_auth_code'))
    has_aksk = bool(cfg.get('xdr_access_key')) and bool(cfg.get('xdr_secret_key'))
    if not has_auth_code and not has_aksk:
        missing.append('xdr_auth_code 或 (xdr_access_key + xdr_secret_key)')
    if missing:
        return jsonify({'error': 'XDR 配置不完整，缺少: ' + ', '.join(missing)}), 400
    active = next((c for c in load_model_configs() if c.get('active')), None)
    if not active:
        return jsonify({'error': '没有激活的模型，请在智能助理配置中启用一个模型'}), 400
    try:
        summary = _xdr_fetch_once(count=count, force_full=True)
        return jsonify(summary)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 502


@app.route('/api/xdr/ingest', methods=['POST'])
def api_xdr_ingest():
    """将已有的 pipeline_result.json 导入 MySQL 告警表"""
    data = request.get_json(force=True) or {}
    path = data.get('path') or '/private/tmp/pipeline_result.json'
    try:
        with open(path, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        db.insert_xdr_results(summary)
        refresh_alarms()
        return jsonify({'ok': True, 'count': summary.get('total_fetched', 0)})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 502


@app.route('/api/xdr/scheduler/status', methods=['GET'])
def api_xdr_scheduler_status():
    """查看 XDR 定时拉取调度器状态"""
    ok, reason = _can_run_xdr_pipeline()
    return jsonify({
        'running': _scheduler_state['running'],
        'interval_seconds': SCHEDULER_INTERVAL,
        'ready': ok,
        'reason': reason,
        'last_run_at': _scheduler_state['last_run_at'],
        'last_error': _scheduler_state['last_error'],
        'last_summary': _scheduler_state['last_summary'],
    })


# ═══════════════════════════════════════════════════
# XDR 定时拉取调度器
# ═══════════════════════════════════════════════════

SCHEDULER_INTERVAL = 60  # 秒
_scheduler_state = {
    'running': False,
    'thread': None,
    'last_run_at': None,
    'last_error': None,
    'last_summary': None,
}

_SCHEDULER_LOCK_FILE = os.path.join(os.path.dirname(__file__), '.xdr_scheduler.lock')


def _read_lock_pid():
    try:
        with open(_SCHEDULER_LOCK_FILE, 'r') as f:
            return int(f.read().strip())
    except Exception:
        return None


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _remove_scheduler_lock():
    try:
        if os.path.exists(_SCHEDULER_LOCK_FILE):
            os.remove(_SCHEDULER_LOCK_FILE)
    except Exception:
        pass


def _can_run_xdr_pipeline():
    """检查 XDR 配置与模型配置是否就绪"""
    cfg = load_xdr_config()
    if not cfg.get('xdr_base_url'):
        return False, 'XDR base_url 未配置'
    has_auth_code = bool(cfg.get('xdr_auth_code'))
    has_aksk = bool(cfg.get('xdr_access_key')) and bool(cfg.get('xdr_secret_key'))
    if not has_auth_code and not has_aksk:
        return False, 'XDR 认证信息未配置（连接码或 AK/SK 二选一）'
    active = next((c for c in load_model_configs() if c.get('active')), None)
    if not active:
        return False, '没有激活的 AI 模型'
    return True, None


def _xdr_fetch_once(count: int = 50, force_full: bool = False):
    """执行一次 XDR 拉取研判并写入数据库
    force_full=True 时忽略库中最大 update_time，直接拉最近 7 天，用于补齐历史遗漏
    """
    global ALARMS
    cfg = load_xdr_config()
    active = next((c for c in load_model_configs() if c.get('active')), None)
    from datetime import datetime, timezone, timedelta
    max_update = db.get_max_update_time()
    list_kwargs = {"order_by": "updateTime", "order": "desc"}
    if force_full or not max_update:
        list_kwargs["start_time"] = int((datetime.now(timezone.utc) - timedelta(days=7)).timestamp())
    else:
        list_kwargs["start_time"] = int(max_update.timestamp())
    skip_uuids = db.get_judged_uuids()
    summary = run_pipeline(cfg, active, count=count, list_alerts_kwargs=list_kwargs,
                           skip_uuids=skip_uuids, progress_callback=lambda x: None)
    db.insert_xdr_results(summary)
    refresh_alarms()
    return summary


def _scheduler_loop():
    """后台守护线程：每分钟尝试拉取一次真实 XDR 告警"""
    while _scheduler_state['running']:
        try:
            ok, reason = _can_run_xdr_pipeline()
            if ok:
                summary = _xdr_fetch_once(count=50, force_full=not _scheduler_state['last_run_at'])
                _scheduler_state['last_run_at'] = now_str()
                _scheduler_state['last_summary'] = summary
                _scheduler_state['last_error'] = None
            else:
                _scheduler_state['last_error'] = reason
        except Exception as e:
            import traceback
            traceback.print_exc()
            _scheduler_state['last_error'] = f'{type(e).__name__}: {e}'
            _scheduler_state['last_run_at'] = now_str()
        # 按固定间隔休眠，避免任务执行时间导致漂移
        for _ in range(SCHEDULER_INTERVAL):
            if not _scheduler_state['running']:
                break
            time.sleep(1)


def start_xdr_scheduler():
    """启动 XDR 定时拉取调度器（仅在主进程中启动一次）"""
    if _scheduler_state['running']:
        return
    # 通过 PID 锁保证一个机器上只有一个调度器进程在跑
    lock_pid = _read_lock_pid()
    if lock_pid and lock_pid != os.getpid() and _pid_alive(lock_pid):
        return
    try:
        with open(_SCHEDULER_LOCK_FILE, 'w') as f:
            f.write(str(os.getpid()))
        atexit.register(_remove_scheduler_lock)
    except Exception:
        pass
    _scheduler_state['running'] = True
    _scheduler_state['thread'] = threading.Thread(target=_scheduler_loop, daemon=True)
    _scheduler_state['thread'].start()
    print('[scheduler] XDR 定时拉取已启动，间隔 60 秒')


def stop_xdr_scheduler():
    _scheduler_state['running'] = False
    t = _scheduler_state.get('thread')
    if t and t.is_alive():
        t.join(timeout=2)


# 测试/离线导入时设置 DISABLE_XDR_SCHEDULER=1 可跳过后台调度线程（默认照常启动）
if os.environ.get('DISABLE_XDR_SCHEDULER', '') != '1':
    start_xdr_scheduler()


vuln_scheduler.apply_config()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

