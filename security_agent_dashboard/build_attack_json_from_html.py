#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build attack_subtechniques.json from the cached MITRE ATT&CK v19 flat matrix.

The flat matrix in /tmp/attack_v19.html contains all 222 parent techniques and
their tactic columns. Sub-techniques are loaded dynamically and not present in the
static HTML. To add sub-techniques later, merge a separate JSON into the list.
"""
import json
import re
from pathlib import Path
from bs4 import BeautifulSoup

HTML = '/tmp/attack_v19.html'
DICT = '/tmp/attack_dict.json'
OUT = Path('/Users/zhangshanshan/Documents/AI_xinyu/security_agent_dashboard/static/data/attack_subtechniques.json')

TACTIC_ORDER = [
    'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
    'Persistence', 'Privilege Escalation', 'Stealth', 'Defense Impairment',
    'Credential Access', 'Discovery', 'Lateral Movement', 'Collection',
    'Command and Control', 'Exfiltration', 'Impact',
]

EXTRA_PHRASES = {
    'OS Credential Dumping': 'OS 凭证转储',
    'Valid Accounts': '有效账户',
    'Active Scanning': '主动扫描',
    'Living Off The Land': '离地生存',
    'Data Obfuscation': '数据混淆',
    'Dynamic Data Exchange': '动态数据交换',
    'Server Software Component': '服务器软件组件',
    'Virtual Private Network': '虚拟专用网络',
    'Exfiltration Over Web Service': '通过 Web 服务外渗',
    'Exfiltration Over Other Network Medium': '通过其他网络介质外渗',
    'Exfiltration Over Alternative Protocol': '通过替代协议外渗',
    'Browser Session Hijacking': '浏览器会话劫持',
    'Cloud Infrastructure Discovery': '云基础设施发现',
    'Cloud Service Dashboard': '云服务面板',
    'Cloud Service Discovery': '云服务发现',
    'Domain Policy Modification': '域策略修改',
    'File and Directory Permissions Modification': '文件与目录权限修改',
    'Hijack Execution Flow': '劫持执行流',
    'Input Capture': '输入捕获',
    'Inter-Process Communication': '进程间通信',
    'Network Boundary Bridging': '网络边界桥接',
    'Non-Application Layer Protocol': '非应用层协议',
    'Obtain Capabilities': '获取能力',
    'Office Application Startup': 'Office 应用启动',
    'Permission Groups Discovery': '权限组发现',
    'Pre-OS Boot': '预启动执行',
    'Process Injection': '进程注入',
    'Reflective Code Loading': '反射式代码加载',
    'Remote Service Session Hijacking': '远程服务会话劫持',
    'Scheduled Task/Job': '计划任务/作业',
    'Search Open Websites/Domains': '搜索公开网站/域名',
    'Search Open Technical Databases': '搜索公开技术数据库',
    'Software Deployment Tools': '软件部署工具',
    'Supply Chain Compromise': '供应链入侵',
    'System Information Discovery': '系统信息发现',
    'System Location Discovery': '系统位置发现',
    'System Network Configuration Discovery': '系统网络配置发现',
    'System Network Connections Discovery': '系统网络连接发现',
    'System Owner/User Discovery': '系统所有者/用户发现',
    'System Service Discovery': '系统服务发现',
    'Trusted Relationship': '信任关系',
    'Unused/Unsupported Cloud Regions': '未使用/不受支持的云区域',
    'User Execution': '用户执行',
    'Windows Management Instrumentation': 'WMI',
    'Container Administration Command': '容器管理命令',
    'Container and Resource Discovery': '容器与资源发现',
    'Data from Configuration Repository': '来自配置仓库的数据',
    'Data from Information Repositories': '来自信息仓库的数据',
    'Data from Local System': '来自本地系统的数据',
    'Data from Network Shared Drive': '来自网络共享驱动器的数据',
    'Data from Removable Media': '来自可移动介质的数据',
    'Data Manipulation': '数据操纵',
    'Data Staged': '数据暂存',
    'Endpoint Denial of Service': '终端拒绝服务',
    'Event Triggered Execution': '事件触发执行',
    'Exploit Public-Facing Application': '利用面向公众的应用',
    'File and Directory Discovery': '文件与目录发现',
    'File and Directory Permissions Modification': '文件与目录权限修改',
    'Hide Artifacts': '隐藏痕迹',
    'Impair Defenses': '削弱防御',
    'Indicator Removal on Host': '主机指标清除',
    'Indirect Command Execution': '间接命令执行',
    'Ingress Tool Transfer': '入口工具传输',
    'Internal Spearphishing': '内部鱼叉钓鱼',
    'Masquerading': '伪装',
    'Modify Authentication Process': '修改认证过程',
    'Modify Registry': '修改注册表',
    'Modify System Image': '修改系统镜像',
    'Network Service Discovery': '网络服务发现',
    'Network Service Scanning': '网络服务扫描',
    'Network Sniffing': '网络嗅探',
    'Password Policy Discovery': '密码策略发现',
    'Phishing for Information': '钓鱼收集信息',
    'Protocol Tunneling': '协议隧道',
    'Proxy': '代理',
    'Query Registry': '查询注册表',
    'Remote Data Staging': '远程数据暂存',
    'Remote System Discovery': '远程系统发现',
    'Resource Hijacking': '资源劫持',
    'Rogue Domain Controller': '流氓域控制器',
    'Search Closed Sources': '搜索封闭来源',
    'Search Open Websites/Domains': '搜索公开网站/域名',
    'Server Software Component': '服务器软件组件',
    'Service Stop': '服务停止',
    'Steal Web Session Cookie': '窃取 Web 会话 Cookie',
    'System Shutdown/Reboot': '系统关机/重启',
    'Traffic Signaling': '流量信令',
    'Use Alternate Authentication Material': '使用替代认证材料',
    'Video Capture': '视频捕获',
}

EXTRA_WORDS = {
    'Acquire': '获取', 'Access': '访问', 'Alternative': '替代', 'Antivirus': '杀毒软件',
    'Application': '应用', 'Artifact': '痕迹', 'Artifacts': '痕迹', 'Authentication': '认证',
    'Automated': '自动化', 'Binary': '二进制', 'Boot': '启动', 'Boundary': '边界',
    'Bridge': '桥接', 'Browser': '浏览器', 'Brute': '暴力', 'Capture': '捕获',
    'Channel': '通道', 'Channels': '通道', 'Chat': '聊天', 'Clipboard': '剪贴板', 'Cloud': '云', 'Code': '代码', 'Command': '命令',
    'Communication': '通信', 'Component': '组件', 'Compromise': '入侵', 'Config': '配置',
    'Configuration': '配置', 'Connection': '连接', 'Container': '容器', 'Content': '内容',
    'Cookie': 'Cookie', 'Credentials': '凭证', 'Credential': '凭证', 'Damage': '破坏',
    'Data': '数据', 'DCSync': 'DCSync', 'Defenses': '防御', 'Deployment': '部署',
    'Detection': '检测', 'Device': '设备', 'Directory': '目录', 'Disable': '禁用',
    'Discovery': '发现', 'Disk': '磁盘', 'DLL': 'DLL', 'Domain': '域', 'Drive': '驱动器',
    'Dumping': '转储', 'Endpoint': '终端', 'Environment': '环境', 'Evasion': '规避',
    'Event': '事件', 'Evade': '规避', 'Exchange': 'Exchange', 'Execution': '执行',
    'Exfiltration': '外渗', 'Exploit': '利用', 'Exploitation': '利用', 'External': '外部',
    'Face': '面部', 'Fallback': '备用', 'File': '文件', 'Firewall': '防火墙', 'Firmware': '固件',
    'Force': '破解', 'Generate': '生成', 'Graphical': '图形', 'Group': '组', 'Groups': '组',
    'Handler': '处理程序', 'Hijack': '劫持', 'Hijacking': '劫持', 'Hide': '隐藏',
    'Hiding': '隐藏', 'Host': '主机', 'Image': '镜像', 'Impair': '削弱', 'Impairment': '削弱',
    'Indicator': '指标', 'Indirect': '间接', 'Information': '信息', 'Initial': '初始',
    'Injection': '注入', 'Input': '输入', 'Interactive': '交互式', 'Internal': '内部',
    'Internet': '互联网', 'Interpreter': '解释器', 'Kernel': '内核', 'Key': '密钥',
    'Keylogging': '键盘记录', 'LAN': 'LAN', 'Layer': '层', 'Library': '库', 'Link': '链接',
    'Linux': 'Linux', 'Local': '本地', 'Logon': '登录', 'Logs': '日志', 'MAC': 'MAC',
    'Machine': '机器', 'Mail': '邮件', 'Malicious': '恶意', 'Manager': '管理器',
    'Manipulate': '操纵', 'Manipulation': '操纵', 'Masquerade': '伪装', 'Memory': '内存',
    'Message': '消息', 'MITM': '中间人', 'Mobile': '移动', 'Modify': '修改', 'Module': '模块',
    'Network': '网络', 'Non-Standard': '非标准', 'Obfuscate': '混淆', 'Obfuscation': '混淆',
    'Office': 'Office', 'Operating': '操作系统', 'OS': '操作系统', 'Other': '其他', 'Owner': '所有者',
    'Pass': '传递', 'Password': '密码', 'Path': '路径', 'Payload': '载荷', 'Permission': '权限',
    'Permissions': '权限', 'Persistence': '持久化', 'Phishing': '钓鱼', 'Policy': '策略',
    'Port': '端口', 'Pre-OS': '预启动', 'Private': '私有', 'Privilege': '权限', 'Process': '进程',
    'Protocol': '协议', 'Proxy': '代理', 'Public-Facing': '面向公众', 'Query': '查询',
    'Reboot': '重启', 'Reflective': '反射式', 'Regions': '区域', 'Registry': '注册表',
    'Relationship': '关系', 'Remote': '远程', 'Removal': '清除', 'Remove': '清除',
    'Repository': '仓库', 'Resource': '资源', 'Response': '响应', 'Reversible': '可逆',
    'Rogue': '流氓', 'Rootkit': 'Rootkit', 'Runtime': '运行时', 'Scanning': '扫描',
    'Screen': '屏幕', 'Script': '脚本', 'Search': '搜索', 'Security': '安全',
    'Server': '服务器', 'Service': '服务', 'Session': '会话', 'Shared': '共享',
    'Shutdown': '关机', 'Side': '侧', 'Signaling': '信令', 'SMB': 'SMB', 'Software': '软件',
    'Source': '来源', 'Spearphishing': '鱼叉钓鱼', 'SSH': 'SSH', 'SSL/TLS': 'SSL/TLS',
    'Staging': '暂存', 'Standard': '标准', 'Static': '静态', 'Steganography': '隐写术',
    'Stop': '停止', 'Storage': '存储', 'Subvert': '颠覆', 'Supply': '供应链', 'System': '系统',
    'Targeted': '定向', 'Task': '任务', 'Technique': '技术', 'Template': '模板',
    'Ticket': '票据', 'Tools': '工具', 'Traffic': '流量', 'Transfer': '传输',
    'Triggered': '触发', 'Trusted': '受信任', 'Tunneling': '隧道', 'User': '用户',
    'Valid': '有效', 'Video': '视频', 'Virtual': '虚拟', 'VPN': 'VPN', 'Web': 'Web',
    'Webshell': 'WebShell', 'WMI': 'WMI', 'Window': '窗口', 'Windows': 'Windows',
    'and': '与', 'or': '或', 'of': '的', 'to': '至', 'in': '于', 'for': '用于',
    'on': '于', 'from': '来自', 'with': '使用', 'via': '通过', 'over': '通过',
    'into': '进入', 'using': '使用',
    'And': '与', 'Or': '或', 'Of': '的', 'To': '至', 'In': '于', 'For': '用于',
    'On': '于', 'From': '来自', 'With': '使用', 'Via': '通过', 'Over': '通过',
    'Into': '进入', 'Using': '使用',
}


def load_translations():
    with open(DICT, 'r', encoding='utf-8') as f:
        d = json.load(f)
    phrases = {**d.get('PHRASES', {}), **EXTRA_PHRASES}
    words = {**d.get('WORDS', {}), **EXTRA_WORDS}
    return d.get('TACTIC_MAP', {}), phrases, words, d.get('SPECIAL', {})


def normalize_text(s):
    s = s.replace('&nbsp;', ' ')
    s = re.sub(r'\s+', ' ', s)
    s = re.sub(r'<[^>]+>', '', s)
    s = re.sub(r'\s*\(\d+\)\s*$', '', s)
    return s.strip()


def translate(name, tactic_map, phrases, words, special):
    if name in special:
        return special[name]
    for eng, chn in sorted(phrases.items(), key=lambda x: -len(x[0])):
        name = name.replace(eng, chn)
    tokens = re.split(r'(\s+|[,/:;()])', name)
    out = []
    for tok in tokens:
        if tok in words:
            out.append(words[tok])
        elif re.match(r'^T\d+', tok) or re.match(r'^[A-Z]+$', tok) or re.match(r'^v?\d+(\.\d+)?$', tok):
            out.append(tok)
        else:
            out.append(tok)
    zh = ''.join(out).strip()
    # remove spaces between CJK characters
    zh = re.sub(r'([\u4e00-\u9fff])\s+([\u4e00-\u9fff])', r'\1\2', zh)
    zh = re.sub(r'\s+', ' ', zh)
    return zh or name


def tech_id_from_href(href):
    m = re.search(r'/versions/v19/techniques/(T\d+(?:\.\d+)?)', href)
    return m.group(1) if m else None


def main():
    tactic_map, phrases, words, special = load_translations()

    with open(HTML, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f.read(), 'html.parser')

    flat = soup.find('table', class_='matrix flat')
    if not flat:
        raise RuntimeError('未找到 matrix flat 表格')

    thead = flat.find('thead')
    tactic_cols = []
    if thead:
        for td in thead.find_all('td', class_='tactic name'):
            a = td.find('a')
            en = a.get_text(strip=True) if a else td.get_text(strip=True)
            tactic_cols.append(tactic_map.get(en, en))

    tbody = flat.find('tbody')
    matrix_row = tbody.find('tr') if tbody else None
    tds = matrix_row.find_all('td', class_='tactic', recursive=False) if matrix_row else []

    entries = {}

    for idx, td in enumerate(tds):
        if idx >= len(tactic_cols):
            continue
        tactic = tactic_cols[idx]
        # flat matrix: each tactic column contains div.technique-cell and table.supertechnique
        for cell in td.find_all(['div'], class_='technique-cell'):
            a = cell.find('a', href=re.compile(r'/versions/v19/techniques/T'))
            if not a:
                continue
            tech_id = tech_id_from_href(a.get('href', ''))
            tech_name = normalize_text(a.get_text())
            if not tech_id or not tech_name or '.' in tech_id:
                continue
            if tech_id not in entries:
                zh = translate(tech_name, tactic_map, phrases, words, special)
                entries[tech_id] = {
                    'id': tech_id, 'name': tech_name, 'nameZh': zh,
                    'tactics': set(), 'parentId': tech_id,
                    'parentName': tech_name, 'parentNameZh': zh,
                }
            entries[tech_id]['tactics'].add(tactic)

    result = []
    for tid in sorted(entries.keys()):
        e = entries[tid]
        ordered = [t for t in TACTIC_ORDER if t in e['tactics']]
        ordered += sorted([t for t in e['tactics'] if t not in TACTIC_ORDER])
        result.append({
            'id': e['id'], 'name': e['name'], 'nameZh': e['nameZh'],
            'tactics': ordered, 'parentId': e['parentId'],
            'parentName': e['parentName'], 'parentNameZh': e['parentNameZh'],
        })

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f'已写入 {OUT}，共 {len(result)} 条父技术项。')


if __name__ == '__main__':
    main()
