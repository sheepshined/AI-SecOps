#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parse /tmp/attack_v19.html and write enriched attack_subtechniques.json."""
import json
import re
from bs4 import BeautifulSoup

HTML = '/tmp/attack_v19.html'
OUT = '/Users/zhangshanshan/Documents/AI_xinyu/security_agent_dashboard/static/data/attack_subtechniques.json'

TACTIC_MAP = {
    'Reconnaissance': '侦察', 'Resource Development': '资源开发', 'Initial Access': '初始访问',
    'Execution': '执行', 'Persistence': '持久化', 'Privilege Escalation': '权限提升',
    'Stealth': '隐藏痕迹', 'Defense Impairment': '防御削弱', 'Credential Access': '凭证访问',
    'Discovery': '发现', 'Lateral Movement': '横向移动', 'Collection': '收集',
    'Command and Control': '命令与控制', 'Exfiltration': '外渗', 'Impact': '影响',
}

PHRASES = {
    'Application Layer Protocol': '应用层协议',
    'Command and Scripting Interpreter': '命令与脚本解释器',
    'Domain Controller': '域控制器',
    'Group Policy': '组策略',
    'Man-in-the-Middle': '中间人',
    'Network Device': '网络设备',
    'Network Share': '网络共享',
    'Operating System': '操作系统',
    'Remote Desktop': '远程桌面',
    'Remote Services': '远程服务',
    'Security Account Manager': '安全账户管理器',
    'Social Engineering': '社会工程',
    'Spearphishing Attachment': '鱼叉钓鱼附件',
    'Spearphishing Link': '鱼叉钓鱼链接',
    'Supply Chain': '供应链',
    'Symbolic Link': '符号链接',
    'Web Protocol': 'Web 协议',
    'Web Shell': 'Web Shell',
    'Windows Command': 'Windows 命令',
    'Windows Management Instrumentation': 'WMI',
    'Windows Service': 'Windows 服务',
}

WORDS = {
    'Access': '访问', 'Account': '账户', 'Active': '主动', 'AD': 'AD',
    'Admin': '管理员', 'Administrator': '管理员', 'Application': '应用',
    'Archive': '归档', 'Audio': '音频', 'Authentication': '认证',
    'Automated': '自动化', 'Backup': '备份', 'Binary': '二进制', 'BITS': 'BITS',
    'Bluetooth': '蓝牙', 'Boot': '启动', 'Border': '边界', 'Browser': '浏览器',
    'Brute': '暴力', 'Force': '破解', 'Buffer': '缓冲', 'Bypass': '绕过',
    'C2': 'C2', 'Cached': '缓存', 'Certificate': '证书', 'Change': '变更',
    'Chat': '聊天', 'Client': '客户端', 'Clipboard': '剪贴板', 'Cloud': '云',
    'Code': '代码', 'Command': '命令', 'Communication': '通信', 'Component': '组件',
    'COM': 'COM', 'Compromise': '入侵', 'Concealment': '隐藏', 'Config': '配置',
    'Configuration': '配置', 'Connection': '连接', 'Container': '容器', 'Content': '内容',
    'Cookie': 'Cookie', 'Copy': '复制', 'Credentials': '凭据', 'Cryptocurrency': '加密货币',
    'DCSync': 'DCSync', 'Data': '数据', 'Database': '数据库', 'Debug': '调试',
    'Decode': '解码', 'Default': '默认', 'Delete': '删除', 'Denial': '拒绝',
    'Deployment': '部署', 'Device': '设备', 'Directory': '目录', 'Disable': '禁用',
    'Discover': '发现', 'Discovery': '发现', 'Disk': '磁盘', 'DLL': 'DLL',
    'DNS': 'DNS', 'Domain': '域', 'Download': '下载', 'Dynamic': '动态',
    'Egress': '出口', 'Email': '邮件', 'Encode': '编码', 'Encrypt': '加密',
    'Encryption': '加密', 'Endpoint': '终端', 'Environment': '环境', 'Error': '错误',
    'Event': '事件', 'Evade': '规避', 'Evasion': '规避', 'Excel': 'Excel',
    'Exchange': 'Exchange', 'Execution': '执行', 'Exploit': '利用', 'External': '外部',
    'Exfiltration': '外渗', 'Face': '面部', 'Fake': '伪造', 'File': '文件',
    'Filesystem': '文件系统', 'Filter': '过滤', 'Firewall': '防火墙', 'Firmware': '固件',
    'Flash': 'Flash', 'Foreground': '前台', 'FTP': 'FTP', 'Gateway': '网关',
    'Gather': '收集', 'Group': '组', 'GUI': 'GUI', 'Handle': '句柄',
    'Hardcoded': '硬编码', 'Hardware': '硬件', 'Hash': '哈希', 'HCR': 'HCR',
    'Hidden': '隐藏', 'Hiding': '隐藏', 'Hijack': '劫持', 'HMAC': 'HMAC',
    'Hook': '钩子', 'HTTP': 'HTTP', 'HTTPS': 'HTTPS', 'ICMP': 'ICMP',
    'Identity': '身份', 'Image': '镜像', 'Impair': '削弱', 'Impersonation': '伪装',
    'Indicator': '指标', 'Indirect': '间接', 'Information': '信息', 'Ingress': '入口',
    'Input': '输入', 'Install': '安装', 'Internal': '内部', 'Internet': '互联网',
    'Inter-Process': '进程间', 'Interpreter': '解释器', 'Intranet': '内网',
    'Kerberos': 'Kerberos', 'Key': '密钥', 'Keyboard': '键盘', 'Keychain': '钥匙串',
    'Keylogger': '键盘记录器', 'Lateral': '横向', 'LDAP': 'LDAP', 'Library': '库',
    'Link': '链接', 'Linux': 'Linux', 'LLMNR': 'LLMNR', 'Local': '本地',
    'Log': '日志', 'Logon': '登录', 'LSASS': 'LSASS', 'LSA': 'LSA', 'MAC': 'MAC',
    'Machine': '机器', 'Mail': '邮件', 'Malicious': '恶意', 'Masquerade': '伪装',
    'Memory': '内存', 'Message': '消息', 'Mimikatz': 'Mimikatz', 'MITM': 'MITM',
    'Modify': '修改', 'Module': '模块', 'Monitor': '监控', 'Mount': '挂载',
    'Mouse': '鼠标', 'Msiexec': 'Msiexec', 'Multi-Factor': '多因素', 'Named': '命名',
    'Pipe': '管道', 'NBNS': 'NBNS', 'NDS': 'NDS', 'Network': '网络', 'New': '新',
    'NFS': 'NFS', 'NTLM': 'NTLM', 'NTDS': 'NTDS', 'Obfuscate': '混淆',
    'Obfuscation': '混淆', 'Obtain': '获取', 'Office': 'Office', 'One-Way': '单向',
    'Open': '打开', 'OS': 'OS', 'Outlook': 'Outlook', 'Pass': '传递',
    'Password': '密码', 'Path': '路径', 'Payload': '载荷', 'Permission': '权限',
    'Persistence': '持久化', 'Phishing': '钓鱼', 'Phone': '电话', 'Plist': 'Plist',
    'Policy': '策略', 'Port': '端口', 'Portable': '便携', 'PowerShell': 'PowerShell',
    'Print': '打印', 'Private': '私有', 'Privilege': '权限', 'Process': '进程',
    'Proc': '进程', 'Protocol': '协议', 'Proxy': '代理', 'Python': 'Python',
    'Query': '查询', 'RAS': 'RAS', 'RDP': 'RDP', 'Registry': '注册表',
    'Remote': '远程', 'Remove': '删除', 'Replicate': '复制', 'Request': '请求',
    'Response': '响应', 'Revert': '恢复', 'Rootkit': 'Rootkit', 'Route': '路由',
    'Run': '运行', 'SAML': 'SAML', 'SAM': 'SAM', 'Scan': '扫描', 'Scanning': '扫描',
    'Screen': '屏幕', 'Script': '脚本', 'Scripting': '脚本', 'Security': '安全',
    'Server': '服务器', 'Service': '服务', 'Session': '会话', 'Set': '设置',
    'Share': '共享', 'Shared': '共享', 'Shell': 'Shell', 'Shortcut': '快捷方式',
    'SMB': 'SMB', 'SMTP': 'SMTP', 'SNMP': 'SNMP', 'Software': '软件',
    'Source': '源', 'SSH': 'SSH', 'SSL/TLS': 'SSL/TLS', 'SSL': 'SSL', 'TLS': 'TLS',
    'Staging': '暂存', 'Standard': '标准', 'Startup': '启动项', 'Steal': '窃取',
    'Steganography': '隐写术', 'Stored': '存储', 'Subvert': '颠覆', 'Supply': '供应链',
    'Symbolic': '符号', 'System': '系统', 'Table': '表', 'Target': '目标',
    'Targeted': '定向', 'Task': '任务', 'TCP': 'TCP', 'Template': '模板',
    'Ticket': '票据', 'Time': '时间', 'Token': '令牌', 'Tool': '工具',
    'Traffic': '流量', 'Transfer': '传输', 'Trap': '陷阱', 'Trusted': '受信任',
    'Two-Factor': '双因素', 'UAC': 'UAC', 'USB': 'USB', 'User': '用户',
    'Utility': '工具', 'Valid': '有效', 'Victim': '受害者', 'Video': '视频',
    'Virtual': '虚拟', 'VNC': 'VNC', 'Volume': '卷', 'Vulnerability': '漏洞',
    'Web': 'Web', 'Website': '网站', 'Wi-Fi': 'Wi-Fi', 'Winlogon': 'Winlogon',
    'WMI': 'WMI', 'Windows': 'Windows', 'Wireless': '无线', 'Word': 'Word',
    'Wordlist': '字典', 'Write': '写入', 'XSL': 'XSL', 'and': '与', 'or': '或',
    'of': '的', 'to': '至', 'in': '于', 'for': '用于', 'on': '于', 'from': '来自',
    'with': '使用', 'via': '通过', 'over': '通过', 'into': '进入', 'using': '使用',
    'And': '与', 'Or': '或', 'Of': '的', 'To': '至', 'In': '于', 'For': '用于',
    'On': '于', 'From': '来自', 'With': '使用', 'Via': '通过', 'Over': '通过',
    'Into': '进入', 'Using': '使用',
}

SPECIAL = {
    'T1071.001': '应用层协议：Web 协议',
    'T1071.002': '应用层协议：文件传输协议',
    'T1071.003': '应用层协议：DNS',
    'T1071.004': '应用层协议：邮件协议',
    'T1059.001': '命令与脚本解释器：PowerShell',
    'T1059.003': '命令与脚本解释器：Windows 命令 Shell',
    'T1059.005': '命令与脚本解释器：Visual Basic',
    'T1059.007': '命令与脚本解释器：JavaScript',
    'T1003.001': 'OS 凭证转储：LSASS 内存',
    'T1003.002': 'OS 凭证转储：SAM',
    'T1003.003': 'OS 凭证转储：NTDS',
    'T1003.004': 'OS 凭证转储：LSA 密钥',
    'T1003.005': 'OS 凭证转储：缓存域凭证',
    'T1003.006': 'OS 凭证转储：DCSync',
    'T1003.007': 'OS 凭证转储：Proc 文件系统',
    'T1003.008': 'OS 凭证转储：/etc/passwd 与 /etc/shadow',
    'T1110': '暴力破解',
    'T1110.001': '暴力破解：密码猜测',
    'T1110.002': '暴力破解：密码喷洒',
    'T1110.003': '暴力破解：密码碰撞',
    'T1110.004': '暴力破解：凭证填充',
    'T1498': '网络拒绝服务',
    'T1498.001': '网络拒绝服务：直接洪水',
    'T1498.002': '网络拒绝服务：反射放大',
    'T1078': '有效账户',
    'T1041': '通过 C2 通道渗出',
    'T1021.002': '远程服务：SMB/Windows 管理共享',
    'T1505.003': 'Web Shell',
    'T1091': '可复制到可移动媒体',
    'T1566.001': '钓鱼：鱼叉钓鱼附件',
    'T1053': '计划任务/作业',
}

def normalize_text(s):
    s = s.replace('&nbsp;', ' ')
    s = re.sub(r'\s+', ' ', s)
    s = re.sub(r'<[^>]+>', '', s)
    s = re.sub(r'\s*\(\d+\)\s*$', '', s)
    return s.strip()

def tech_id_from_href(href):
    m = re.search(r'/versions/v19/techniques/(T\d+(?:\.\d+)?)', href)
    return m.group(1) if m else None

def translate(name):
    if not name:
        return name
    for eng, chn in sorted(PHRASES.items(), key=lambda x: -len(x[0])):
        name = name.replace(eng, chn)
    tokens = re.split(r'(\s+|[,/:;()])', name)
    out = []
    for tok in tokens:
        if tok in WORDS:
            out.append(WORDS[tok])
        elif re.match(r'^T\d+', tok) or re.match(r'^[A-Z]+$', tok) or re.match(r'^v?\d+(\.\d+)?$', tok):
            out.append(tok)
        else:
            out.append(tok)
    zh = ''.join(out).strip()
    zh = re.sub(r'\s+', ' ', zh)
    return zh or name

def main():
    with open(HTML, 'r', encoding='utf-8') as f:
        soup = BeautifulSoup(f.read(), "html.parser")

    matrix_table = soup.find('table', class_='matrix side')
    if not matrix_table:
        print('未找到矩阵表格')
        return

    thead = matrix_table.find('thead')
    tactic_cols = []
    if thead:
        for td in thead.find_all('td', class_='tactic name')[:15]:
            a = td.find('a')
            en = a.get_text(strip=True) if a else td.get_text(strip=True)
            tactic_cols.append(TACTIC_MAP.get(en, en))

    tbody = matrix_table.find('tbody')
    matrix_row = tbody.find('tr') if tbody else None
    tds = matrix_row.find_all('td', class_='tactic', recursive=False) if matrix_row else []

    entries = {}
    parents = {}

    for idx, td in enumerate(tds):
        if idx >= len(tactic_cols):
            continue
        tactic = tactic_cols[idx]
        tech_table = td.find('table', class_='techniques-table')
        if not tech_table:
            continue
        for tr in tech_table.find_all('tr', class_='technique-row'):
            super_table = tr.find('table', class_='supertechnique')
            if super_table:
                parent_cell = super_table.find('td', class_='supertechniquecell')
                parent_a = parent_cell.find('a', href=re.compile(r'/versions/v19/techniques/T')) if parent_cell else None
                if not parent_a:
                    continue
                parent_id = tech_id_from_href(parent_a.get('href', ''))
                parent_name = normalize_text(parent_a.get_text())
                if not parent_id:
                    continue
                if parent_id not in parents:
                    parents[parent_id] = {'name': parent_name, 'nameZh': translate(parent_name), 'tactics': set()}
                parents[parent_id]['tactics'].add(tactic)

                for sub_cell in super_table.find_all('td', class_='technique-cell'):
                    if 'supertechniquecell' in sub_cell.get('class', []):
                        continue
                    sub_a = sub_cell.find('a', href=re.compile(r'/versions/v19/techniques/T'))
                    if not sub_a:
                        continue
                    sub_id = tech_id_from_href(sub_a.get('href', ''))
                    sub_name = normalize_text(sub_a.get_text())
                    if not sub_id:
                        continue
                    if sub_id not in entries:
                        entries[sub_id] = {
                            'id': sub_id, 'name': sub_name, 'nameZh': translate(sub_name),
                            'tactics': set(), 'parentId': parent_id,
                            'parentName': parent_name,
                            'parentNameZh': parents[parent_id]['nameZh'],
                        }
                    entries[sub_id]['tactics'].add(tactic)
            else:
                cell = tr.find('td', class_='technique-cell')
                a = cell.find('a', href=re.compile(r'/versions/v19/techniques/T')) if cell else None
                if not a:
                    continue
                tech_id = tech_id_from_href(a.get('href', ''))
                tech_name = normalize_text(a.get_text())
                if not tech_id:
                    continue
                if tech_id not in entries:
                    entries[tech_id] = {
                        'id': tech_id, 'name': tech_name, 'nameZh': translate(tech_name),
                        'tactics': set(), 'parentId': tech_id,
                        'parentName': tech_name, 'parentNameZh': translate(tech_name),
                    }
                entries[tech_id]['tactics'].add(tactic)

    for tid, zh in SPECIAL.items():
        if tid in entries:
            entries[tid]['nameZh'] = zh
            if entries[tid].get('parentId') == tid:
                entries[tid]['parentNameZh'] = zh
        elif tid in parents:
            parents[tid]['nameZh'] = zh

    for pid, p in parents.items():
        if pid not in entries:
            entries[pid] = {
                'id': pid, 'name': p['name'], 'nameZh': p['nameZh'],
                'tactics': p['tactics'], 'parentId': pid,
                'parentName': p['name'], 'parentNameZh': p['nameZh'],
            }
        else:
            entries[pid]['tactics'] = entries[pid]['tactics'].union(p['tactics'])

    result = []
    for tid in sorted(entries.keys()):
        e = entries[tid]
        result.append({
            'id': e['id'], 'name': e['name'], 'nameZh': e['nameZh'],
            'tactics': sorted(list(e['tactics'])),
            'parentId': e['parentId'], 'parentName': e['parentName'],
            'parentNameZh': e['parentNameZh'],
        })

    with open(OUT, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f'已写入 {OUT}，共 {len(result)} 条。')

if __name__ == '__main__':
    main()
