#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""读取现有 attack_subtechniques.json，补充中文名称与父技术信息。"""
import json
import re

IN = '/Users/zhangshanshan/Documents/AI_xinyu/security_agent_dashboard/static/data/attack_subtechniques.json'
OUT = '/Users/zhangshanshan/Documents/AI_xinyu/security_agent_dashboard/static/data/attack_subtechniques.json'

PHRASES = {
    'Application Layer Protocol': '应用层协议',
    'Command and Scripting Interpreter': '命令与脚本解释器',
    'Command and Control': '命令与控制',
    'Domain Controller': '域控制器',
    'Domain Trust': '域信任',
    'Drive-by Compromise': '路过式入侵',
    'Dynamic-link Library': '动态链接库',
    'Group Policy': '组策略',
    'Internal Defacement': '内部篡改',
    'Internal Spearphishing': '内部鱼叉钓鱼',
    'Living Off The Land': '离地生存',
    'Logon Script': '登录脚本',
    'Man-in-the-Middle': '中间人',
    'Network Device': '网络设备',
    'Network Security': '网络安全',
    'Network Share': '网络共享',
    'Office Application': 'Office 应用',
    'Office Document': 'Office 文档',
    'Office Template': 'Office 模板',
    'Operating System': '操作系统',
    'Pass the Hash': 'Pass-the-Hash',
    'Pass the Ticket': 'Pass-the-Ticket',
    'Remote Desktop': '远程桌面',
    'Remote Services': '远程服务',
    'Remote System': '远程系统',
    'Security Account Manager': '安全账户管理器',
    'Service Execution': '服务执行',
    'Social Engineering': '社会工程',
    'Spearphishing Attachment': '鱼叉钓鱼附件',
    'Spearphishing Link': '鱼叉钓鱼链接',
    'Spearphishing Service': '鱼叉钓鱼服务',
    'Supply Chain': '供应链',
    'Symbolic Link': '符号链接',
    'System Information': '系统信息',
    'System Network': '系统网络',
    'System Service': '系统服务',
    'Virtual Private Network': '虚拟专用网络',
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
    'Block': '阻止', 'Bluetooth': '蓝牙', 'Boot': '启动', 'Border': '边界',
    'Browser': '浏览器', 'Brute': '暴力', 'Force': '破解', 'Buffer': '缓冲',
    'Bypass': '绕过', 'C2': 'C2', 'Cached': '缓存', 'Certificate': '证书',
    'Change': '变更', 'Chat': '聊天', 'Client': '客户端', 'Clipboard': '剪贴板',
    'Cloud': '云', 'Code': '代码', 'Command': '命令', 'Communication': '通信',
    'Component': '组件', 'COM': 'COM', 'Compromise': '入侵', 'Concealment': '隐藏',
    'Config': '配置', 'Configuration': '配置', 'Connection': '连接', 'Container': '容器',
    'Content': '内容', 'Cookie': 'Cookie', 'Copy': '复制', 'Credentials': '凭据',
    'Cryptocurrency': '加密货币', 'DCSync': 'DCSync', 'Data': '数据', 'Database': '数据库',
    'Debug': '调试', 'Decode': '解码', 'Default': '默认', 'Delete': '删除',
    'Denial': '拒绝', 'Deployment': '部署', 'Device': '设备', 'Directory': '目录',
    'Disable': '禁用', 'Discover': '发现', 'Discovery': '发现', 'Disk': '磁盘',
    'DLL': 'DLL', 'DNS': 'DNS', 'Domain': '域', 'Download': '下载', 'Dynamic': '动态',
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
    'Machine': '机器', 'Mail': '邮件', 'Malicious': '恶意', 'Man-in-the-Middle': '中间人',
    'Masquerade': '伪装', 'Memory': '内存', 'Message': '消息', 'Mimikatz': 'Mimikatz',
    'MITM': 'MITM', 'Modify': '修改', 'Module': '模块', 'Monitor': '监控',
    'Mount': '挂载', 'Mouse': '鼠标', 'Msiexec': 'Msiexec', 'Multi-Factor': '多因素',
    'Named': '命名', 'Pipe': '管道', 'NBNS': 'NBNS', 'NDS': 'NDS', 'Network': '网络',
    'New': '新', 'NFS': 'NFS', 'NTLM': 'NTLM', 'NTDS': 'NTDS', 'Obfuscate': '混淆',
    'Obfuscation': '混淆', 'Obtain': '获取', 'Office': 'Office', 'One-Way': '单向',
    'Open': '打开', 'OS': 'OS', 'Outlook': 'Outlook', 'Pass': '传递',
    'Password': '密码', 'Path': '路径', 'Payload': '载荷', 'Permission': '权限',
    'Persistence': '持久化', 'Phishing': '钓鱼', 'Phone': '电话', 'Plist': 'Plist',
    'Policy': '策略', 'Port': '端口', 'Portable': '便携', 'PowerShell': 'PowerShell',
    'Print': '打印', 'Printer': '打印机', 'Private': '私有', 'Privilege': '权限',
    'Process': '进程', 'Proc': '进程', 'Protocol': '协议', 'Proxy': '代理',
    'Python': 'Python', 'Query': '查询', 'RAS': 'RAS', 'RDP': 'RDP',
    'Registry': '注册表', 'Remote': '远程', 'Remove': '删除', 'Replicate': '复制',
    'Replication': '复制', 'Request': '请求', 'Response': '响应', 'Revert': '恢复',
    'Rootkit': 'Rootkit', 'Route': '路由', 'Run': '运行', 'SAML': 'SAML', 'SAM': 'SAM',
    'Scan': '扫描', 'Scanning': '扫描', 'Screen': '屏幕', 'Script': '脚本',
    'Scripting': '脚本', 'Security': '安全', 'Server': '服务器', 'Service': '服务',
    'Session': '会话', 'Set': '设置', 'Share': '共享', 'Shared': '共享', 'Shell': 'Shell',
    'Shortcut': '快捷方式', 'SMB': 'SMB', 'SMTP': 'SMTP', 'SNMP': 'SNMP',
    'Software': '软件', 'Source': '源', 'SSH': 'SSH', 'SSL/TLS': 'SSL/TLS',
    'SSL': 'SSL', 'TLS': 'TLS', 'Staging': '暂存', 'Standard': '标准',
    'Startup': '启动项', 'Steal': '窃取', 'Steganography': '隐写术', 'Stored': '存储',
    'Subvert': '颠覆', 'Supply': '供应链', 'Symbolic': '符号', 'System': '系统',
    'Table': '表', 'Target': '目标', 'Targeted': '定向', 'Task': '任务',
    'TCP': 'TCP', 'Template': '模板', 'Ticket': '票据', 'Time': '时间',
    'Token': '令牌', 'Tool': '工具', 'Traffic': '流量', 'Transfer': '传输',
    'Trap': '陷阱', 'Trusted': '受信任', 'Two-Factor': '双因素', 'UAC': 'UAC',
    'USB': 'USB', 'User': '用户', 'Utility': '工具', 'Valid': '有效',
    'Victim': '受害者', 'Video': '视频', 'Virtual': '虚拟', 'VNC': 'VNC',
    'Volume': '卷', 'Vulnerability': '漏洞', 'Web': 'Web', 'Website': '网站',
    'Wi-Fi': 'Wi-Fi', 'Winlogon': 'Winlogon', 'WMI': 'WMI', 'Windows': 'Windows',
    'Wireless': '无线', 'Word': 'Word', 'Wordlist': '字典', 'Write': '写入',
    'XSL': 'XSL', 'and': '与', 'or': '或', 'of': '的', 'to': '至', 'in': '于',
    'for': '用于', 'on': '于', 'from': '来自', 'with': '使用', 'via': '通过',
    'over': '通过', 'into': '进入', 'using': '使用', 'And': '与', 'Or': '或',
    'Of': '的', 'To': '至', 'In': '于', 'For': '用于', 'On': '于', 'From': '来自',
    'With': '使用', 'Via': '通过', 'Over': '通过', 'Into': '进入', 'Using': '使用',
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
    'T1001': '混淆协议或命令',
    'T1001.001': '混淆协议或命令：垃圾数据',
    'T1001.002': '混淆协议或命令：隐写术',
    'T1001.003': '混淆协议或命令：协议或服务伪装',
    'T1016': '系统网络配置发现',
    'T1016.001': '系统网络配置发现：互联网连接发现',
    'T1016.002': '系统网络配置发现：Wi-Fi 发现',
    'T1011': '经由其他网络媒介渗出',
    'T1011.001': '经由其他网络媒介渗出：通过蓝牙渗出',
}

PARENT_SPECIAL = {
    'T1071': '应用层协议',
    'T1059': '命令与脚本解释器',
    'T1003': 'OS 凭证转储',
    'T1110': '暴力破解',
    'T1498': '网络拒绝服务',
    'T1078': '有效账户',
    'T1041': '通过 C2 通道渗出',
    'T1021': '远程服务',
    'T1505': '服务器软件组件',
    'T1091': '可复制到可移动媒体',
    'T1566': '钓鱼',
    'T1053': '计划任务/作业',
    'T1001': '混淆协议或命令',
    'T1016': '系统网络配置发现',
    'T1011': '经由其他网络媒介渗出',
    'T1595': '主动扫描',
    'T1592': '收集受害者主机信息',
    'T1589': '收集受害者身份信息',
    'T1190': '利用面向公众的应用程序',
    'T1133': '外部远程服务',
    'T1098': '账户操作',
    'T1098.001': '账户操作：额外云凭证',
    'T1071': '应用层协议',
    'T1548': '滥用提升控制机制',
    'T1548.001': '滥用提升控制机制：Setuid 和 Setgid',
    'T1548.002': '滥用提升控制机制：绕过用户访问控制',
    'T1548.003': '滥用提升控制机制：Sudo 和 Sudo Caching',
    'T1548.004': '滥用提升控制机制：Elevated Execution with Prompt',
}

def translate(name):
    if not name:
        return name
    # 优先词组
    for eng, chn in sorted(PHRASES.items(), key=lambda x: -len(x[0])):
        name = name.replace(eng, chn)
    # 单词
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

def parent_id(tid):
    return tid.split('.')[0]

def main():
    with open(IN, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    parents = {}
    for item in data:
        tid = item['id']
        pid = parent_id(tid)
        item['parentId'] = pid
        # 中文名称
        item['nameZh'] = SPECIAL.get(tid) or translate(item['name'])
        # 聚合父技术战术
        parents.setdefault(pid, {'tactics': set(), 'name': pid, 'nameZh': PARENT_SPECIAL.get(pid, pid)})
        for t in item['tactics']:
            parents[pid]['tactics'].add(t)

    # 补齐父技术条目（用 ID 作为占位名称）
    existing_ids = {item['id'] for item in data}
    for pid, p in parents.items():
        if pid not in existing_ids:
            data.append({
                'id': pid,
                'name': p['name'],
                'nameZh': p['nameZh'],
                'tactics': sorted(list(p['tactics'])),
                'parentId': pid,
            })

    # 为所有条目补充 parentNameZh
    for item in data:
        pid = item['parentId']
        item['parentNameZh'] = PARENT_SPECIAL.get(pid, pid)

    # 排序：按 ID
    data.sort(key=lambda x: x['id'])

    with open(OUT, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f'已翻译并写入 {OUT}，共 {len(data)} 条。')

if __name__ == '__main__':
    main()
