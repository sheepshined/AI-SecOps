#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把 MITRE ATT&CK STIX JSON（如 enterprise-attack-19.1.json）
转换为前端可直接加载的轻量子技术 JSON。

前端期望格式：
[
  {"id": "T1071.001", "name": "应用层协议: Web 协议", "tactics": ["命令与控制"]},
  ...
]

用法示例：
    python3 convert_mitre_attack.py enterprise-attack-19.1.json -o static/data/attack_subtechniques.json
"""
import json
import argparse

TACTIC_ZH = {
    'initial-access': '初始访问',
    'execution': '执行',
    'persistence': '持久化',
    'privilege-escalation': '权限提升',
    'defense-evasion': '防御规避',
    'credential-access': '凭证访问',
    'discovery': '发现',
    'lateral-movement': '横向移动',
    'collection': '收集',
    'command-and-control': '命令与控制',
    'exfiltration': '外渗',
    'impact': '影响',
    'reconnaissance': '侦察',
    'resource-development': '资源开发'
}

def external_id(obj):
    refs = obj.get('external_references', [])
    for r in refs:
        if r.get('source_name') == 'mitre-attack':
            return r.get('external_id')
    return None

def extract_subtechniques(stix_path):
    with open(stix_path, 'r', encoding='utf-8') as f:
        bundle = json.load(f)

    results = []
    for obj in bundle.get('objects', []):
        if obj.get('type') != 'attack-pattern':
            continue
        ext_id = external_id(obj)
        if not ext_id or '.' not in ext_id or not ext_id.startswith('T'):
            continue
        if obj.get('revoked') or obj.get('x_mitre_deprecated'):
            continue
        tactics = []
        for phase in obj.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack':
                short = phase.get('phase_name')
                if short in TACTIC_ZH and TACTIC_ZH[short] not in tactics:
                    tactics.append(TACTIC_ZH[short])
        if not tactics:
            continue
        results.append({
            'id': ext_id,
            'name': obj.get('name', ext_id),
            'tactics': tactics
        })

    results.sort(key=lambda x: x['id'])
    return results

def main():
    parser = argparse.ArgumentParser(description='Convert MITRE ATT&CK STIX JSON to frontend JSON')
    parser.add_argument('input', help='Path to official ATT&CK STIX JSON')
    parser.add_argument('-o', '--output', default='static/data/attack_subtechniques.json',
                        help='Output path (default: static/data/attack_subtechniques.json)')
    args = parser.parse_args()

    data = extract_subtechniques(args.input)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    print('Converted {} sub-techniques -> {}'.format(len(data), args.output))

if __name__ == '__main__':
    main()
