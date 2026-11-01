#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""漏洞每日统计与 AI 研判匹配技能。"""

import json
import re

import db
import vuln_updater


def build_daily_stats(alarms=None):
    """按上传日期统计漏洞库数量，并和告警 AI 研判结果做关键词匹配。"""
    index = vuln_updater.load_vuln_index()
    daily = {}
    sources = {}
    total = 0
    for item in index:
        date = item.get("uploaded_at", "")[:10]
        count = int(item.get("count") or 0)
        if not date:
            continue
        daily[date] = daily.get(date, 0) + count
        total += count
        src = item.get("source_id") or "unknown"
        sources[src] = sources.get(src, 0) + count

    cve_set = set()
    cve_to_source = {}
    product_set = set()
    vendor_set = set()
    for item in index:
        uid = item.get("id")
        if not uid:
            continue
        content = vuln_updater.get_vulnerability_content(uid)
        if not content:
            continue
        try:
            doc = json.loads(content)
        except Exception:
            continue
        src = item.get("source_id") or "unknown"
        for vuln in doc.get("vulnerabilities", []) or []:
            cve = (vuln.get("cve_id") or "").strip()
            if cve:
                cve_set.add(cve)
                cve_to_source.setdefault(cve, src)
            for p in str(vuln.get("product") or "").split(","):
                p = p.strip()
                if p:
                    product_set.add(p)
            for v in str(vuln.get("vendor") or "").split(","):
                v = v.strip()
                if v:
                    vendor_set.add(v)

    if alarms is None:
        alarms = db.load_alarms()

    matched = []
    for alarm in alarms:
        fields = {
            "ai_result": alarm.get("ai_result") or "",
            "description": alarm.get("description") or "",
            "name": alarm.get("name") or "",
            "type": alarm.get("type") or "",
            "verdict": alarm.get("verdict") or "",
            "model_response": alarm.get("model_response") or "",
        }
        text_all = " ".join(fields.values()).lower()
        if not text_all.strip():
            continue

        alarm_cves = set(re.findall(r"cve-\d{4}-\d+", text_all, flags=re.IGNORECASE))
        found = False
        for cve in alarm_cves:
            if cve.upper() in cve_set:
                for field_name, val in fields.items():
                    if cve.lower() in (val or "").lower():
                        matched.append({
                            "alarm_id": alarm["id"],
                            "cve_id": cve.upper(),
                            "matched_field": field_name,
                            "source": cve_to_source.get(cve.upper(), ""),
                        })
                        found = True
                        break
                if found:
                    break
        if found:
            continue

        for kw_set, kw_type in ((product_set, "product"), (vendor_set, "vendor")):
            found = False
            for kw in sorted(kw_set, key=len, reverse=True):
                if len(kw) < 3:
                    continue
                pattern = r"\b" + re.escape(kw.lower()) + r"\b"
                if re.search(pattern, text_all):
                    for field_name, val in fields.items():
                        if re.search(pattern, (val or "").lower()):
                            matched.append({
                                "alarm_id": alarm["id"],
                                "cve_id": "",
                                "keyword": kw,
                                "keyword_type": kw_type,
                                "matched_field": field_name,
                            })
                            found = True
                            break
                    break
            if found:
                break

    return {
        "daily": daily,
        "total": total,
        "sources": sources,
        "matched_alarms": matched,
        "match_count": len(matched),
    }


def execute_vuln_daily_stats():
    """生成漏洞每日统计的自然语言回答。"""
    stats = build_daily_stats()
    source_names = {
        "nvd-cve-recent": "NVD 最近新增 CVE",
        "cisa-kev": "CISA KEV 目录",
        "circl-cve-recent": "CIRCL 最近 CVE",
        "osv-recent": "OSV 开源组件近期漏洞",
    }

    lines = []
    for d in sorted(stats["daily"].keys(), reverse=True):
        lines.append(f"- {d}：{stats['daily'][d]} 条")

    src_lines = []
    for src, cnt in sorted(stats["sources"].items(), key=lambda x: -x[1]):
        src_lines.append(f"- {source_names.get(src, src)}：{cnt} 条")

    if stats["match_count"]:
        mlines = []
        for m in stats["matched_alarms"][:10]:
            if m.get("cve_id"):
                mlines.append(f"• 告警 {m['alarm_id']} 命中 {m['cve_id']}（字段：{m['matched_field']}）")
            else:
                mlines.append(f"• 告警 {m['alarm_id']} 命中关键词 {m['keyword']}（{m['keyword_type']}，字段：{m['matched_field']}）")
        tail = ""
        if stats["match_count"] > 10:
            tail = f"\n... 还有 {stats['match_count'] - 10} 条匹配告警"
        match_text = f"\n\nAI 研判与漏洞库匹配结果：共命中 {stats['match_count']} 条告警：\n" + "\n".join(mlines) + tail
    else:
        match_text = "\n\n当前 AI 研判暂未匹配到漏洞库中的 CVE/产品关键词。"

    msg = f"漏洞库每日拉取统计（累计 {stats['total']} 条）：\n" + "\n".join(lines)
    if src_lines:
        msg += f"\n\n按数据源分布：\n" + "\n".join(src_lines)
    msg += match_text

    return {"ok": True, "message": msg, "data": stats}
