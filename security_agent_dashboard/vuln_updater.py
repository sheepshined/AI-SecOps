#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""漏洞库自动更新模块（多源）。

支持从以下公开漏洞库拉取最新漏洞信息并写入漏洞资料库：
- NVD (National Vulnerability Database) CVE API 2.0
- CISA Known Exploited Vulnerabilities Catalog
- CIRCL CVE Search API（最近 CVE）
- OSV.dev（主流开源组件近期漏洞）

用法：
    from vuln_updater import update_vulnerability_library
    update_vulnerability_library()
"""
import json
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

LIBRARY_DIR = Path(__file__).resolve().parent / "data" / "library"
VULN_INDEX = LIBRARY_DIR / "vuln_index.json"

# ═══════════════════════════════════════════════════
# 源注册表
# ═══════════════════════════════════════════════════
VULN_SOURCES = {
    "nvd-cve-recent": {
        "name": "NVD 最近新增 CVE",
        "source_type": "nvd-api-2.0",
        "description": "NVD CVE API 2.0，拉取最近 7 天新增 CVE",
        "default": True,
    },
    "cisa-kev": {
        "name": "CISA KEV 目录",
        "source_type": "cisa-kev",
        "description": "CISA 已知被利用漏洞目录（Known Exploited Vulnerabilities）",
        "default": True,
    },
    "circl-cve-recent": {
        "name": "CIRCL 最近 CVE",
        "source_type": "circl-api",
        "description": "CIRCL CVE Search API，获取最近 30 条 CVE",
        "default": True,
    },
    "osv-recent": {
        "name": "OSV 开源组件近期漏洞",
        "source_type": "osv-api",
        "description": "OSV.dev 主流开源组件（PyPI/npm/Go/Maven 等）近期漏洞",
        "default": False,
    },
}

NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CIRCL_LAST_URL = "https://cve.circl.lu/api/last/30"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# OSV 查询包列表：覆盖主流语言与关键基础设施组件
OSV_PACKAGES = [
    {"ecosystem": "PyPI", "name": "django"},
    {"ecosystem": "PyPI", "name": "flask"},
    {"ecosystem": "PyPI", "name": "requests"},
    {"ecosystem": "PyPI", "name": "cryptography"},
    {"ecosystem": "PyPI", "name": "urllib3"},
    {"ecosystem": "npm", "name": "lodash"},
    {"ecosystem": "npm", "name": "express"},
    {"ecosystem": "npm", "name": "next"},
    {"ecosystem": "npm", "name": "react"},
    {"ecosystem": "npm", "name": "vue"},
    {"ecosystem": "npm", "name": "axios"},
    {"ecosystem": "Go", "name": "stdlib"},
    {"ecosystem": "Maven", "name": "org.springframework:spring-core"},
    {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
    {"ecosystem": "crates.io", "name": "openssl"},
]

OSV_RECENT_DAYS = 90


def now_str():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def parse_iso_dt(value):
    if not value:
        return None
    try:
        v = value.replace("Z", "+00:00")
        return datetime.fromisoformat(v)
    except Exception:
        return None


def _format_size(size):
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _make_preview(text, length=300):
    if not text:
        return ""
    t = re.sub(r"\s+", " ", text).strip()
    return t[:length] + ("..." if len(t) > length else "")


def ensure_library_dir():
    LIBRARY_DIR.mkdir(parents=True, exist_ok=True)


def load_vuln_index():
    ensure_library_dir()
    if not VULN_INDEX.exists():
        return []
    try:
        with open(VULN_INDEX, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_vuln_index(index):
    ensure_library_dir()
    with open(VULN_INDEX, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)


def get_available_sources():
    """返回所有可用漏洞源的配置信息。"""
    return [
        {"id": k, "name": v["name"], "description": v["description"], "default": v.get("default", False)}
        for k, v in VULN_SOURCES.items()
    ]


def _extract_cpe_parts(cpe23uri):
    """从 CPE 2.3 URI 中提取 vendor 和 product。"""
    try:
        parts = cpe23uri.split(":")
        if len(parts) >= 5:
            return parts[3], parts[4]
    except Exception:
        pass
    return "", ""


# ═══════════════════════════════════════════════════
# 数据归一化
# ═══════════════════════════════════════════════════
def normalize_nvd_api_item(item):
    """把 NVD API 2.0 的 CVE item 转成统一格式。"""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    descriptions = cve.get("descriptions", [])
    description = ""
    for d in descriptions:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    references = [r.get("url") for r in cve.get("references", []) if r.get("url")]

    cvss_score = None
    severity = ""
    metrics = cve.get("metrics", {})
    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
    if not cvss_v3:
        cvss_v3 = metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30") else {}
    if cvss_v3:
        cvss_score = cvss_v3.get("cvssData", {}).get("baseScore")
        severity = cvss_v3.get("cvssData", {}).get("baseSeverity", "")
    if not cvss_score:
        cvss_v2 = metrics.get("cvssMetricV2", [{}])[0] if metrics.get("cvssMetricV2") else {}
        if cvss_v2:
            cvss_score = cvss_v2.get("cvssData", {}).get("baseScore")
            severity = cvss_v2.get("cvssData", {}).get("baseSeverity", "") or cvss_v2.get("severity", "")

    vendors = set()
    products = set()
    for node in cve.get("configurations", []):
        for child in node.get("children", []):
            for match in child.get("cpeMatch", []):
                vendor, product = _extract_cpe_parts(match.get("criteria", ""))
                if vendor:
                    vendors.add(vendor)
                if product:
                    products.add(product)
        for match in node.get("cpeMatch", []):
            vendor, product = _extract_cpe_parts(match.get("criteria", ""))
            if vendor:
                vendors.add(vendor)
            if product:
                products.add(product)

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "severity": severity,
        "published": cve.get("published", ""),
        "modified": cve.get("lastModified", ""),
        "vendor": ", ".join(sorted(vendors)) if vendors else "",
        "product": ", ".join(sorted(products)) if products else "",
        "references": references,
        "source": "NVD",
        "vuln_status": cve.get("vulnStatus", ""),
    }


def normalize_cisa_item(item):
    """把 CISA KEV 单项转成统一格式。"""
    return {
        "cve_id": item.get("cveID", ""),
        "description": item.get("shortDescription", ""),
        "vendor": item.get("vendorProject", ""),
        "product": item.get("product", ""),
        "published": item.get("dateAdded", ""),
        "modified": item.get("dateAdded", ""),
        "known_exploited": True,
        "required_action": item.get("requiredAction", ""),
        "due_date": item.get("dueDate", ""),
        "ransomware_use": item.get("knownRansomwareCampaignUse", ""),
        "references": [],
        "source": "CISA-KEV",
    }


def normalize_circl_item(item):
    """把 CIRCL CVE Search 单项转成统一格式。"""
    refs = []
    for r in item.get("references", []):
        if isinstance(r, dict):
            u = r.get("url") or r.get("reference")
            if u:
                refs.append(u)
        elif isinstance(r, str):
            refs.append(r)
    impact = item.get("impact", {}) or {}
    cvss = impact.get("cvss", {})
    return {
        "cve_id": item.get("id", ""),
        "description": item.get("summary", ""),
        "cvss_score": cvss.get("baseScore") if isinstance(cvss, dict) else None,
        "severity": cvss.get("baseSeverity", "") if isinstance(cvss, dict) else "",
        "published": item.get("Published", ""),
        "modified": item.get("Modified", ""),
        "vendor": "",
        "product": "",
        "references": refs,
        "source": "CIRCL",
    }


def normalize_osv_item(item):
    """把 OSV 漏洞记录转成统一格式。"""
    aliases = item.get("aliases", [])
    cve_id = ""
    for a in aliases:
        if a.upper().startswith("CVE-"):
            cve_id = a
            break
    if not cve_id and aliases:
        cve_id = aliases[0]

    affected = item.get("affected", [])
    products = set()
    ecosystems = set()
    for aff in affected:
        pkg = aff.get("package", {})
        if pkg.get("name"):
            products.add(pkg["name"])
        if pkg.get("ecosystem"):
            ecosystems.add(pkg["ecosystem"])

    refs = []
    for r in item.get("references", []):
        if isinstance(r, dict) and r.get("url"):
            refs.append(r["url"])
        elif isinstance(r, str):
            refs.append(r)

    return {
        "cve_id": cve_id,
        "description": item.get("details", ""),
        "cvss_score": None,
        "severity": item.get("severity", "") or "",
        "published": item.get("published", ""),
        "modified": item.get("modified", ""),
        "vendor": ", ".join(sorted(ecosystems)) if ecosystems else "",
        "product": ", ".join(sorted(products)) if products else "",
        "references": refs,
        "source": "OSV",
        "osv_id": item.get("id", ""),
        "aliases": aliases,
    }


# ═══════════════════════════════════════════════════
# 源拉取
# ═══════════════════════════════════════════════════
def _nvd_api_headers():
    headers = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


def _nvd_rate_limit_sleep(page_index):
    """NVD 公开 API 限速：无 Key 时 30 秒内不超过 5 次，有 Key 时 50 次。"""
    limit = 50 if NVD_API_KEY else 5
    if page_index > 0 and page_index % limit == 0:
        time.sleep(32)
    elif page_index > 0:
        time.sleep(6 if NVD_API_KEY else 7)


def fetch_nvd_api_recent(days=7):
    """使用 NVD API 2.0 拉取最近 days 天的 CVE。"""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.999"),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    all_items = []
    page = 0
    source_uri = NVD_BASE_URL + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    while True:
        _nvd_rate_limit_sleep(page)
        r = requests.get(NVD_BASE_URL, params=params, headers={**_nvd_api_headers(), "User-Agent": "security-agent-dashboard/1.0"}, timeout=120)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        all_items.extend([normalize_nvd_api_item(i) for i in vulns])
        total = data.get("totalResults", 0)
        if params["startIndex"] + len(vulns) >= total:
            break
        params["startIndex"] += len(vulns)
        page += 1
        if page > 20:  # 安全上限
            break
    return {
        "feed": "nvd-cve-recent",
        "title": "NVD 最近新增 CVE",
        "description": f"NVD CVE API 2.0，拉取最近 {days} 天新增 CVE",
        "source_uri": source_uri,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(all_items),
        "vulnerabilities": all_items,
    }


def fetch_cisa_kev():
    r = requests.get(CISA_KEV_URL, headers={"User-Agent": "security-agent-dashboard/1.0"}, timeout=120)
    r.raise_for_status()
    raw = r.json()
    items = [normalize_cisa_item(i) for i in raw.get("vulnerabilities", [])]
    return {
        "feed": "cisa-kev",
        "title": "CISA KEV 目录",
        "description": "CISA 已知被利用漏洞目录",
        "source_uri": CISA_KEV_URL,
        "generated_at": raw.get("dateReleased", "") or datetime.now(timezone.utc).isoformat(),
        "catalog_version": raw.get("catalogVersion", ""),
        "count": len(items),
        "vulnerabilities": items,
    }


def fetch_circl_recent():
    r = requests.get(CIRCL_LAST_URL, headers={"User-Agent": "security-agent-dashboard/1.0"}, timeout=60)
    r.raise_for_status()
    raw = r.json()
    items = [normalize_circl_item(i) for i in raw]
    return {
        "feed": "circl-cve-recent",
        "title": "CIRCL 最近 CVE",
        "description": "CIRCL CVE Search API，获取最近 30 条 CVE",
        "source_uri": CIRCL_LAST_URL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(items),
        "vulnerabilities": items,
    }


def fetch_osv_recent(days=OSV_RECENT_DAYS):
    """查询主流开源组件，保留最近 days 天的漏洞。"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    all_items = []
    seen = set()
    for pkg in OSV_PACKAGES:
        try:
            body = {"package": pkg}
            r = requests.post(OSV_QUERY_URL, json=body, headers={"User-Agent": "security-agent-dashboard/1.0"}, timeout=60)
            r.raise_for_status()
            data = r.json()
            for item in data.get("vulns", []):
                published = parse_iso_dt(item.get("published"))
                if published and published < cutoff:
                    continue
                vid = item.get("id", "")
                if vid in seen:
                    continue
                seen.add(vid)
                all_items.append(normalize_osv_item(item))
            time.sleep(0.4)
        except Exception as e:
            print(f"[vuln_updater] OSV query failed for {pkg}: {e}")
            continue
    return {
        "feed": "osv-recent",
        "title": "OSV 开源组件近期漏洞",
        "description": f"OSV.dev 主流开源组件最近 {days} 天漏洞",
        "source_uri": OSV_QUERY_URL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(all_items),
        "vulnerabilities": all_items,
    }


# ═══════════════════════════════════════════════════
# 资料库存储
# ═══════════════════════════════════════════════════
def _save_library_document(name, doc, source_id=None):
    """把漏洞文档写入资料库并更新漏洞索引。保留同一 source_id 的历史记录。"""
    ensure_library_dir()
    uid = str(uuid.uuid4())[:12]
    stored_name = f"{uid}.json"
    stored_path = LIBRARY_DIR / stored_name
    content_text = json.dumps(doc, ensure_ascii=False, indent=2)
    with open(stored_path, "w", encoding="utf-8") as f:
        f.write(content_text)

    size = stored_path.stat().st_size
    preview = _make_preview(content_text)

    item = {
        "id": uid,
        "name": name,
        "stored_name": stored_name,
        "source_id": source_id,
        "type": "JSON",
        "size": size,
        "size_human": _format_size(size),
        "uploaded_at": now_str(),
        "preview": preview,
        "has_content": True,
        "content_length": len(content_text),
        "category": "vulnerability",
        "count": doc.get("count"),
        "generated_at": doc.get("generated_at", ""),
    }

    content_path = LIBRARY_DIR / f"{uid}.content.txt"
    try:
        with open(content_path, "w", encoding="utf-8") as f:
            f.write(content_text)
    except Exception:
        pass

    index = load_vuln_index()
    index.append(item)
    save_vuln_index(index)
    return item


def list_vulnerability_library():
    """列出漏洞资料库中的所有条目。"""
    return load_vuln_index()


def delete_vulnerability_document(uid):
    """删除漏洞资料库中的指定条目及对应文件。"""
    index = load_vuln_index()
    item = next((x for x in index if x.get("id") == uid), None)
    if not item:
        return False
    index = [x for x in index if x.get("id") != uid]
    save_vuln_index(index)
    try:
        (LIBRARY_DIR / item["stored_name"]).unlink(missing_ok=True)
    except Exception:
        pass
    try:
        (LIBRARY_DIR / f"{uid}.content.txt").unlink(missing_ok=True)
    except Exception:
        pass
    return True


def get_vulnerability_content(uid):
    """获取漏洞文档的文本内容（优先 .content.txt，回退到 JSON 原文件）。"""
    item = next((x for x in load_vuln_index() if x.get("id") == uid), None)
    if not item:
        return None
    content_path = LIBRARY_DIR / f"{uid}.content.txt"
    try:
        if content_path.exists():
            return content_path.read_text(encoding="utf-8")
    except Exception:
        pass
    try:
        return (LIBRARY_DIR / item["stored_name"]).read_text(encoding="utf-8")
    except Exception:
        return None


def get_vulnerability_summary():
    """返回漏洞库概览，用于注入智能助理系统提示词。"""
    index = load_vuln_index()
    return {
        "document_count": len(index),
        "sources": sorted({x.get("source_id", "") for x in index if x.get("source_id")}),
        "latest_documents": [
            {"id": x["id"], "name": x["name"], "source_id": x.get("source_id", ""), "uploaded_at": x.get("uploaded_at", "")}
            for x in sorted(index, key=lambda x: x.get("uploaded_at", ""), reverse=True)[:10]
        ],
    }


def update_vulnerability_library(sources=None, days=7):
    """更新漏洞库资料。默认更新 NVD recent、CISA KEV、CIRCL。
    days 参数控制 NVD/OSV 最近多少天的数据，适合定时任务使用小窗口。"""
    if sources is None:
        sources = [k for k, v in VULN_SOURCES.items() if v.get("default")]

    results = []
    for src in sources:
        try:
            if src == "nvd-cve-recent":
                doc = fetch_nvd_api_recent(days=days)
                name = f"{doc['title']} ({datetime.now(timezone.utc).strftime('%Y-%m-%d')}).json"
            elif src == "cisa-kev":
                doc = fetch_cisa_kev()
                name = f"{doc['title']} ({datetime.now(timezone.utc).strftime('%Y-%m-%d')}).json"
            elif src == "circl-cve-recent":
                doc = fetch_circl_recent()
                name = f"{doc['title']} ({datetime.now(timezone.utc).strftime('%Y-%m-%d')}).json"
            elif src == "osv-recent":
                doc = fetch_osv_recent(days=days)
                name = f"{doc['title']} ({datetime.now(timezone.utc).strftime('%Y-%m-%d')}).json"
            else:
                results.append({"source": src, "status": "skipped", "reason": "未知数据源"})
                continue
            item = _save_library_document(name, doc, source_id=src)
            results.append({
                "source": src,
                "status": "success",
                "count": doc["count"],
                "id": item["id"],
                "name": item["name"],
            })
        except Exception as e:
            results.append({"source": src, "status": "error", "error": str(e), "error_type": type(e).__name__})

    return {
        "updated_at": now_str(),
        "sources": results,
    }


if __name__ == "__main__":
    import sys
    srcs = sys.argv[1:] or None
    print(json.dumps(update_vulnerability_library(sources=srcs), ensure_ascii=False, indent=2))
