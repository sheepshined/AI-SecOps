#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""告警研判知识库上下文召回模块。

从漏洞库（data/library/vuln_index.json）和资料库（data/library/index.json）中，
根据告警信息提取关键词，召回最相关的漏洞条目与资料文档，并格式化为限定长度
的文本上下文，供 AI 研判模型参考。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

# 与 vuln_updater 保持一致，避免硬编码路径
from vuln_updater import list_vulnerability_library, get_vulnerability_content

LIBRARY_DIR = Path(__file__).resolve().parent / "data" / "library"
LIBRARY_INDEX = LIBRARY_DIR / "index.json"

_MAX_TOTAL_CHARS = 2500
_TOP_VULN = 3
_TOP_LIBRARY = 3
# 关键词上限：切词+同义词扩展后词条可能很多，超长列表会拖慢评分且稀释强特征
_MAX_KEYWORDS = 60

# 强特征：IP / CVE 编号 / ATT&CK 技术 ID。命中这类词的信息量远高于普通词，评分加权 ×3
_STRONG_FEATURE_RE = re.compile(
    r"^(?:(?:\d{1,3}\.){3}\d{1,3}|cve-\d{4}-\d+|t\d+(?:\.\d+)?)$"
)

# 纯中文 token（无空格分隔）超过该长度时拆成 bigram，避免"整段中文"成为不可命中的巨词
_CHINESE_BIGRAM_THRESHOLD = 4

# 常见停用词（中英文），命中这些词不加分
_STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "must", "can", "this", "that", "these",
    "those", "of", "in", "on", "at", "to", "for", "with", "by", "from",
    "as", "and", "or", "not", "no", "if", "then", "else", "when", "where",
    "which", "who", "what", "how", "all", "any", "each", "every", "some",
    "攻击", "告警", "尝试", "成功", "失败", "数据", "信息", "用户", "系统",
    "文件", "进程", "服务", "网络", "地址", "端口", "来源", "目标", "时间",
    "检测到", "针对", "应用的",
}

# 常见命令行/路径噪声词，过滤后减少误召回
_NOISE_TOKENS = {
    "var", "usr", "sbin", "bin", "lib", "etc", "opt", "home", "root", "local",
    "tmp", "temp", "start", "stop", "run", "exe", "dll", "so", "sys", "windows",
    "system32", "syswow64", "program", "files", "users", "http", "https", "com",
    "org", "net", "cn", "php", "html", "js", "css",
    "-k", "-s", "-d", "-p", "-c", "-e", "-l", "-u", "-g", "-o", "-a", "-n",
}

# 中英攻击类型同义词扩展：命中中文后补充英文关键词，反之亦然
_KEYWORD_SYNONYMS = {
    "sql": ["sql injection", "injection", "注入"],
    "注入": ["sql injection", "injection", "sql"],
    "injection": ["sql injection", "注入", "sql"],
    "xss": ["cross-site scripting", "xss"],
    "跨站脚本": ["cross-site scripting", "xss"],
    "cross-site": ["xss", "跨站脚本"],
    "rce": ["remote code execution", "rce", "代码执行"],
    "远程代码执行": ["remote code execution", "rce"],
    "代码执行": ["remote code execution", "rce"],
    "命令注入": ["command injection"],
    "command injection": ["命令注入"],
    "webshell": ["web shell", "webshell", "file upload"],
    "web shell": ["webshell", "文件上传"],
    "文件上传": ["file upload", "webshell"],
    "file upload": ["文件上传", "webshell"],
    "暴力破解": ["brute force"],
    "brute": ["brute force", "暴力破解"],
    "拒绝服务": ["denial of service", "dos", "ddos"],
    "denial": ["denial of service", "dos", "ddos"],
    "ddos": ["distributed denial of service", "dos"],
    "权限提升": ["privilege escalation"],
    "privilege escalation": ["权限提升"],
    "横向移动": ["lateral movement"],
    "lateral movement": ["横向移动"],
    "恶意代码": ["malware", "c2", "command and control"],
    "c2": ["command and control", "malware", "恶意代码"],
    "凭证窃取": ["credential dumping", "mimikatz"],
    "mimikatz": ["credential dumping", "凭证窃取"],
    "敏感信息泄露": ["information disclosure"],
    "信息泄露": ["information disclosure"],
    "缓冲区溢出": ["buffer overflow"],
    "buffer overflow": ["缓冲区溢出"],
    "提权": ["privilege escalation", "权限提升"],
}

# 缓存：同一进程内避免反复读取大文件
_cache: dict[str, Any] = {}


def _normalize_text(text: str) -> str:
    """统一小写、去标点、压缩空白。"""
    text = text.lower()
    text = re.sub(r"[\s\xa0]+", " ", text)
    return text.strip()


def _tokenize(text: str) -> list[str]:
    """提取关键词：保留连续中文或连续英文/数字/下划线/点号/横杠。

    中文没有空格分隔，长中文串会被整体抓成一个 token（如 20 字的告警描述），
    这样的词几乎不可能在任何语料中命中。因此对超长纯中文串做 bigram 拆分
    （信息检索对 CJK 的经典做法），短中文串保持原样。"""
    text = _normalize_text(text)
    tokens = re.findall(r"[\u4e00-\u9fa5]{2,}|[a-z0-9_.\-]+", text)
    result = []
    for t in tokens:
        if len(t) < 2:
            continue
        if t in _STOPWORDS:
            continue
        if re.fullmatch(r"[\u4e00-\u9fa5]+", t) and len(t) > _CHINESE_BIGRAM_THRESHOLD:
            # bigram 滑窗拆分，并逐个过滤停用词
            for i in range(len(t) - 1):
                gram = t[i:i + 2]
                if gram not in _STOPWORDS:
                    result.append(gram)
        else:
            result.append(t)
    return result


def _expand_synonyms(tokens: set[str]) -> set[str]:
    """根据同义词表扩展关键词，支持中英互转。"""
    expanded = set(tokens)
    for t in list(tokens):
        for key, values in _KEYWORD_SYNONYMS.items():
            if key == t or key in t or t in key:
                expanded.update(values)
    return expanded


def _extract_keywords(alert_data: dict) -> list[str]:
    """从告警数据中递归提取关键词与特征标识。"""
    tokens: set[str] = set()
    texts: list[str] = []

    def collect(obj: Any):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str):
                    texts.append(v)
                else:
                    collect(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                collect(item)
        elif isinstance(obj, str):
            texts.append(obj)

    collect(alert_data)

    full_text = " ".join(texts)
    tokens.update(_tokenize(full_text))

    # 单独提取 IP 地址和 ATT&CK ID 作为强特征
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", full_text):
        tokens.add(ip)
    for attck in re.findall(r"\bT\d+(?:\.\d+)?\b", full_text):
        tokens.add(attck.lower())
    for cve in re.findall(r"\bCVE-\d{4}-\d+\b", full_text, flags=re.IGNORECASE):
        tokens.add(cve.lower())

    # 中英同义词扩展
    tokens = _expand_synonyms(tokens)

    # 过滤噪声词与不合格词条
    filtered = []
    for t in tokens:
        if t in _NOISE_TOKENS or t in _STOPWORDS:
            continue
        if len(t) < 2 or len(t) > 40:
            continue
        if re.match(r"^[\W_]+$", t):
            continue
        if "\\" in t or t.count(".") > 4:
            continue
        filtered.append(t)
    # 按长度降序（长词更具体），截断到上限，控制评分成本
    filtered = list(dict.fromkeys(filtered))
    filtered.sort(key=lambda x: len(x), reverse=True)
    return filtered[:_MAX_KEYWORDS]


def _load_vuln_items() -> list[dict]:
    """加载所有漏洞文档并扁平化为条目列表。

    同一个 CVE 会同时出现在多个数据源文档（如 NVD 与 CISA KEV），去重时保留
    信息量更大的一条：优先 CVSS 分数非空者，再取 modified 时间较新者。"""
    if "vuln_items" in _cache:
        return _cache["vuln_items"]

    items: list[dict] = []
    for doc_meta in list_vulnerability_library():
        uid = doc_meta.get("id")
        if not uid:
            continue
        content = get_vulnerability_content(uid)
        if not content:
            continue
        try:
            doc = json.loads(content)
        except json.JSONDecodeError:
            continue
        vulns = doc.get("vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            if not isinstance(v, dict):
                continue
            desc = v.get("description") or ""
            # 空描述条目价值低，跳过
            if not desc.strip():
                continue
            items.append(v)

    # CVE 去重
    deduped: dict[str, dict] = {}
    others: list[dict] = []
    seen_nocve: set[str] = set()
    for v in items:
        cid = (v.get("cve_id") or "").strip().upper()
        if not cid:
            key = (v.get("description") or "")[:80]
            if key in seen_nocve:
                continue
            seen_nocve.add(key)
            others.append(v)
            continue
        prev = deduped.get(cid)
        if prev is None or _vuln_richness(v) > _vuln_richness(prev):
            deduped[cid] = v

    _cache["vuln_items"] = list(deduped.values()) + others
    return _cache["vuln_items"]


def _vuln_richness(v: dict) -> tuple:
    """条目信息量排序键：CVSS 有分者优先，其次 modified 时间新者优先。"""
    score = v.get("cvss_score")
    has_score = 1 if score not in (None, "") else 0
    try:
        score_val = float(score) if has_score else 0.0
    except (TypeError, ValueError):
        score_val, has_score = 0.0, 0
    return (has_score, score_val, str(v.get("modified") or ""))


def _load_library_docs() -> list[dict]:
    """加载资料库索引及对应 content.txt 内容。"""
    if "library_docs" in _cache:
        return _cache["library_docs"]

    docs: list[dict] = []
    if not LIBRARY_INDEX.exists():
        _cache["library_docs"] = docs
        return docs

    try:
        with open(LIBRARY_INDEX, "r", encoding="utf-8") as f:
            index = json.load(f)
    except Exception:
        _cache["library_docs"] = docs
        return docs

    for meta in index:
        if not isinstance(meta, dict):
            continue
        uid = meta.get("id")
        if not uid:
            continue
        content_path = LIBRARY_DIR / f"{uid}.content.txt"
        try:
            text = content_path.read_text(encoding="utf-8") if content_path.exists() else ""
        except Exception:
            text = ""
        docs.append({
            "id": uid,
            "name": meta.get("name", ""),
            "type": meta.get("type", ""),
            "category": meta.get("category", ""),
            "preview": meta.get("preview", ""),
            "text": text,
        })

    _cache["library_docs"] = docs
    return docs


def _vuln_text(v: dict) -> str:
    parts = [
        v.get("cve_id", ""),
        v.get("description", ""),
        v.get("vendor", ""),
        v.get("product", ""),
        v.get("severity", ""),
        v.get("source", ""),
        v.get("vuln_status", ""),
    ]
    return _normalize_text(" ".join(str(p) for p in parts if p))


def _score(items: list[dict], keywords: list[str],
           text_getter: Callable[[dict], str]) -> list[tuple[int, dict]]:
    """按加权命中数评分：强特征（IP/CVE/ATT&CK ID）命中记 3 分，普通词记 1 分；
    总分相同则保留原顺序。"""
    scored = []
    for item in items:
        text = text_getter(item)
        score = 0
        for kw in keywords:
            if kw in text:
                score += 3 if _STRONG_FEATURE_RE.match(kw) else 1
        if score > 0:
            scored.append((score, item))
    scored.sort(key=lambda x: x[0], reverse=True)
    return scored


def _format_vuln(v: dict) -> str:
    lines = [f"- {v.get('cve_id', '未知CVE')}"]
    desc = v.get("description", "")
    if desc:
        preview = desc.strip().replace("\n", " ")
        if len(preview) > 220:
            preview = preview[:220] + "..."
        lines.append(f"  描述：{preview}")
    if v.get("cvss_score"):
        lines.append(f"  CVSS：{v['cvss_score']} ({v.get('severity', '')})")
    if v.get("product"):
        lines.append(f"  产品：{v['product']}")
    if v.get("published"):
        lines.append(f"  发布时间：{v['published']}")
    return "\n".join(lines)


def _format_library(doc: dict) -> str:
    lines = [f"- {doc.get('name', '未知资料')}（ID: {doc['id']}）"]
    preview = doc.get("preview", "") or doc.get("text", "")
    preview = preview.strip().replace("\n", " ")
    if len(preview) > 220:
        preview = preview[:220] + "..."
    if preview:
        lines.append(f"  摘要：{preview}")
    return "\n".join(lines)


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    # 保留到上一个完整换行处，避免截断条目
    cut = text.rfind("\n\n", 0, max_chars - 50)
    if cut < max_chars // 2:
        cut = text.rfind("\n", 0, max_chars)
    if cut <= 0:
        cut = max_chars
    return text[:cut] + "\n\n[知识库上下文过长，已截断]"


def build_knowledge_context(alert_data: dict,
                            max_total_chars: int = _MAX_TOTAL_CHARS,
                            top_vuln: int = _TOP_VULN,
                            top_library: int = _TOP_LIBRARY) -> dict:
    """根据告警数据构建漏洞库+资料库上下文。

    返回字典包含：
        text: 格式化后的上下文文本
        vuln_matches: 命中的漏洞条目列表
        library_matches: 命中的资料库文档列表
    """
    keywords = _extract_keywords(alert_data)

    vuln_scored = _score(_load_vuln_items(), keywords, _vuln_text)
    library_scored = _score(_load_library_docs(), keywords, lambda d: _normalize_text(f"{d.get('name', '')} {d.get('text', '')}"))

    top_vulns = [v for _, v in vuln_scored[:top_vuln]]
    top_docs = [d for _, d in library_scored[:top_library]]

    parts: list[str] = []
    parts.append("## 相关知识库上下文（供参考，请结合告警举证数据研判）")
    parts.append("")

    if top_vulns:
        parts.append("### 相关漏洞信息")
        for v in top_vulns:
            parts.append(_format_vuln(v))
        parts.append("")
    else:
        parts.append("### 相关漏洞信息\n未命中高相关漏洞。\n")

    if top_docs:
        parts.append("### 相关资料库文档")
        for doc in top_docs:
            parts.append(_format_library(doc))
        parts.append("")
    else:
        parts.append("### 相关资料库文档\n未命中高相关资料。\n")

    text = _truncate("\n".join(parts), max_total_chars)

    return {
        "text": text,
        "vuln_matches": top_vulns,
        "library_matches": top_docs,
        "keywords": keywords,
    }


def clear_cache():
    """清空模块级缓存，便于测试或外部手动刷新。"""
    _cache.clear()


if __name__ == "__main__":
    sample_alert = {
        "name": "SQL注入攻击（测试）",
        "type": "SQL注入攻击",
        "attck": "T1190",
        "src_ip": "10.67.201.61",
        "target_ip": "192.168.100.200",
        "process": "apache2",
        "commandLine": "/usr/sbin/apache2 -k start",
        "filePath": "/var/www/html/search.php",
        "description": "检测到针对 Web 应用的 SQL 注入尝试",
    }
    ctx = build_knowledge_context(sample_alert)
    print(json.dumps({
        "keywords": ctx["keywords"],
        "context": ctx["text"],
    }, ensure_ascii=False, indent=2))
