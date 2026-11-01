#!/usr/bin/env python3
"""XDR告警拉取 -> 智能助理模型研判 流水线模块

支持两种认证方式（二选一）：
  1. XDR连接码：xdr_auth_code / XDR_AUTH_CODE
  2. AK/SK直连：xdr_access_key + xdr_secret_key / XDR_AK + XDR_SK

可从 app.py 导入调用，也可直接当脚本运行:
    python xdr_pipeline.py
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import hmac
import json
import re
import sys
import time
import traceback
import uuid as _uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import quote, urlencode, urlparse

import requests
import urllib3
from llm_client import call_openai_compatible_with_retry
import db
import knowledge_context as kc

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Windows 控制台默认 GBK, 强制 UTF-8 输出避免 UnicodeEncodeError
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


# ═══════════════════════════════════════════════════
# AKSK 签名 (深信服XDR OpenAPI, 自包含实现)
# ═══════════════════════════════════════════════════

AUTH_CODE_PARAMS = "%s+%s+%s+%s+%s+%s+%s+%s"
AUTH_CODE_PARAMS_NUM = 14
EXTEND_HEADER = "algorithm=HMAC-SHA256, Access=%s, SignedHeaders=%s, Signature=%s"
TOTAL_STR = "HMAC-SHA256\n%s\n%s"


try:
    from Crypto.Cipher import AES  # type: ignore
except Exception:  # pragma: no cover
    AES = None


class AkskSigningError(ValueError):
    pass


def _sign_date_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def decode_auth_code(auth_code: str) -> tuple[str, str]:
    """将XDR连接码(十六进制)解码为 (access_key, secret_key)"""
    if not auth_code:
        raise AkskSigningError("connection code is empty")
    if AES is None:
        raise AkskSigningError("pycryptodome is required to decode XDR_AUTH_CODE")
    try:
        builders = binascii.unhexlify(auth_code).decode("utf-8").split("|")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise AkskSigningError("invalid hex-encoded connection code") from exc
    if len(builders) != AUTH_CODE_PARAMS_NUM:
        raise AkskSigningError("connection code format error")
    build_str = AUTH_CODE_PARAMS % (
        builders[0], builders[1], builders[2], builders[3],
        builders[4], builders[5], builders[6], builders[11],
    )
    aes_secret = hashlib.sha256(build_str.encode("utf-8")).digest()
    ak = _aes_cbc_decrypt(builders[9], aes_secret)
    sk = _aes_cbc_decrypt(builders[10], aes_secret)
    if not ak or not sk:
        raise AkskSigningError("connection code did not decode to AK/SK")
    return ak, sk


def _aes_cbc_decrypt(cipher_text: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, bytearray(AES.block_size))
    return cipher.decrypt(bytes.fromhex(cipher_text)).decode("utf-8")


def _sha256_hex_upper(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _hmac_sha256_hex(secret_key: str, data: str) -> str:
    mac = hmac.new(secret_key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256)
    return binascii.hexlify(mac.digest()).decode("utf-8").upper()


def _url_transform(url_str: str) -> str:
    path = urlparse(url_str).path
    if not path.endswith("/"):
        path += "/"
    return quote(path, encoding="utf-8")


def _query_str_transform(params: dict) -> str:
    ordered = sorted(params.items(), key=lambda item: str(item[0]))
    flat = []
    for key, value in ordered:
        if isinstance(value, (list, tuple)):
            for item in value:
                flat.append((str(key), str(item)))
        else:
            flat.append((str(key), str(value)))
    return urlencode(flat).replace("%3D", "=")


def _payload_transform(payload: str) -> str:
    """字节排序+去空格后SHA256 (深信服非标准payload hash)"""
    byte_values = sorted(payload.encode("utf-8"))
    compact = bytearray(v for v in byte_values if v != 32)
    return _sha256_hex_upper(bytes(compact))


class AkskSigner:
    """HMAC-SHA256 请求签名器"""

    def __init__(self, access_key: str, secret_key: str):
        self._ak = access_key
        self._sk = secret_key

    def sign(self, method: str, url: str, headers: dict | None = None,
             params: dict | None = None, json_body=None) -> dict[str, str]:
        headers = dict(headers or {})
        payload = json.dumps(json_body, ensure_ascii=True) if json_body is not None else ""
        host = urlparse(url).netloc

        # 注入必要头
        headers["sdk-host"] = host
        headers["sdk-content-type"] = headers.get("content-type", "application/json")
        sign_date = _sign_date_now()
        headers["sign-date"] = sign_date

        # 排序拼接
        header_keys = sorted(headers.items(), key=lambda x: x[0].lower())
        header_str = "".join(f"{k}:{v}\n" for k, v in header_keys)
        sign_header_str = ";".join(k for k, _ in header_keys)

        canonical = "".join([
            method.upper(), "\n",
            _url_transform(url), "\n",
            _query_str_transform(dict(params or {})), "\n",
            header_str,
            sign_header_str, "\n",
            _payload_transform(payload),
        ])

        hashed = _sha256_hex_upper(canonical.encode("utf-8"))
        total = TOTAL_STR % (sign_date, hashed)
        signature = _hmac_sha256_hex(self._sk, total)

        headers["Authorization"] = EXTEND_HEADER % (self._ak, sign_header_str, signature)
        return headers


# ═══════════════════════════════════════════════════
# XDR 客户端
# ═══════════════════════════════════════════════════

class XDRClient:
    def __init__(self, base_url: str, auth_code: str | None = None,
                 access_key: str | None = None, secret_key: str | None = None,
                 timeout: int = 60):
        self.base_url = base_url.rstrip("/")
        if auth_code:
            ak, sk = decode_auth_code(auth_code)
        elif access_key and secret_key:
            ak, sk = access_key, secret_key
        else:
            raise AkskSigningError(
                "必须提供 xdr_auth_code（连接码）或 xdr_access_key + xdr_secret_key（AK/SK）"
            )
        self.signer = AkskSigner(ak, sk)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False  # 自签证书环境

    def _request(self, method: str, path: str, json_body=None, params=None):
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        signed = self.signer.sign(method=method, url=url, headers=headers,
                                  params=params, json_body=json_body)
        resp = self.session.request(method=method, url=url, headers=signed,
                                    json=json_body, params=params,
                                    timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def list_alerts(self, page: int = 1, page_size: int = 5,
                    start_time: int | None = None,
                    end_time: int | None = None,
                    order_by: str | None = None,
                    order: str | None = None) -> dict:
        """拉取告警列表，支持分页、时间范围与排序"""
        page_size = max(5, page_size)
        body = {"page": page, "pageSize": page_size}
        if start_time is not None:
            body["startTime"] = int(start_time)
        if end_time is not None:
            body["endTime"] = int(end_time)
        if order_by:
            body["orderBy"] = order_by
        if order:
            body["order"] = order
        return self._request("POST", "/api/xdr/v1/alerts/list", json_body=body)

    def get_proof(self, uuid: str) -> dict:
        return self._request("GET", f"/api/xdr/v1/alerts/{uuid}/proof")


# ═══════════════════════════════════════════════════
# 智能助理模型研判
# ═══════════════════════════════════════════════════

def build_judgment_request(alert_data: dict, chat_id: str = "") -> dict:
    """构建模型研判的完整请求（用于前端展示请求/响应）"""
    system_prompt = (
        "你是安全运营专家。请根据以下深信服XDR告警举证数据，判断该告警的性质，"
        "给出威胁等级、攻击类型、ATT&CK技术（如有）、处置建议，并以简洁中文返回。"
        "最后必须给出明确的 AI 研判结果，只能是以下三者之一：攻击成功、攻击失败、尝试。"
        "请使用如下格式：\n研判结果: 攻击成功\n（或 研判结果: 攻击失败 / 研判结果: 尝试）"
        "\n在研判结果行的下一行必须给出你的置信度（0-100 的整数），格式：置信度: 85"
    )
    knowledge = kc.build_knowledge_context(alert_data)
    knowledge_text = knowledge.get("text", "")
    if knowledge_text:
        system_prompt += (
            "\n\n研判时可参考下方知识库上下文（漏洞库与资料库召回结果）。"
            "若上下文与告警无关，请忽略并基于举证数据本身判断。"
        )
    content = json.dumps(alert_data, ensure_ascii=False, indent=2)
    cid = f"{chat_id}-{_uuid.uuid4().hex[:8]}" if chat_id else _uuid.uuid4().hex
    user_content = f"告警举证数据（chatId: {cid}）：\n\n{content}"
    if knowledge_text:
        user_content += f"\n\n{knowledge_text}"
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]
    return {
        "system_prompt": system_prompt,
        "messages": messages,
        "chat_id": cid,
        "model_config": {"temperature": 0.3},
        "knowledge_context": knowledge,
    }


def call_model_judgment(alert_data: dict, model_config: dict,
                        chat_id: str = "") -> str:
    """使用智能助理配置的模型对单条告警进行研判"""
    request_info = build_judgment_request(alert_data, chat_id)
    return call_openai_compatible_with_retry(model_config, request_info["messages"])


def extract_verdict(resp) -> str:
    """保持兼容，若返回字符串则直接返回，否则尝试取 choices。"""
    if isinstance(resp, str):
        return resp
    try:
        return resp["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        return json.dumps(resp, ensure_ascii=False)


def extract_ai_result(resp) -> str:
    """从模型响应中提取 AI 研判结果值：攻击成功 / 攻击失败 / 尝试。"""
    text = extract_verdict(resp)
    # 移除可能的 markdown 加粗/斜体标记，提升格式兼容性
    cleaned = re.sub(r"[\*_]", "", text)
    match = re.search(r"研判结果[：:]\s*(攻击成功|攻击失败|失败|尝试)", cleaned)
    if match:
        val = match.group(1)
        return "攻击失败" if val == "失败" else val
    return ""


def extract_confidence(resp) -> int | None:
    """从模型响应中提取置信度（0-100 整数），缺失或非法时返回 None。"""
    text = extract_verdict(resp)
    cleaned = re.sub(r"[\*_]", "", text)
    match = re.search(r"置信度[：:]\s*(\d{1,3})\s*%?", cleaned)
    if not match:
        return None
    val = int(match.group(1))
    return val if 0 <= val <= 100 else None


def _matches_whitelist(item: dict, rules: list) -> dict | None:
    """确定性预评分（对标 AiSOC 的 deterministic scoring 层）：
    在调用 LLM 之前，用原始 XDR item 匹配加白规则；命中则完全不消耗模型调用。
    返回命中的规则，未命中返回 None。空字段表示任意。"""
    src_ip = (item.get('srcIp') or [''])[0] if isinstance(item.get('srcIp'), list) else (item.get('srcIp') or '')
    dst_ip = (item.get('dstIp') or [''])[0] if isinstance(item.get('dstIp'), list) else (item.get('dstIp') or '')
    src_port = (item.get('srcPort') or [''])[0] if isinstance(item.get('srcPort'), list) else (item.get('srcPort') or '')
    dst_port = (item.get('dstPort') or [''])[0] if isinstance(item.get('dstPort'), list) else (item.get('dstPort') or '')
    name = item.get('name', '') or item.get('threatTypeDesc', '') or ''
    for rule in rules or []:
        if not rule.get('enabled'):
            continue
        if rule.get('src_ip') and src_ip != rule['src_ip']:
            continue
        if rule.get('dst_ip') and dst_ip != rule['dst_ip']:
            continue
        if rule.get('src_port') and str(src_port) != str(rule['src_port']):
            continue
        if rule.get('dst_port') and str(dst_port) != str(rule['dst_port']):
            continue
        if rule.get('name_pattern') and rule['name_pattern'] not in name:
            continue
        if not any([rule.get('src_ip'), rule.get('dst_ip'), rule.get('src_port'),
                    rule.get('dst_port'), rule.get('name_pattern')]):
            continue
        return rule
    return None


# ═══════════════════════════════════════════════════
# 主流程
# ═══════════════════════════════════════════════════

def _validate_config(config: dict) -> dict:
    """校验并返回标准化XDR配置（连接码或AK/SK二选一）"""
    missing = []
    xdr_base_url = config.get("xdr_base_url", "") or config.get("XDR_BASE_URL", "")
    xdr_auth_code = config.get("xdr_auth_code", "") or config.get("XDR_AUTH_CODE", "")
    xdr_access_key = config.get("xdr_access_key", "") or config.get("XDR_AK", "")
    xdr_secret_key = config.get("xdr_secret_key", "") or config.get("XDR_SK", "")
    timeout = int(config.get("request_timeout", config.get("REQUEST_TIMEOUT", 60)))

    if not xdr_base_url:
        missing.append("xdr_base_url")
    if not xdr_auth_code and not (xdr_access_key and xdr_secret_key):
        missing.append("xdr_auth_code 或 (xdr_access_key + xdr_secret_key)")
    if missing:
        raise ValueError(f"缺少必填配置: {', '.join(missing)}")

    return {
        "xdr_base_url": xdr_base_url,
        "xdr_auth_code": xdr_auth_code,
        "xdr_access_key": xdr_access_key,
        "xdr_secret_key": xdr_secret_key,
        "request_timeout": timeout,
    }


def run_pipeline(xdr_config: dict, model_config: dict,
                 count: int = 5, output_path: str | None = None,
                 progress_callback: Callable[[str], None] | None = None,
                 list_alerts_kwargs: dict | None = None,
                 skip_uuids: set | None = None) -> dict:
    """运行XDR告警拉取 -> 智能助理模型研判流水线

    Args:
        xdr_config: XDR配置字典, 必填 xdr_base_url 以及 (xdr_auth_code 或 xdr_access_key/xdr_secret_key)
        model_config: 智能助理模型配置字典, 必填 provider/base_url/api_key/model
        count: 拉取告警条数
        list_alerts_kwargs: 可选, 透传给 list_alerts 的额外参数（时间范围、排序等）
        skip_uuids: 可选, 已研判过的告警 uuid 集合，这些告警不再调用 LLM
        output_path: 可选, 结果JSON保存路径
        progress_callback: 可选, 接收进度字符串的回调

    Returns:
        汇总结果字典
    """
    cfg = _validate_config(xdr_config)
    timeout = cfg["request_timeout"]

    def log(msg: str, end: str = "\n", flush: bool = False):
        if progress_callback:
            progress_callback(msg)
        else:
            print(msg, end=end, flush=flush)

    log("=" * 60)
    log("  XDR告警拉取 -> 智能助理模型研判 流水线")
    log(f"  拉取数量: {count} 条")
    log("=" * 60 + "\n")

    # 1. XDR
    log("[1/3] 初始化XDR签名客户端...")
    if cfg["xdr_auth_code"]:
        xdr = XDRClient(cfg["xdr_base_url"], auth_code=cfg["xdr_auth_code"], timeout=timeout)
    else:
        xdr = XDRClient(cfg["xdr_base_url"], access_key=cfg["xdr_access_key"],
                        secret_key=cfg["xdr_secret_key"], timeout=timeout)
    log("      ✓ AKSK签名就绪\n")

    # 2. 拉告警
    log(f"[2/3] 拉取告警列表 (pageSize={count})...")
    list_kwargs = dict(list_alerts_kwargs or {})
    list_kwargs.setdefault("page", 1)
    list_kwargs.setdefault("page_size", count)
    alerts_resp = xdr.list_alerts(**list_kwargs)
    if alerts_resp.get("code") != "Success":
        raise RuntimeError(f"拉取告警列表失败: {alerts_resp}")

    items = alerts_resp.get("data", {}).get("item", [])
    total = alerts_resp.get("data", {}).get("total", 0)
    log(f"      ✓ 平台共 {total} 条告警, 本次拉到 {len(items)} 条\n")

    if not items:
        log("      ⚠ 无告警数据，退出")
        return {"total_fetched": 0, "total_success": 0, "total_failed": 0, "results": []}

    # 3. 逐条研判
    log("[3/3] 逐条研判中...\n")
    try:
        whitelist_rules = db.load_whitelist_rules()
    except Exception:
        whitelist_rules = []
    results = []

    for idx, item in enumerate(items, 1):
        uuid = item.get("uuId", "unknown")
        name = item.get("name", "未知告警")
        severity = item.get("severity", 0)

        log(f"  [{idx}/{len(items)}] {name}")
        log(f"           UUID: {uuid}  严重度: {severity}")

        record = {"index": idx, "uuid": uuid, "name": name,
                  "severity": severity, "alert_item": item,
                  "proof": None, "model_response": None,
                  "verdict": "", "ai_confidence": None, "error": None}

        # 确定性预评分：命中加白规则的告警直接跳过 LLM（不花模型调用）
        hit_rule = _matches_whitelist(item, whitelist_rules)
        if hit_rule:
            log(f"           -> 命中加白规则「{hit_rule.get('reason') or hit_rule.get('id', '')}」，跳过 LLM")
            record["verdict"] = f"命中加白规则（{hit_rule.get('reason') or hit_rule.get('id', '')}），确定性跳过模型研判"
            record["ai_judged"] = 1
            record["ai_result"] = ""
            try:
                db.upsert_alarm(db.record_from_xdr_result(record))
            except Exception as db_err:
                log(f"           ⚠ 加白跳过记录入库失败: {db_err}")
            results.append(record)
            log("✓")
            if idx < len(items):
                time.sleep(0.5)
            continue

        # 如已研判且数据库已有结论，复用结论，不再请求 LLM
        if skip_uuids and uuid in skip_uuids:
            log(f"           -> 已研判，跳过 LLM 调用")
            existing = db.get_alarm(uuid)
            if existing:
                record["model_response"] = existing.get("model_response", "")
                record["verdict"] = existing.get("verdict", "")
                record["ai_result"] = existing.get("ai_result", "")
                # 保留已入库的 XDR 举证详情，避免被后面的空 proof 覆盖
                if existing.get("proof"):
                    record["proof"] = existing["proof"]
                if existing.get("xdr_raw"):
                    record["xdr_raw"] = existing["xdr_raw"]
                record["ai_judged"] = 1
            else:
                record["verdict"] = "已研判（结论复用）"
            record["model_response"] = record.get("model_response") or record.get("verdict", "")
            log("✓")
            preview = record["verdict"][:200].replace("\n", " ")
            log(f"           -> {preview}...")
            results.append(record)
            log("")
            if idx < len(items):
                time.sleep(1)
            continue

        try:
            log(f"           -> 拉取举证...", end=" ")
            proof_resp = xdr.get_proof(uuid)
            record["proof"] = proof_resp
            log("✓")

            merged = {
                "message": proof_resp.get("message", "成功"),
                "code": proof_resp.get("code", "Success"),
                "data": proof_resp.get("data", {}),
            }

            request_info = build_judgment_request(merged, chat_id=uuid)
            record["request"] = request_info

            # 先写入原始告警，保证即使 LLM 失败也能展示
            try:
                raw_record = db.record_from_xdr_result(record)
                raw_record['ai_judged'] = 0
                db.upsert_alarm(raw_record)
            except Exception as db_err:
                log(f"           ⚠ 原始告警入库失败: {db_err}")

            log(f"           -> 智能助理模型研判...", end=" ", flush=True)
            verdict = call_model_judgment(merged, model_config, chat_id=uuid)
            record["model_response"] = verdict
            record["verdict"] = extract_verdict(verdict)
            record["ai_result"] = extract_ai_result(verdict)
            record["ai_confidence"] = extract_confidence(verdict)
            log("✓")

            # 更新为已研判状态
            try:
                judged_record = db.record_from_xdr_result(record)
                db.upsert_alarm(judged_record)
            except Exception as db_err:
                log(f"           ⚠ 研判结果入库失败: {db_err}")

            preview = record["verdict"][:200].replace("\n", " ")
            log(f"           -> {preview}...")

        except Exception as e:
            record["error"] = f"{type(e).__name__}: {e}"
            log(f"           ✗ {record['error']}")
            traceback.print_exc()

        results.append(record)
        log("")
        if idx < len(items):
            time.sleep(3)

    # 4. 汇总
    ok = sum(1 for r in results if r["error"] is None)
    fail = len(results) - ok
    summary = {"total_fetched": len(items), "total_success": ok,
               "total_failed": fail, "results": results}

    log(f"\n{'=' * 60}")
    log(f"  汇总: 成功 {ok}/{len(items)}, 失败 {fail}")
    log(f"{'=' * 60}\n")

    for r in results:
        s = "✓" if r["error"] is None else "✗"
        log(f"  {s} [{r['index']}] {r['name']} (严重度:{r['severity']})")
        if r["verdict"]:
            for line in r["verdict"].strip().split("\n"):
                log(f"      {line}")
        if r["error"]:
            log(f"      ERROR: {r['error']}")
        log("")

    out_path = Path(output_path) if output_path else Path(__file__).resolve().parent / "pipeline_result.json"
    out_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    log(f"  📁 结果已保存: {out_path.resolve()}")

    return summary


def _load_dotenv(env_path: Path) -> dict[str, str]:
    env = {}
    if not env_path.exists():
        return env
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip()
    return env


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XDR告警 -> 智能助理模型研判流水线")
    parser.add_argument("--xdr-base-url", type=str, default=None,
                        help="XDR平台地址")
    parser.add_argument("--xdr-auth-code", type=str, default=None,
                        help="XDR连接码")
    parser.add_argument("--xdr-access-key", type=str, default=None,
                        help="XDR Access Key (AK)")
    parser.add_argument("--xdr-secret-key", type=str, default=None,
                        help="XDR Secret Key (SK)")
    parser.add_argument("--count", type=int, default=5,
                        help="拉取告警条数 (默认5)")
    parser.add_argument("--output", type=str, default=None,
                        help="结果JSON输出路径")
    parser.add_argument("--env", type=str, default=None,
                        help="指定.env文件路径")
    parser.add_argument("--model-provider", type=str, default=None,
                        help="模型提供商，例如 openai")
    parser.add_argument("--model-base-url", type=str, default=None,
                        help="模型base_url")
    parser.add_argument("--model-api-key", type=str, default=None,
                        help="模型API Key")
    parser.add_argument("--model", type=str, default=None,
                        help="模型名")
    args = parser.parse_args()

    env_path = Path(args.env) if args.env else Path(__file__).resolve().parent / ".env"
    cfg = _load_dotenv(env_path)
    xdr_cfg = {
        "xdr_base_url": args.xdr_base_url or cfg.get("XDR_BASE_URL", ""),
        "xdr_auth_code": args.xdr_auth_code or cfg.get("XDR_AUTH_CODE", ""),
        "xdr_access_key": args.xdr_access_key or cfg.get("XDR_AK", ""),
        "xdr_secret_key": args.xdr_secret_key or cfg.get("XDR_SK", ""),
        "request_timeout": int(cfg.get("REQUEST_TIMEOUT", 60)),
    }
    model_cfg = {
        "provider": args.model_provider or cfg.get("MODEL_PROVIDER", "openai"),
        "base_url": args.model_base_url or cfg.get("MODEL_BASE_URL", ""),
        "api_key": args.model_api_key or cfg.get("MODEL_API_KEY", ""),
        "model": args.model or cfg.get("MODEL_MODEL", ""),
    }
    run_pipeline(xdr_cfg, model_cfg, count=args.count, output_path=args.output)
