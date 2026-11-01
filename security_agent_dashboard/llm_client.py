import json
import time
import uuid
import requests
from requests.exceptions import HTTPError


def _log_usage(model: str, latency_ms: int, usage):
    """把每次 LLM 调用的模型名/耗时/token 用量追加到 data/llm_usage.jsonl（对标
    M507/AI-SOC-Agent 的逐告警成本日志；尽力而为，失败静默）。"""
    try:
        from datetime import datetime
        from pathlib import Path
        log_path = Path(__file__).resolve().parent / "data" / "llm_usage.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        rec = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "model": model,
            "latency_ms": latency_ms,
            "usage": usage,
        }
        with log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _is_fastgpt(config: dict) -> bool:
    """通过 provider 或 base_url 判断是否为 FastGPT."""
    return (config.get("provider") or "").lower() == "fastgpt" or "fastgpt" in (config.get("base_url") or "").lower()


def _extract_chat_id_and_raw(content: str):
    # 格式: 告警举证数据（chatId: xxx）：\n\n{json}
    if "）：" in content:
        head, raw = content.split("）：", 1)
        raw = raw.lstrip("\n ")
    else:
        head, raw = "", content
    chat_id = ""
    if "chatId:" in head:
        chat_id = head.split("chatId:", 1)[1].strip()
    return chat_id, raw


def _call_fastgpt(config: dict, messages: list) -> str:
    """调用 FastGPT Chat API（非标准 OpenAI 兼容格式）"""
    url = (config.get("base_url") or "").strip().rstrip("/")
    api_key = (config.get("api_key") or "").strip()
    if not url or not api_key:
        raise ValueError("FastGPT 调用缺少 base_url 或 api_key")

    user_content = ""
    for m in reversed(messages):
        if m.get("role") == "user":
            user_content = m.get("content", "")
            break
    chat_id, raw_data = _extract_chat_id_and_raw(user_content)
    if not chat_id:
        chat_id = uuid.uuid4().hex[:16]

    payload = {
        "chatId": chat_id,
        "stream": False,
        "detail": False,
        "messages": [{"role": "user", "content": raw_data}],
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + api_key,
    }
    _t0 = time.time()
    r = requests.post(url, json=payload, headers=headers, timeout=120, verify=False)
    r.raise_for_status()
    try:
        data = r.json()
    except Exception as e:
        raise RuntimeError(f"FastGPT 返回非 JSON: {r.text[:200]}") from e
    _usage = data.get("usage")
    if not _usage and isinstance(data.get("data"), dict):
        _usage = data["data"].get("usage")
    _log_usage(config.get("model") or "fastgpt", int((time.time() - _t0) * 1000), _usage)
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError(f"FastGPT 返回 choices 为空: {r.text[:200]}")
    msg = choices[0].get("message") or {}
    text = msg.get("content") or ""
    if not text.strip():
        text = msg.get("reasoning_content") or ""
    return text


def _call_openai_compatible(config: dict, messages: list) -> str:
    """标准 OpenAI 兼容接口调用"""
    base_url = (config.get("base_url") or "https://api.openai.com/v1").strip().rstrip("/")
    if not base_url.endswith("/v1"):
        base_url = base_url + "/v1"
    api_key = (config.get("api_key") or "").strip()
    model = config.get("model") or "gpt-4o-mini"
    url = base_url + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    temperature = 1.0 if model == "kimi-for-coding" else 0.5
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": 4096,
    }
    _t0 = time.time()
    r = requests.post(url, headers=headers, json=payload, timeout=120)
    r.raise_for_status()
    try:
        data = r.json()
    except Exception as e:
        raise RuntimeError(f"模型返回非 JSON: {r.text[:200]}") from e
    _log_usage(model, int((time.time() - _t0) * 1000), data.get("usage"))
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError(f"模型返回 choices 为空: {r.text[:200]}")
    msg = choices[0].get("message") or {}
    text = msg.get("content") or ""
    if not text.strip():
        text = msg.get("reasoning_content") or ""
    return text


def call_openai_compatible(config: dict, messages: list) -> str:
    """统一入口：FastGPT 或标准 OpenAI 兼容接口"""
    if _is_fastgpt(config):
        return _call_fastgpt(config, messages)
    return _call_openai_compatible(config, messages)


def call_openai_compatible_with_retry(config: dict, messages: list, max_retries: int = 3) -> str:
    for attempt in range(max_retries):
        try:
            return call_openai_compatible(config, messages)
        except HTTPError as e:
            if e.response.status_code == 429 and attempt < max_retries - 1:
                time.sleep((2 ** attempt) * 5)
                continue
            raise
