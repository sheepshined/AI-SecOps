# Security Agent Dashboard

A frontend-only security operations dashboard prototype for the "AI+安全大模型平台的智能体研究" challenge.

## Features

- 告警展示 (Alarm display) with severity, status, source IP and timestamps
- IP 封禁 (IP blocking / unblock management)
- ATT&CK 告警映射 (ATT&CK tactic/technique mapping)
- 误报剔除 (False-positive removal)
 - 报告生成 (Security report generation)
 - Web 资产监测 (URL 可用性 / WAF 覆盖 / SSL 证书探测)

## Run

```bash
python3 app.py
```

Then open http://127.0.0.1:5000 in your browser.

## Stack

- Python 3 + Flask (server only, no backend business logic)
- Vanilla HTML / CSS / JavaScript
- Lucide icons via CDN
