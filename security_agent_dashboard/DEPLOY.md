# Security Agent Dashboard 部署手册

> 适用对象：拿到本项目目录、需要把它跑起来的任何人。
> 本手册以 **Windows 本机实测跑通的流程**为准（2026-09-01 验证），Linux/macOS 差异见 §7。
> 读完 §1~§3 即可完成部署，全程约 10 分钟。

## 0. 部署完成后你会得到什么

- 一个安全运营智能体仪表盘：http://127.0.0.1:5000 （局域网其他机器用 `http://<本机IP>:5000`）
- 功能：真实 XDR 告警拉取与 AI 研判、告警处置（封禁/加白/关闭）、ATT&CK 映射、智能助理、资料库、漏洞库自动更新、Web 资产监测、IP-学生身份映射、报告生成
- 后台自动化：XDR 每 60 秒增量拉取 → AI 研判入库；页面每 30 秒自动同步；漏洞库按配置周期自动更新

## 1. 环境要求

| 项目 | 要求 | 说明 |
|------|------|------|
| 操作系统 | Windows 10/11（或 Linux/macOS） | 本手册以 Windows 为主 |
| Python | 3.10+ | 实测 3.13.5 可用 |
| MySQL | 5.7+ / 8.0+ | 服务需处于运行状态；**硬依赖**，程序启动即连库 |
| 外网 | 建议有 | 拉 XDR、漏洞源、大模型 API 需要；无外网时仅离线功能可用 |

## 2. 安装 Python 依赖（一条命令）

```bash
python -m pip install flask requests urllib3 mysql-connector-python python-dotenv beautifulsoup4 pdfplumber python-docx
```

> 资料库解析 PDF/Word 需要 pdfplumber、python-docx；缺了它们上传类资料会解析失败，但服务能起。

## 3. 准备数据库

程序首次启动会**自动建库建表**（库名默认 `security_dashboard`），你只需要准备一个有权限的 MySQL 账号。

**方式 A：沿用本项目自带账号（最快）**

项目目录里的 `start_dashboard.cmd` 已内置账号 `qwet / 123456`。只要你的 MySQL 里存在该账号且授权正确，直接跳到 §4。建账号的 SQL（在 root 里执行一次即可）：

```sql
CREATE USER IF NOT EXISTS 'qwet'@'localhost' IDENTIFIED BY '123456';
CREATE USER IF NOT EXISTS 'qwet'@'%' IDENTIFIED BY '123456';
GRANT ALL PRIVILEGES ON security_dashboard.* TO 'qwet'@'localhost';
GRANT ALL PRIVILEGES ON security_dashboard.* TO 'qwet'@'%';
FLUSH PRIVILEGES;
```

**方式 B：用自己的账号**

编辑 `start_dashboard.cmd` 里这两行，改成你的账号密码：

```
set DB_USER=你的用户名
set DB_PASSWORD=你的密码
```

> 账号需要的权限：对 `security_dashboard` 库的 ALL（建库、建表、改表、读写）。
> ⚠️ 常见坑：在 Workbench 里“新建连接”**不会**创建 MySQL 账号，必须用上面的 SQL（或 Users and Privileges 面板）真正建账号；报 `1045 Access denied` 一律是账号/密码不对，不是端口问题。

## 4. 启动

**双击 `start_dashboard.cmd`**（或在项目目录执行 `python start_server.py`，前提是 DB 环境变量已设）。

然后浏览器打开 http://127.0.0.1:5000 ，看到“平台在线”即成功。

- 日志：项目目录 `dashboard.log`
- 停止：任务管理器结束对应的 `python.exe` 进程，或 `taskkill /F /PID <pid>`（pid 用 `netstat -ano | findstr :5000` 查）

## 5. 配置说明（需要改才看）

| 配置 | 位置 | 说明 |
|------|------|------|
| 数据库账号 | `start_dashboard.cmd` 的 `DB_USER/DB_PASSWORD` | **app.py 不读 .env 的数据库配置**，只认进程环境变量 |
| XDR 对接 | `.env`（`XDR_BASE_URL/XDR_AK/XDR_SK/XDR_AUTH_CODE`）与 `data/xdr_config.json` | 随项目附带已配好的真实平台凭据；换平台时两处同步改 |
| 大模型 | 前端「智能助理」设置面板 → 保存到 `data/assistant_config.json` | 支持 OpenAI 兼容/Kimi/MiniMax/FastGPT；前端 API Key 脱敏展示 |
| 漏洞库调度 | `data/vuln_scheduler_config.json` 或前端「漏洞库」页 | enabled / interval_seconds / selected_sources |
| 监听端口 | `app.py` 末尾 `app.run(port=5000)` | 改完重启 |
| 身份映射表 | `data/identity_db.json`，可用 `data/student_ip_identity_demo.csv` 导入 | IP→姓名/学号/院系 |

> `.env`、`data/xdr_config.json`、`data/assistant_config.json` 含**明文密钥**。本仓库尚无 .gitignore，**推送任何远程仓库前必须先加 .gitignore 排除它们**。

## 6. 验收清单（照做一遍确认部署无误）

```bash
curl http://127.0.0.1:5000/                      # 期望：200，返回 HTML
curl http://127.0.0.1:5000/api/stats             # 期望：200，JSON 含 total/blocked 等字段
curl http://127.0.0.1:5000/api/xdr/scheduler/status
# 期望：running=true；last_error=null。若 last_error 有值，看 §8
curl -X POST http://127.0.0.1:5000/api/alarms/refresh
# 期望：{"ok":true,"count":N}，N 为本次拉到的真实告警数（平台无新告警时为 0，属正常）
```

页面侧：总览页有数据卡；「漏洞库」点“更新漏洞库”能拉回 NVD/CISA/CIRCL 数据（需外网）；「智能助理」发一句“当前安全态势”有应答。

> 演示需要告警数据但平台暂时没有时：`python seed_malware_alerts.py` 可造一批演示告警（会在库中标记来源，注意不要与真实数据混淆）。

## 7. Linux / macOS 与生产部署

- 依赖与 §2 相同；启动用 `DB_USER=xx DB_PASSWORD=xx python3 app.py`（或 nohup/screen/tmux）。
- 生产：`gunicorn -w 4 -b 0.0.0.0:5000 app:app` + Nginx 反代 + HTTPS；把 `data/` 与 `dashboard.log` 纳入备份。
- 纯静态导出（不经 Flask）：`python build_static.py` 生成 `static/index.html`。

```nginx
server {
    listen 80;
    server_name dashboard.example.com;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## 8. 常见坑（本机实测踩过并修复的）

| 现象 | 原因 | 处理 |
|------|------|------|
| 启动直接崩 / `1045 Access denied` | MySQL 账号不存在或密码不对（见 §3 警告） | 用 SQL 建账号或改 cmd 里的密码 |
| `1054 Unknown column 'ai_result'` | 旧版本代码的建表迁移用了 MariaDB 语法，MySQL 8 下静默失败 | **当前代码已修复**（自动补列）；若仍遇到，手动 `ALTER TABLE alerts ADD COLUMN ai_result VARCHAR(32);` |
| 双击 cmd 报 “'xxx' 不是内部或外部命令” | 批处理被存成了 UTF-8 中文注释或 LF 换行 | `start_dashboard.cmd` 必须保持 **ASCII 内容 + CRLF 换行** |
| 端口占用 | 5000 被占 | 换端口（§5）或先杀掉占用进程 |
| 告警数一直是 0 | XDR 平台近 7 天无新告警，或 `.env` 凭据失效 | 看 `/api/xdr/scheduler/status` 的 `last_error`；`total_fetched=0 且无错误` = 链路正常、平台没数据 |
| 页面数据不更新 | 正常情况 30 秒自动同步；也可点右上“刷新” | 仍不更新看浏览器控制台与 `dashboard.log` |
| 漏洞库更新失败/很慢 | 无外网，或 NVD 无限速 Key 被限流 | 可在 `.env` 补 `NVD_API_KEY`/`GITHUB_TOKEN`（可选） |

## 9. 目录速查

```
app.py                Flask 入口（54 个 API）
start_server.py       后台启动（清锁+detach）
start_dashboard.cmd   一键启动（内置 DB 环境变量）← 日常用它
db.py                 MySQL 操作（首启自动建库建表）
xdr_pipeline.py       XDR 拉取+AI 研判流水线（可独立 CLI 运行）
skills.py             智能助理技能
knowledge_context.py  研判 RAG 上下文（漏洞库+资料库召回）
vuln_updater.py       漏洞源拉取（NVD/CISA KEV/CIRCL/OSV）
seed_malware_alerts.py 演示告警造数
data/                 运行时配置与数据（备份重点）
dashboard.log         运行日志
```
