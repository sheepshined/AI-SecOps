 # 安全运营智能助理使用说明

 ## 1. 入口

 打开平台首页：http://127.0.0.1:5000/

 左侧导航栏新增「智能助理」菜单，点击后右侧会弹出助理面板，同时菜单会高亮。

 页面右下角也有悬浮的机器人按钮（`assistant-fab`），同样可以打开/关闭助理面板。

 ## 2. 双模式运行

 助理面板支持两种工作模式：

 - **规则模式（默认）**：通过本地关键词/正则匹配，直接查询平台数据或执行操作，无需联网。
 - **大模型模式**：调用配置的大模型 API，模型自动理解问题并返回操作指令。

 切换方式：点击助理面板右上角的齿轮图标，在设置区打开「启用大模型」开关。

 ## 3. 模型配置

 在设置区可以添加多个模型配置，支持以下服务商：

 - **OpenAI / 兼容 OpenAI**（如 OpenAI、Azure OpenAI、智谱、DeepSeek 等 OpenAI 兼容服务）
 - **Kimi (Moonshot)**
 - **MiniMax**

 点击「当前模型」下拉框右侧的 **「添加模型」** 按钮即可展开表单；如果当前没有任何模型配置，打开设置区时会自动展开空白表单。选择服务商后会自动填入默认的 Base URL 和模型名。

 配置字段：

 | 字段 | 说明 |
 |------|------|
 | 名称 | 自定义备注，如「OpenAI GPT-4o」 |
 | 服务商 | openai / kimi / minimax |
 | Base URL | API 地址，如 `https://api.openai.com/v1`、`https://api.moonshot.cn/v1` |
 | API Key | 对应模型的密钥 |
 | 模型名 | 如 `gpt-4o-mini`、`moonshot-v1-8k`、`abab6.5s-chat` |

 保存后，该模型会自动被设为「当前激活模型」。下拉切换模型时，只需点击对应配置即可自动激活。

 > 注意：API Key 只在后端完整存储，前端列表会做脱敏展示。编辑已有配置时如果留空 API Key 输入框，系统会保留原 Key，不会误清空。

 ## 4. 支持的对话指令

 规则模式下可直接发送：

 - 「今天有多少告警」「当前安全态势」 -> 查看统计
 - 「查看高危告警」「待处理告警」 -> 按条件列告警
 - 「封禁 IP 1.2.3.4」 -> 封禁指定 IP
 - 「把 ALT-20260821-005 标记为误报」 -> 标记误报
 - 「关闭告警 ALT-20260821-001」 -> 关闭告警
 - 「哪些 IP 被封禁了」 -> 查看封禁列表
- 「今天哪个学生受到了攻击」「今日受攻击学生」 -> 结合 IP-ID 映射表查询今天受攻击的学生
 - 「ATT&CK 哪个技术最多」 -> ATT&CK 统计
 - 「切换到告警展示」 -> 自动切换左侧页面

 大模型模式下可以自然语言提问，模型会结合平台实时数据回答；如果要求执行操作，模型会输出 JSON 命令，前端自动执行。

 大模型可执行的 JSON 动作：

 ```json
 {"action":"block_ip","ip":"x.x.x.x"}
 {"action":"unblock_ip","ip":"x.x.x.x"}
 {"action":"false_positive","id":"ALT-20260821-001"}
 {"action":"close_alarm","id":"ALT-20260821-001"}
 ```

 ## 5. 后端接口

 - `GET /api/config/models`：列出模型配置（API Key 已脱敏）
 - `POST /api/config/models`：保存/更新模型配置
 - `DELETE /api/config/models/<id>`：删除配置
 - `GET /api/config/active_model`：获取当前激活模型（含完整 Key，仅后端/服务器调用）
 - `POST /api/assistant/chat`：大模型对话代理

 ## 6. 配置文件

 模型配置存储在本地 JSON 文件：

 `data/assistant_config.json`

 该文件由后端自动创建，无需手动编辑。

## 7. 服务重启

如果修改了 `app.py` 或静态文件想让后端生效，可执行：

```bash
screen -S dashboard5000 -X quit 2>/dev/null; sleep 1
cd /Users/zhangshanshan/Documents/AI_xinyu/security_agent_dashboard
screen -dmS dashboard5000 python3 -u app.py
```

## 8. 资料库（AI 研判）

左侧导航新增「资料库」，可上传文本、PDF、Word、Markdown、JSON、CSV、代码文件等。

### 8.1 使用方式

1. 点击「资料库」进入页面。
2. 点击「上传资料」或拖拽文件到上传区，文件会自动保存到 `data/library/`。
3. 文件列表中点击「预览」查看提取的文本内容。
4. 点击列表中的「AI 研判」或在预览面板中点击「AI 研判」，会调用当前激活的大模型对文件内容进行安全分析。
5. 搜索框支持按资料名称和内容进行全文检索。
6. 可下载原文件或删除不再需要的资料。

### 8.2 支持的文件格式

- 文本类：`txt`、`md`、`json`、`csv`、`log`、`xml`、`yml`/`yaml`
- 代码文件：`py`、`js`、`html`、`css`
- 文档：`pdf`、`docx`
- 其他：作为普通文件上传，不提供文本预览

### 8.3 后端接口

- `GET /api/library`：列出所有资料
- `POST /api/library/upload`：上传文件（FormData，字段名 `file`）
- `GET /api/library/<id>`：下载原文件
- `GET /api/library/<id>/content`：获取提取的文本内容
- `DELETE /api/library/<id>`：删除资料
- `GET /api/library/search?q=...`：按名称/内容搜索
- `POST /api/library/<id>/analyze`：调用当前激活模型进行 AI 研判

### 8.4 助理引用资料库

进入「智能助理」后，系统提示词会自动注入当前资料库概览（文件数量、文件名列表），大模型在回答时可以结合资料库内容给出更准确的研判与建议。

### 8.5 IP-ID 身份映射表自动导入

上传 CSV 文件到资料库时，如果表头包含 **IP** 与 **姓名**（可选学号、院系/班级等列），系统会自动把映射写入 `data/identity_db.json`，用于：

- 智能助理「IP 查询姓名学号」技能
- 智能助理「今天哪个学生受到了攻击」技能（根据告警 target_ip 反查学生身份）

CSV 表头支持中英文，例如：

```csv
ip,name,student_id,department
10.0.1.52,李四,2021001002,软件学院
```

上传成功后接口会返回 `identity_imported` 字段，表示本次导入的映射条数。

---

## 安全提醒

你的 API Key 在之前的聊天记录以及本地的 `data/assistant_config.json` 中已完整暴露。建议立即前往 Moonshot 控制台将该 Key 作废并重新生成，避免被他人盗用。

 静态文件（HTML/CSS/JS）修改后刷新浏览器即可生效。


## 漏洞库自动更新

漏洞库已接入 NVD、CISA KEV、CIRCL 三个数据源。调度器默认每 6 小时自动拉取一次，也可在「漏洞库」页面手动点击「更新漏洞库」。

新增后端接口：
- `POST /api/vulns/scheduler/restart`：手动触发调度器健康检查/重启。

漏洞库列表仍以“数据源资料文件”为粒度展示（例如一条 NVD、一条 CISA、一条 CIRCL），点击「预览」会解析并展示结构化 CVE 列表（CVE ID、严重等级、CVSS、发布时间、描述），底部可展开原始 JSON。
