# AI SecOps 智能体平台 — 学习引导手册

> 面向对象：要「吃透」这套代码的人（本人、队友、答辩前突击）
> 编写日期：2026-09-20
> 核实基准：本手册所有事实均在 **2026-09-20** 对照 `security_agent_dashboard/` 现行代码逐条实测过；行号以当日代码为准。
> **2026-09-28 增补**：项目完成一轮对标开源的升级（处置硬校验 / 加白预评分 / 置信度 / RAG 修复 / 测试套件 / Docker），全部改动与出处见 [§11 对标开源升级记录](#11-对标开源升级记录2026-09-28)。涉及差异的章节均已就地标注。
> 与交付文档的关系：`docs/01~04` 是**参赛交付文档**；本手册是**学习手册**，两者内容分工不同。交付文档中被本手册核实出的错误已就地修正，完整清单见 [§8 文档与代码出入登记表](#8-文档与代码出入登记表)。

---

## 0. 先读这一页：这套代码到底是什么

一句话：**一个 Flask 单体应用，定时从深信服 XDR 拉告警 → 拼装"告警举证 + 知识库召回"的 Prompt → 调大模型研判 → 结果入库 → 前端展示与人工处置。**

它不是一个「AI 决定一切」的系统。真实的分工是：

| 环节 | 谁在做 | 代码位置 |
|------|--------|----------|
| 拉告警、拉举证 | 确定性代码 + HMAC 签名 | `xdr_pipeline.py:176-224` |
| 拼 Prompt、注入知识库 | 确定性代码（规则检索，**不是**向量检索） | `xdr_pipeline.py:231-261`、`knowledge_context.py:314-360` |
| 判性质、写结论 | 大模型（唯一的"智能"环节） | `llm_client.py:102-117` |
| 结论结构化 | 正则表达式 | `xdr_pipeline.py:281-290` |
| 处置动作（封禁/加白/关闭） | 确定性代码，**无人工二次确认，也无风险评估** | `app.py:1038-1104` |
| 前端展示、人工点按钮 | 原生 JS + Flask 路由 | `static/js/*.js`、`app.py` 各路由 |

**学习时最容易走偏的三个认知：**

1. **这不是 RAG（至少不是通常意义的 RAG）。** `knowledge_context.py` 全部实现是「正则切词 + 同义词表扩展 + 子串命中计数排序」，没有 embedding、没有向量库、没有 rerank。它有效，但要知道它的能力边界（见 `knowledge_context.py:258-271` 的 `_score`，评分就是 `sum(1 for kw in keywords if kw in text)`）。
2. **智能助理有两条完全独立的路径。** 「技能优先」（关键词命中直接执行，不调 LLM）与「大模型 JSON 命令」（LLM 输出 `{"action":...}` 再执行）。两者的判定与执行代码不共享（`app.py:1264-1343`）。同一件事（比如标误报）在两条路径上的副作用甚至不同（见 §8 登记表 #21）。
3. **平台变量状态全部在进程内存里。** `ALARMS` / `BLOCKED` / `WHITELIST_RULES` 是 app.py 的模块级全局变量（`app.py:211`、`app.py:354-361`），DB 只是持久层。所以「改了数据库但页面没变」是常见现象，必须调 `refresh_alarms()` 或 `POST /api/alarms/refresh`。

---

## 1. 阅读路径（谁先读什么）

按「先跑起来再往里看」的顺序，不要一上来读 `app.py`（1933 行，会淹死人）。

| 顺序 | 读什么 | 目的 | 预估 |
|------|--------|------|------|
| 1 | `README.md`、`DEPLOY.md` | 知道这系统对外承诺什么、怎么起 | 10 min |
| 2 | **实验 1、2、3**（见 §6） | 亲手跑出东西，建立"我能改"的信心 | 30 min |
| 3 | `docs/01_设计文档.md` §1–§3 | 建立架构骨架（注意配合 §8 的修正项一起看） | 40 min |
| 4 | `xdr_pipeline.py` **全文**（557 行） | **主线**：一次研判的完整生命周期，读透这一个文件就懂一半 | 2 h |
| 5 | `knowledge_context.py` 全文（384 行） | 理解"知识库增强"到底做了什么 | 1.5 h |
| 6 | `llm_client.py` 全文（117 行） | 最小文件，理解双协议适配与重试 | 20 min |
| 7 | `db.py` 全文（610 行） | 数据模型 + 前后端字段名转换 + 幂等策略 | 2 h |
| 8 | `app.py` **按主题分段读**（别线性读） | 见 §4 精读清单的分段建议 | 4 h |
| 9 | `skills.py`、`vuln_*.py` | 技能系统与漏洞库三源 | 2.5 h |
| 10 | `static/js/app.js` + `templates/index.html` | 前端如何消费 API | 2 h |

**如果只有 3 小时**（答辩前突击）：读 4 → 5 → 8（只读 `app.py:1624-1886` 的 XDR 段），再跑实验 1、3、5。

---

## 2. 概念地图：领域词 → 代码位置

把「安全运营的黑话」和「代码里的东西」对上，之后读代码就不需要猜了。

### 2.1 安全领域概念

| 概念 | 在本项目里指什么 | 代码位置 |
|------|------------------|----------|
| **XDR 平台** | 深信服 XDR，外部告警源，通过 OpenAPI 拉取 | `xdr_pipeline.py:176-224` |
| **AK/SK 签名** | 深信服私有 HMAC-SHA256 签名规范，自研实现不依赖 SDK | `xdr_pipeline.py:131-169` |
| **连接码** | 16 进制字符串，AES-CBC 解密后得到 AK/SK，用户只填一个值 | `xdr_pipeline.py:67-88` |
| **举证（proof）** | XDR 对某条告警的原始证据包（进程/命令行/文件/网络连接等） | `xdr_pipeline.py:223-224`，`GET /alerts/{uuid}/proof` |
| **研判** | 让大模型判「这条告警是攻击成功 / 攻击失败 / 尝试」 | `xdr_pipeline.py:264-290` |
| **误报 / 加白** | 把某类告警规则化地标为 `false_positive`，后续同类告警自动加白 | `app.py:246-297` |
| **ATT&CK** | MITRE 攻击技术库，把告警映射到 T1xxx 技术 ID，前端画矩阵 | `app.py:302-347`；数据 `static/data/attack_subtechniques.json` |
| **CVE / CVSS / KEV** | 漏洞编号 / 严重度评分 / CISA「已知被在野利用」清单 | `vuln_updater.py:160-238` |
| **WAF** | Web 应用防火墙；本项目用一条 SQL 注入探针**实测**它是否拦截 | `app.py:684-723` |
| **SOAR** | 自动化编排响应；本项目**未实现**，封禁只是写自己的库 + 伪造接口 | `app.py:589-603` 是"伪造深信服防火墙" |

### 2.2 代码概念

| 概念 | 说明 | 代码位置 |
|------|------|----------|
| **主循环 / 调度线程** | 3 个后台线程：XDR 研判（60s）、漏洞库更新（可配）、漏洞库看门狗 | `app.py:1828-1879`、`vuln_scheduler.py:194-281` |
| **幂等入库** | `INSERT ... ON DUPLICATE KEY UPDATE`，重复拉取不产生脏数据 | `db.py:256-276` |
| **决策保护** | 重新拉取时保留用户的加白状态与已有研判结论，不被空值覆盖 | `db.py:506-537` |
| **增量水位线（watermark）** | 用 `MAX(update_time)` 作为下次拉取的起始时间 | `db.py:579-587` + `app.py:1806-1825` |
| **跳过已研判** | 已研判的 uuid 集合，命中则复用 DB 结论、不再花 LLM 钱 | `db.py:590-598` + `xdr_pipeline.py:399-422` |
| **文件锁 + PID 探活** | 多 worker 下保证只有一个调度线程 | `app.py:1764-1788`、`vuln_scheduler.py:97-122` |
| **脱敏 / 掩码回填** | API Key 只显示前 4 位；编辑时若提交的是掩码则保留原值 | `app.py:817-822`、`app.py:1166-1167`、`app.py:1677-1679` |
| **字段名转换层** | DB 用 `src_ip`/`ai_judged`，前端要 `src`/`aiJudged` | `db.py:441-486` `row_to_frontend()` |
| **双协议适配** | FastGPT 非标准协议 vs OpenAI 兼容协议 | `llm_client.py:8-10`、`26-65` |
| **进程内缓存** | RAG 的漏洞/资料数据缓存在模块级 dict，需显式清 | `knowledge_context.py:86`、`363-365` |

---

## 3. 分阶段学习路线

四个阶段，每阶段给「读什么 → 做什么 → 通关检验」。**通关检验的答案都能从代码里找到**，答不出来就说明还没读透，别跳。

### L1 — 能跑起来、能看懂一次请求（1 天）

**读**：`README.md`、`DEPLOY.md`、`xdr_pipeline.py`（全文）、`llm_client.py`（全文）

**做**：实验 1、2、3

**通关检验**（答案位置已标注，先自己答）：

1. 一次完整的自动研判，从线程醒来到底层写库，依次调用了哪些函数？（链路见 `xdr_pipeline.py:322-498`）
2. 为什么拉告警能拿到数据、拉举证也能拿到数据，但你不配 `XDR_AUTH_CODE` 也能跑？（`xdr_pipeline.py:177-188` 的两种认证分支）
3. 大模型返回的是 Markdown 长文，`ai_result` 字段里的「攻击成功」是从哪来的？（`xdr_pipeline.py:281-290` 的正则；注意它只认 `研判结果：` 这个前缀）
4. 调度器第一次跑和之后跑，`startTime` 参数有什么不同？为什么要这样设计？（`app.py:1816-1819`：首次回溯 7 天，之后以库里最大 `update_time` 为水位线）
5. `llm_client.py:114` 的 `e.response.status_code == 429` 之外的状态码会怎样？（直接 `raise`，不重试——所以 401/500 会一路抛到入库失败分支 `xdr_pipeline.py:464-467`）

### L2 — 能改一条链路、能解释数据模型（2 天）

**读**：`db.py`（全文）、`app.py` 的告警/加白/封禁三段（`app.py:210-603`）

**做**：实验 4、7

**通关检验**：

1. 前端拿到的 `src` / `aiJudged` 字段名，在数据库里叫什么？在哪一层做的转换？（`db.py:447-449`）
2. 同一批告警重复拉取两次，为什么 `verdict` 不会被清空？（`db.py:528-537` 的决策保护；注意它只保护 `false_positive` 状态，`blocked` / `closed` 不保护）
3. 标记误报时，除了改当前告警，还发生了什么连锁动作？（`app.py:457-485` → 建规则 → `_apply_whitelist_to_alarms()` 批量刷状态 → 写回 DB）
4. 一条加白规则的「命中」是怎么判定的？空字段代表什么？（`app.py:246-268`，空字段=任意）
5. 为什么 `refresh_alarms()` 在几乎每个写操作后面都被调用？（因为平台状态在内存全局变量里，见 §0 第 3 点）

### L3 — 能吃透「知识库增强」和「技能/助理」（2 天）

**读**：`knowledge_context.py`（全文）、`skills.py`（全文）、`app.py:1028-1426`

**做**：实验 2、6

**通关检验**：

1. `build_knowledge_context()` 返回的 `text` 被插到 Prompt 的哪个位置？（`xdr_pipeline.py:239-250`：system prompt 里加一句说明，**正文塞在 user message 末尾**——注意这个设计不是典型 RAG 做法，想想为什么）
2. 告警里出现「SQL注入攻击（测试）」，会扩展出哪些关键词？（`knowledge_context.py:49-83` 的同义词表；实测见 §6 实验 2）
3. 召回上限是多少字符？超了怎么截？（`knowledge_context.py:22`、`302-311`）
4. 智能助理收到 `"今天哪个学生受到了攻击"` 时，走技能路径还是 LLM 路径？依据是什么？（`app.py:1268-1294` 的关键词匹配，关键词见 `skills.py:47`）
5. 同一个「受攻击学生」业务，为什么有两套实现、口径还不一样？（`skills.py:205-265` 用 `target_ip` 查 `identity_db.json`；`app.py:1381-1421` 用 `src_ip` 查 RAG 召回的 CSV 文本。见 §8 #20）

### L4 — 能重写、能扩展、能答辩（2–3 天）

**读**：全文扫尾 + `static/js/app.js` + `vuln_updater.py` + `vuln_scheduler.py`

**通关检验**（答辩级）：

1. 这套系统的「智能」到底在哪里？如果把大模型换成一个 `if severity > 80: return "攻击成功"` 的规则，哪些功能会真正退化？（提示：`xdr_pipeline.py:231-261`、`app.py:1107-1145`、`app.py:1489-1492` 三处用了 LLM）
2. 加白规则是「安全」功能还是「安全风险」功能？如果攻击者能构造告警名匹配已有白名单会怎样？（`app.py:264-267` 的 `name_pattern` 子串匹配是宽匹配）
3. 漏洞库更新线程和 XDR 研判线程都用「文件锁 + PID 探活」，这套机制在 Windows 上有什么坑？（实验 4 的结论 + `app.py:1775-1780`）
4. 现在要把它从"演示可用"推到"生产可用"，最该先做哪三件事？（对照 `docs/04_总结报告.md` §5.3 已知缺陷表逐条评估；注意 `docs/04` 自认无 RBAC、无测试、明文密钥）
5. 如果要把 RAG 换成真的向量检索，最小改动面是哪里？（`knowledge_context.py:258-271` 是唯一的评分点，`build_knowledge_context` 的输出契约被 `xdr_pipeline.py:239` 和 `app.py:1410` 两个调用方依赖）

---

## 4. 精读代码清单

按价值排序。`★` = 必读，`☆` = 值得读，`△` = 读时注意有坑。

### 4.1 主线：一次告警研判的生命周期

| 位置 | 解决的问题 | 值得学的机制 | 坑 |
|------|-----------|--------------|-----|
| ★ `xdr_pipeline.py:47-50, 96-169` | 深信服签名怎么算 | 完整 Canonical String 拼装：URL/Query/Header 各自排序转义，payload 做「字节排序 + 去空格 + SHA256」这种非标准哈希 | `_payload_transform` 是深信服特有实现，别按 AWS SigV4 直觉理解 |
| ★ `xdr_pipeline.py:67-93` | 连接码怎么变成 AK/SK | 14 段 `\|` 分隔 → 取 0-6 与 11 段拼串 → SHA256 当 AES key → CBC 解密第 9/10 段得到 AK/SK | IV 是全零 `bytearray(AES.block_size)`；`pycryptodome` 缺失时抛 `AkskSigningError`（不是 ImportError） |
| ★ `xdr_pipeline.py:231-261` | Prompt 怎么拼 | system 只给规则 + 一句话说明知识库；举证 JSON 与知识库正文都塞进 user message | 知识库正文在 **user** message，不在 system；`temperature: 0.3` 只在 `model_config` 里躺着，`llm_client` 实际用自己算的温度（`llm_client.py:79`）→ 这是个没生效的配置 |
| ★ `xdr_pipeline.py:281-290` | 从长文里抠出结论 | 先 `re.sub(r"[\*_]", "")` 去掉 Markdown 强调符再匹配，容忍 `失败` 简写 | 必须出现 `研判结果：` 前缀，否则返回空串（空串会写进 `ai_result`） |
| ★ `xdr_pipeline.py:322-498` | 主流程编排 | 先写原始告警（`ai_judged=0`）再调 LLM，保证 LLM 挂了也能看到告警；每条之间 `sleep(3)` 限速 | 单条异常被 `try/except` 吞成 `record["error"]`，整体继续（fail-safe） |
| ★ `xdr_pipeline.py:399-422` | 不重复花 LLM 钱 | 已研判 uuid 直接复用 DB 结论，且**回填已有的 proof**（避免被空 proof 覆盖） | 跳过分支也 `sleep(1)` |
| ☆ `xdr_pipeline.py:501-557` | CLI 模式配置加载 | 自写 40 行 `.env` 解析（不依赖 python-dotenv） | 这是**唯一**读 `.env` 的地方；Web 服务不读 `.env`（见 §8 #12） |
| ★ `llm_client.py:68-99` | 兼容各家模型 | `base_url` 不以 `/v1` 结尾就自动补 `/v1`；`content` 为空则回退 `reasoning_content` | 补 `/v1` 这个行为对内网自建网关是隐形陷阱；温度硬编码（`kimi-for-coding` → 1.0，其余 0.5） |
| ★ `llm_client.py:109-117` | 限流重试 | 只在 429 时退避：`sleep((2**attempt)*5)` = **5s / 10s**，共 3 次尝试 | 文档写的是"2s/4s/8s"，与实际不符（§8 #17）；其他错误码不重试 |

### 4.2 数据层

| 位置 | 解决的问题 | 值得学的机制 | 坑 |
|------|-----------|--------------|-----|
| ★ `db.py:33-125` | 首启自动建库建表 | 3 张表一次建完；对已存在的表用 `ALTER TABLE ADD COLUMN` + 吞异常来补列 | MySQL 不支持 `ADD COLUMN IF NOT EXISTS`，靠捕获 1060 错误实现幂等——**每次启动都会打印一串 `alter column warning` 是正常的** |
| ★ `db.py:158-216` | XDR item → 表字段 | 大量 `列表取首元素` 的防御（`srcIp` 是数组）；`map_severity` 把 0-100 分映射成 4 档 | `xdr_user` 硬编码为 `'N/A'`，`xdr_parent_process`/`xdr_file_path` 恒为空串 → 前端"进程链/文件路径"字段其实没数据 |
| ★ `db.py:256-276` | 幂等写 | `ON DUPLICATE KEY UPDATE` + 从字段列表自动生成 update 子句 | 全字段覆盖，保护逻辑必须写在调用方（即 `insert_xdr_results`） |
| ★ `db.py:506-537` | 不让机器覆盖人的决策 | 先查已有行的 `verdict`/`model_response`/`status`，再决定是否回填 | **只保护 `false_positive`**；用户手动 `blocked`/`closed` 的告警重新拉取后会退回 `open` |
| ★ `db.py:441-486` | 后端字段名 → 前端字段名 | 集中式映射表 `key_map`，`xdr_*` 拍平成嵌套 `xdr` 对象 | `time` 字段有三级回退 `update_time or last_time or created_at`；`name` 缺失回退 `type` |
| ☆ `db.py:579-598` | 增量拉取的锚点 | `MAX(update_time)` 当水位线；`ai_judged=1` 的 id 集合当跳过表 | `update_time` 来自 XDR 而非入库时间，XDR 侧的乱序更新会影响水位线 |
| △ `db.py:219-290` | — | `record_from_sample` / `seed_sample_alarms` 是**死代码**（全项目无调用） | 对照 `app.py:54-183` 的 `_SAMPLE_ALARMS` 也是死数据：它只被用来填充 `request`/`verdict` 字段，从未写库 |

### 4.3 检索层（RAG）

| 位置 | 解决的问题 | 值得学的机制 | 坑 |
|------|-----------|--------------|-----|
| ★ `knowledge_context.py:96-107` | 切词 | 正则 `[\u4e00-\u9fa5]{2,}\|[a-z0-9_.\-]+` 直接抓连续中文字符串 | **中文不切词**：`检测到针对` 会被当成一个 5 字 token，停用词表里的 `检测到`、`针对` **拦不住它**（实测见实验 2） |
| ★ `knowledge_context.py:49-83, 110-117` | 跨语言召回 | 同义词表 + `key in t or t in key` 的子串匹配双向扩展 | 子串匹配会误扩：`c2` 会命中任何含 `c2` 的词 |
| ★ `knowledge_context.py:120-168` | 从任意 JSON 里挖特征 | 递归遍历所有字符串值 → 统一词表 → 再单独正则捞 IP / `T\d+` / `CVE-xxxx-yyyy`；过滤 `_NOISE_TOKENS` 与超长/含反斜杠的 token | IP 正则 `\b(?:\d{1,3}\.){3}\d{1,3}\b` 会把版本号 `19.1` 之类误当 IP 的概率不高，但会把 `1.2.3.4` 这类全当特征——**任何数字点串都可能成为召回关键词** |
| ★ `knowledge_context.py:258-271` | 排序 | 命中数计数，`score>0` 才入围，同分保持原顺序 | 没有 IDF、没有字段权重（CVE ID 命中与普通词命中同权）、没有长度归一化 → **长文本天然占优** |
| ★ `knowledge_context.py:171-201` | 从 361 个漏洞文档里抽条目 | 遍历索引 → 读 `content.txt` → `json.loads` → 展开 `vulnerabilities[]` → 丢空描述 | 全量加载进内存并缓存；`clear_cache()` 必须显式调用才能看到新数据 |
| ★ `knowledge_context.py:314-360` | 输出契约 | 返回 `{text, vuln_matches, library_matches, keywords}` | `text` 被两个调用方依赖（`xdr_pipeline.py:239`、`app.py:1410`）；`library_matches` 的 `text` 字段被 `app.py:1371` 用来**解析学生身份**——这是把检索结果当结构化数据用，很脆 |

### 4.4 服务入口（app.py 按主题分段）

| 段 | 位置 | 主题 | 该关注什么 |
|----|------|------|-----------|
| A | `app.py:1-52` | 导入 + Flask 初始化 | `after_request` 全局禁缓存（开发期救命，生产期是性能负担） |
| B | `app.py:54-208` | 示例/静态数据 | `_SAMPLE_ALARMS`（10 条假告警，死代码）、`ASSETS`（14 个新余学院资产） |
| C | `app.py:210-347` | 内存状态 + 加白引擎 | `_alarm_matches_rule`（空字段=任意）、`_apply_whitelist_to_alarms`（双向同步：命中→false_positive，不再命中→退回 pending） |
| D | `app.py:350-603` | 启动初始化 + 告警/封禁路由 | 模块级就跑 `db.init_db()`、`delete_sample_alarms()`（**会删掉所有 `ALT-` 开头的告警**） |
| E | `app.py:609-781` | Web 资产真实探测 | `probe_asset()`：正常请求探活 + SSL 证书天数 + **SQL 注入探针验证 WAF**；WAF 判定的启发式标记表在 `694-700` |
| F | `app.py:800-1024` | 资料库 | 上传 → 文本提取（pdf/docx/纯文本）→ 存 `{uid}.content.txt`；**CSV 上传会自动导入身份库**（`app.py:928-934`） |
| G | `app.py:1028-1145` | 命令执行 + 系统提示词 | `execute_command()` 5 个动作；`build_system_prompt()` 把实时统计+告警+封禁+资产+身份表+漏洞库摘要全塞进 system prompt |
| H | `app.py:1148-1261` | 模型配置 + 技能 CRUD | 掩码回填逻辑（编辑时不重填 Key 则保留原值） |
| I | `app.py:1264-1426` | 助理对话三级路由 | **技能优先 → 缺参数提示 → LLM 兜底**；`resolve_infected_students` 是另一套受攻击学生实现 |
| J | `app.py:1503-1632` | 漏洞库路由 | 6 个接口 + 资料库式文件管理（复用同一个 `LIBRARY_DIR`） |
| K | `app.py:1635-1748` | XDR 配置 + 流水线路由 | `load_xdr_config`（**只读 `data/xdr_config.json`**）；`/api/xdr/ingest` 的默认路径是 macOS 的 `/private/tmp/...`（`app.py:1723`） |
| L | `app.py:1751-1886` | XDR 调度器 | 60s 固定间隔；PID 锁；`start_xdr_scheduler()` 在**模块级**调用（导入即启动） |

### 4.5 技能系统与漏洞库

| 位置 | 解决的问题 | 值得学的机制 | 坑 |
|------|-----------|--------------|-----|
| ★ `skills.py:15-62` | 技能定义 | 纯 JSON 描述（触发词 / handler / 参数），可热加载 | 触发词是**子串匹配**且按列表顺序返回第一个命中（`skills.py:278-298`）；`vuln_daily_stats` 的触发词含 `漏洞`/`统计`/`获取`/`每天`，粒度很粗 |
| ★ `skills.py:83-102` | 配置自愈 | 每次加载都把 `_default_skills()` 里缺失的 id 补进配置文件 | 所以你删掉一个默认技能，重启后会**复活** |
| ☆ `skills.py:130-169` | CSV 表头不统一 | `key_map` 同义词表（`ip`/`IP地址`/`src_ip`…） | 只在 `item.get('ip') and item.get('name')` 都非空时导入 |
| ★ `skills.py:205-265` | 受攻击学生（实现一） | 按 `created_at`/`update_time` 时间窗查 alerts → 取 `target_ip` → 查 `identity_db.json` | 用 **target_ip**；且只返回"能在 identity_db 里查到"的学生 |
| ☆ `skills.py:306-315` | 伪造防火墙封禁 | 返回一个长得像成功响应的 dict | 没有任何真实防火墙联动；前端会显示"深信服防火墙已封禁 IP" |
| ★ `vuln_updater.py:31-85` | 源注册表 | 4 个源（NVD / CISA KEV / CIRCL / OSV），`default` 字段决定默认启用哪些 | 文档 01/04 都只写"3 个源"，漏了 OSV（默认关闭，`default: False`） |
| ★ `vuln_updater.py:160-308` | 4 种格式归一化 | 每个源一个 `normalize_*_item()`，统一输出 12 个字段 | NVD 的 vendor/product 要从 CPE 2.3 URI 里切第 3/4 段（`_extract_cpe_parts`）；CISA 项没有 CVSS 分数 |
| ★ `vuln_updater.py:321-365` | NVD 限速 | 无 Key 时每 5 次请求 sleep 32 秒、其余 sleep 7 秒；`startIndex` 翻页，硬上限 21 页 | `resultsPerPage: 2000` 请求体巨大；有 Key 时配额不同（`limit = 50 if NVD_API_KEY else 5`） |
| ★ `vuln_updater.py:439-479` | 漏洞文档落库 | 复用资料库目录，写 `{uid}.json` + `{uid}.content.txt`，并 append 到 `vuln_index.json` | 索引是**只增不减的全量 JSON**，每次更新 append 一条；`/api/vulns/update` 反复点会持续堆积文件 |
| ★ `vuln_scheduler.py:156-191` | 防重入（真机制） | 内存标志 `_state['updating']`，重复触发直接返回 `False, '已有更新任务在运行'` | **不是**文件锁在防重入（§8 #15） |
| ★ `vuln_scheduler.py:260-281` | 看门狗 | 配置启用但线程不在 → 停掉重启 | 这是**漏洞库**调度器的看门狗，不负责 XDR 调度器（§8 #4） |

---

## 5. 全局配置与状态一览（做实验前先看这张表）

### 5.1 所有可调参数

| 参数 | 位置 | 现值 | 影响 |
|------|------|------|------|
| `SCHEDULER_INTERVAL` | `app.py:1755` | 60 秒 | XDR 拉取+研判频率 |
| XDR 单次拉取条数 | `app.py:1834`（调度器）、`app.py:1695`（手动）、`.env PIPELINE_COUNT` | 50 / 5（请求体指定） | 一次花多少 LLM 调用。**注意调度器首轮立即执行，所以启动瞬间就会拉 50 条**（见 §8.3 #38） |
| `_MAX_TOTAL_CHARS` | `knowledge_context.py:22` | 2500 字符 | 注入 Prompt 的知识库上限 |
| `_TOP_VULN` / `_TOP_LIBRARY` | `knowledge_context.py:23-24` | 3 / 3 | 召回条数 |
| `max_retries` | `llm_client.py:109` | 3 | 429 重试次数 |
| 退避基数 | `llm_client.py:115` | `(2**attempt)*5` → 5s、10s | 限流等待 |
| `temperature` | `llm_client.py:79` | `kimi-for-coding` → 1.0；其余 0.5 | 注意 `xdr_pipeline.py:259` 写的 0.3 **不生效** |
| 上传上限 | `app.py:791` | 50 MB | 资料库/漏洞库上传 |
| 漏洞调度间隔 | `data/vuln_scheduler_config.json` | 86400 秒（24 h） | 代码默认是 21600（6 h），实际以配置文件为准 |
| 漏洞调度启用 | 同上 | `enabled: true`，3 个源 | 决定后台是否真的在拉漏洞 |
| 前端自动刷新 | `static/js/app.js` | 30 秒 | 页面感知新告警的延迟 |
| 每条研判间隔 | `xdr_pipeline.py:421, 472` | 跳过 1s / 正常 3s | 串行限速，50 条约等于 150 秒 |
| DB 连接 | `db.py:10-14` | 环境变量优先，默认 `root`/`itopsclaw-root` | `start_dashboard.cmd` 覆盖为 `qwet`/`123456` |
| `ALLOW_INTERNAL_BLOCK` | 进程环境变量 | 未设 | `=1` 时解除内网封禁硬校验（§11 U1），演示内网靶机用 |
| `DISABLE_XDR_SCHEDULER` | 进程环境变量 | 未设 | `=1` 时 `import app` 不启动调度线程（§11 U6），**测试/离线导入必设** |

### 5.2 内存态 vs 持久态

| 状态 | 内存变量 | 持久位置 | 一致性维护 |
|------|----------|----------|-----------|
| 告警列表 | `ALARMS`（`app.py:354`） | MySQL `alerts` | `refresh_alarms()` |
| 封禁列表 | `BLOCKED`（`app.py:361`） | MySQL `blocked_ips` | 各写路由末尾重赋值 |
| 加白规则 | `WHITELIST_RULES`（`app.py:355`） | MySQL `whitelist_rules` | `refresh_whitelist_rules()` |
| ATT&CK 映射 | `_ATTACK_TECHNIQUES`（`app.py:300`） | `static/data/attack_subtechniques.json` | 启动时加载一次，改文件要重启 |
| RAG 语料 | `_cache`（`knowledge_context.py:86`） | `data/library/*.json` | 需 `clear_cache()` |
| 模型配置 | 无（每次读盘） | `data/assistant_config.json` | 每次请求读文件 |
| 技能定义 | 无（每次读盘） | `data/skills_config.json` | 每次请求读文件 |

---

## 6. 动手实验

> **回滚说明（重要）**：`AI_xinyu` 是 git 仓库但**尚无任何提交**（`git log` 报 "does not have any commits yet"），所以**没有 `git checkout` 可用**。凡要改文件的实验，本手册都已把**原始内容逐字抄在"回滚"栏**，照抄还原即可。新建的临时脚本直接删除即可。

### 实验 1：离线跑通 RAG 召回（零风险，★先做这个）

不连数据库、不连 LLM、不花一分钱，直接看「知识库增强」到底召回了什么。

```bash
cd E:/tzb/AI_xinyu/security_agent_dashboard
python knowledge_context.py
```

`knowledge_context.py:368-384` 自带 `__main__` 自测块：内置一条 SQL 注入样例告警 → 打印关键词与召回文本。

**本次核实实测输出**（真实数据，2026-09-20）：关键词含 `sql injection` / `webshell` / `t1190` / `10.67.201.61` / `192.168.100.200`，漏洞召回 3 条（`CVE-2026-80236` 等），资料召回 3 条。

**验证点**：召回结果里既有 CVE 又有资料库文档 → 说明「双源召回」链路是通的。

**回滚**：无副作用，无需回滚。

---

### 实验 2：亲手看见 RAG 的中文切词缺陷（零风险）

这是理解 L3 最好的入口——**先看见它的不完美，才能理解它的设计取舍**。

```bash
cd E:/tzb/AI_xinyu/security_agent_dashboard
python -c "
from knowledge_context import _extract_keywords, _tokenize
cases = [
    {'name':'SQL注入攻击','attck':'T1190','description':'检测到针对 Web 应用的 SQL 注入尝试'},
    {'name':'终端恶意程序感染','description':'检测到针对终端发起的恶意代码通信行为'},
    {'name':'暴力破解','description':'检测到针对 VPN 网关的高频暴力破解'},
]
for c in cases:
    print(c['name'], '->', [k for k in _extract_keywords(c) if '\u4e00' <= k[0] <= '\u9fff'])
"
```

**本次核实实测输出**（2026-09-20 首测；**2026-09-28 bigram 修复后复测**，见 §11 U4）：

```
SQL注入攻击      -> ['注入尝试', '文件上传', '注入攻击', '注入', '测到', '检测', '到针']
终端恶意程序感染  -> ['程序', '通信', '感染', '发起', '端发', '信行', '意程', '起的', '恶意', '对终', '行为', '终端', '测到', '检测', '到针', '意代', '代码', '的恶', '序感', '端恶', '码通']
暴力破解         -> ['暴力破解', '的高', '力破', '网关', '频暴', '检测', '测到', '到针', '关的', '高频', '暴力', '破解']
```

**09-28 修复后的行为**（`knowledge_context.py` 的 `_tokenize`）：超过 4 字的纯中文串按 **bigram 滑窗**拆分——「检测到针对终端发起的恶意代码通信行为」不再是一个 20 字巨词，而拆出 `恶意`/`代码`/`通信`/`行为`/`终端`/`感染` 这类真正能命中语料的 2 字词；≤4 字的短语（如「暴力破解」）保持整词；停用词在 bigram 层面再次过滤。这正是 CJK 信息检索的经典做法。

**修复前的问题**（保留作学习记录）：中文没有空格分隔，旧版 `_tokenize` 用 `[\u4e00-\u9fa5]{2,}` 把连续中文整段抓成一个 token——「检测到针对终端发起的恶意代码通信行为」整整 20 个字成了一个"关键词"，几乎不可能在任何语料中命中；停用词表只做 token 全等匹配，`检测到针对` ≠ `检测到`，滤不掉。当时中文召回主要靠 IP / `T1xxx` / `CVE-xxxx` 强特征撑着（`knowledge_context.py` 的 `_extract_keywords` 专门单独抽这三类）。

**回滚**：无副作用。

---

### 实验 3：数据库只读巡检（零风险）

确认你手上的数据是什么样子——这是后面所有实验的基线。

```bash
cd E:/tzb/AI_xinyu/security_agent_dashboard
DB_USER=qwet DB_PASSWORD=123456 python -c "
import db
from collections import Counter
a = db.load_alarms()
print('告警总数:', len(a))
print('ai_result 分布:', dict(Counter(x.get('ai_result') or '(空)' for x in a)))
print('已研判:', sum(1 for x in a if x.get('aiJudged')), '/', len(a))
print('严重度分布:', dict(Counter(x.get('severity') for x in a)))
print('封禁:', len(db.load_blocked()), ' 加白规则:', len(db.load_whitelist_rules()))
print('增量水位线(MAX update_time):', db.get_max_update_time())
print('已研判uuid数(跳过LLM用):', len(db.get_judged_uuids()))
"
```

**本次核实实测输出**（2026-09-20）：
```
告警总数: 15
ai_result 分布: {'攻击成功': 9, '尝试': 3, '': 2, '攻击失败': 1}
已研判: 15 / 15
封禁: 4   加白规则: 4
增量水位线: 2026-09-05 05:52:12
```

**验证点**：`ai_result` 里有 2 条空串 → 对应 `extract_ai_result` 没匹配到 `研判结果：` 前缀的情况（`xdr_pipeline.py:290` 返回 `""`）。这是理解"结构化提取会失败"的活样本。

**试试加一条**：把 `load_alarms` 换成 `db.load_alarms(q='成功')` 看 DB 层过滤；对比 `app.py:388-400` 的内存层过滤——**两处过滤实现不同，这是 §8 #22**。

**回滚**：只读，无副作用。

---

### 实验 4：验证签名器是确定性的（零风险，不联网）

搞清 `AkskSigner` 的输入输出关系，答辩被问到能直接答。

```bash
cd E:/tzb/AI_xinyu/security_agent_dashboard
python -c "
import json, xdr_pipeline as xp
# 冻结时间，让签名可复现
xp._sign_date_now = lambda: '20260920T000000Z'
s = xp.AkskSigner('AK_TEST', 'SK_TEST')
h1 = s.sign('POST', 'https://xdr.example.com:1443/api/xdr/v1/alerts/list',
            headers={'Content-Type':'application/json'}, json_body={'page':1,'pageSize':5})
h2 = s.sign('POST', 'https://xdr.example.com:1443/api/xdr/v1/alerts/list',
            headers={'Content-Type':'application/json'}, json_body={'page':1,'pageSize':5})
print('两次签名是否一致:', h1['Authorization'] == h2['Authorization'])
print('Authorization:', h1['Authorization'])
# 改一个字节的 body，签名必须全变
h3 = s.sign('POST', 'https://xdr.example.com:1443/api/xdr/v1/alerts/list',
            headers={'Content-Type':'application/json'}, json_body={'page':1,'pageSize':6})
print('body 变化 -> 签名变化:', h3['Authorization'] != h1['Authorization'])
print()
print('payload hash 的输入是排序去空格后的字节:')
print('  ', xp._payload_transform(json.dumps({'page':1,'pageSize':5}, ensure_ascii=True)))
print('  ', xp._payload_transform(json.dumps({'page':5,'pageSize':1}, ensure_ascii=True)))
print('  ^ 两个 payload 内容不同但排序去空格后字节相同 -> hash 相同，这是深信服的非标准设计')
"
```

**验证点**：同输入签名稳定；`{"page":1,"pageSize":5}` 与 `{"page":5,"pageSize":1}` 的 payload hash **相同** —— 这正是 `_payload_transform`（`xdr_pipeline.py:124-128`）「字节排序 + 去空格」的后果。这个反直觉行为是签名器最值得记住的一点。

**回滚**：只读（`_sign_date_now` 的 monkeypatch 只在进程内），无副作用。

---

### 实验 5：端到端复现一条真实研判（**注意：会花钱**）

> 🔴 **先读这条警告**：`import app` **本身就会立刻触发一次 50 条告警的真实拉取 + 研判**。
> 原因：`app.py:1879` 在模块级调用 `start_xdr_scheduler()`，线程函数 `_scheduler_loop`（`app.py:1828-1849`）**首轮立即执行**（不是等 60 秒），且因为 `last_run_at` 还是 `None`，`force_full=True` → `_xdr_fetch_once(count=50, force_full=True)`（`app.py:1834`）。
> 换句话说：**只要 `import app`，就会朝 XDR 拉 50 条并逐条调大模型**（已在库的会跳过）。不想花钱时，请只做下面的第 ① 步。

**① 只看配置（零成本，不 import app）**

绕开 `app`，直接读配置文件：

```bash
cd E:/tzb/AI_xinyu/security_agent_dashboard
python -c "
import json, pathlib
cfg = json.loads(pathlib.Path('data/xdr_config.json').read_text(encoding='utf-8'))
print('base_url :', cfg.get('xdr_base_url'))
print('认证方式 :', '连接码' if cfg.get('xdr_auth_code') else ('AK/SK' if cfg.get('xdr_access_key') else '未配置'))
print('timeout  :', cfg.get('request_timeout'))
cfgs = json.loads(pathlib.Path('data/assistant_config.json').read_text(encoding='utf-8'))
for c in cfgs:
    if c.get('active'):
        print('激活模型 :', c.get('name'), '| provider=', c.get('provider'),
              '| base_url=', c.get('base_url'), '| model=', c.get('model'),
              '| key=', (c.get('api_key') or '')[:4] + '****')
"
```

**② 真跑一条（成本 ≈ 1 次 LLM 调用）**

确认 ① 的配置无误后再执行。**记得在启动的同一命令行里先设好 DB 环境变量**（`app` 依赖它）：

```bash
cd E:/tzb/AI_xinyu/security_agent_dashboard
DB_USER=qwet DB_PASSWORD=123456 python -c "
import app, json
s = app._xdr_fetch_once(count=1, force_full=True)
print(json.dumps({k: v for k, v in s.items() if k != 'results'}, ensure_ascii=False, indent=2))
r = (s.get('results') or [{}])[0]
print('ai_result:', r.get('ai_result'), '| verdict 前80字:', (r.get('verdict') or '')[:80])
"
```

**这一条命令的实际副作用**（比表面看到的多，务必知悉）：

1. `db.init_db()`（建库建表 + 补列警告）、`db.delete_sample_alarms()`（删掉所有 `ALT-` 开头的告警）；
2. 调度线程立刻发起一次 **50 条**的拉取研判（这才是主要成本，不是你以为的 1 条）；
3. 之后主线程结束，daemon 线程随之终止——所以它不会一直跑下去；
4. 前台脚本自己那次 `count=1` 的调用也会真实打 XDR + 大模型。

**看什么**：`ai_result` 是否被成功提取（`攻击成功`/`攻击失败`/`尝试`）；`pipeline_result.json` 里的 `request` 字段能看到完整 Prompt（含知识库正文）；日志里 `[scheduler] XDR 定时拉取已启动，间隔 60 秒`。

**回滚**：会新增/更新若干条告警记录，属正常数据增长。想彻底干净：`DELETE FROM alerts WHERE id = '<该条uuid>';`

**想省掉那条 50 条的额外开销**（L2 小改动作业）：把 `app.py:1834` 的 `count=50` 改成 `count=1`，或在 `_scheduler_loop` 进入循环前先 sleep 一轮。

---

### 实验 6：把 `atexit` 补齐，观察锁文件行为（改代码，给出原值）

这是项目里一个真实的小 bug，修它的过程能顺带搞懂 PID 锁。

**先复现问题**：

```bash
cd E:/tzb/AI_xinyu/security_agent_dashboard
python -c "
import ast
src = open('app.py', encoding='utf-8').read()
tree = ast.parse(src)
imported = set()
for n in ast.walk(tree):
    if isinstance(n, ast.Import):
        imported.update(a.asname or a.name.split('.')[0] for a in n.names)
    elif isinstance(n, ast.ImportFrom):
        imported.update(a.asname or a.name for a in n.names)
print('app.py 的 import 名集合:', sorted(imported))
print('代码里用了 atexit 吗:', 'atexit.register' in src)
print('atexit 被导入了吗:', 'atexit' in imported)
"
```

**本次核实实测输出**（2026-09-20）：

```
app.py 用到 atexit.register: True
atexit 在导入名集合中: False
```

（注：脚本用 `ast.walk` 收集**所有层级**的 import，含函数内的局部 import，所以集合比「顶层 import」更宽——不影响结论。）

**问题定位**：`app.py:1863` 的 `atexit.register(_remove_scheduler_lock)` 会抛 `NameError`，而它被 `app.py:1860-1865` 的 `try/except Exception: pass` **静默吞掉**。后果：调度器照常启动（因为 `_scheduler_state['running'] = True` 在 try 之外），但**进程退出时不会清理 `.xdr_scheduler.lock`**。

**修复（一行）**：把 `app.py:5` 的

```python
import json, os, uuid, threading, time
```

改成

```python
import json, os, uuid, threading, time, atexit
```

**回滚**：把 `app.py:5` 抄回上面那一行原文（去掉 `, atexit`）。

**验证修复**：改完后再跑一次上面的 AST 检查，`atexit` 应出现在导入集合里；启动一次服务再正常退出，`.xdr_scheduler.lock` 应被删除。

---

### 实验 7：把召回条数从 3 调到 5，观察 Prompt 膨胀（改代码，给出原值）

理解「上下文长度」与「召回质量」的权衡。

**改** `knowledge_context.py:23-24`，原文逐字为：

```python
_TOP_VULN = 3
_TOP_LIBRARY = 3
```

改成 `_TOP_VULN = 5` / `_TOP_LIBRARY = 5`。

```bash
python -c "
from knowledge_context import build_knowledge_context
a = {'name':'SQL注入攻击','description':'检测到针对 Web 应用的 SQL 注入尝试','attck':'T1190','src_ip':'10.67.201.61'}
ctx = build_knowledge_context(a)
print('上下文长度:', len(ctx['text']), '字符（上限 2500）')
print('漏洞命中:', len(ctx['vuln_matches']), ' 资料命中:', len(ctx['library_matches']))
print('---- 上下文 ----'); print(ctx['text'][:900])
"
```

**本次核实实测输出**（2026-09-20 首测；**2026-09-28 CVE 去重后复测**，见 §11 U4）：

| 召回设置 | 上下文长度 | 是否被截断 | 实际保留的漏洞条目 |
|----------|-----------|-----------|-------------------|
| `top_vuln=3, top_library=3` | **1716 字符** | 否 | CVE-2026-80236 / 78612 / 78613，3 条描述完整 |
| `top_vuln=5, top_library=5` | **1375 字符** | **是**（含 `[知识库上下文过长，已截断]`） | `vuln_matches` 返回 5 条**唯一** CVE（80236 / 78612 / 78613 / 78614 / 2025-25257），但正文只装得下前几条完整描述 |

**召回 5 条反而比 3 条更短** —— 这是本实验最有价值的一课。机制在 `_truncate`（`knowledge_context.py`）：截断点从 2450 位置**向前**找最近的空行 `\n\n`，而资料库里有个 300 字符的单行 JSON 预览横跨了那一段，导致回溯点一路退到 1375 字符处——新召回的尾部条目一条都进不了正文。**召回条数与注入 Prompt 的信息量不是单调关系**。

09-28 的改进只解决了另一件事：修复前 `vuln_matches` 会出现**两条 CVE-2026-80236**（同一 CVE 存在于多个源文档，`_load_vuln_items` 不去重）；修复后按「CVSS 有分优先、modified 较新优先」去重，top-5 全部唯一。截断机制本身未动，仍是 L4 练习题：如何让超长单行不劫持截断点。

**回滚**：把 `knowledge_context.py:23-24` 抄回上面的原文。

---

## 7. FAQ 预答

**Q1：告警列表是空的 / 页面没数据，但数据库里明明有。**
内存 `ALARMS` 与 DB 不一致。调 `POST /api/alarms/refresh`（`app.py:403-417`），它会 `db.load_alarms()` 后重放加白规则（`app.py:214-217`）。

**Q2：改了 `static/js/app.js`，刷新页面没变化。**
两个可能：(1) 在看构建产物 `static/index.html`（内联了 JS）而没跑 `build_static.py`；(2) 后端已经全局禁缓存（`app.py:46-52`），所以更可能是前者。注意 `build_static.py:4` 的 `BASE` 是**硬编码 macOS 路径**，在本机跑会直接报文件找不到，必须先改这一行（§8 #24）。

**Q3：启动日志里一堆 `[db] alter column warning: 1060 Duplicate column name`。**
正常。`db.py:83-94` 用「尝试加列 + 吞异常」实现跨 MySQL 版本的列补全。

**Q4：XDR 拉不到告警。**
按顺序查：`GET /api/xdr/scheduler/status` 看 `ready`/`reason`（`app.py:1736-1748`）→ 再看 `last_error`。`_can_run_xdr_pipeline()`（`app.py:1791-1803`）会明确告诉你缺 `xdr_base_url`、缺认证、还是缺激活模型。注意**三类配置分别来自 `data/xdr_config.json`（XDR）和 `data/assistant_config.json`（模型）**，与 `.env` 无关。

**Q5：我改了 `.env`，为什么没生效？**
因为 Web 服务根本不读 `.env`。全项目只有 `xdr_pipeline.py:501-557` 的 CLI 分支读它。改 XDR 配置走前端或 `data/xdr_config.json`；改模型走前端或 `data/assistant_config.json`。

**Q6：智能助理回答"没有激活的模型"。**
`data/assistant_config.json` 里没有 `active: true` 的条目，或者技能路径没命中而 LLM 路径缺模型（`app.py:1301-1303`）。技能路径不依赖模型——先测 `POST /api/skills/detect`。

**Q7：助理执行了"封禁"，但防火墙没变化。**
符合预期。`skills.fake_firewall_block()`（`skills.py:306-315`）只是返回一个像成功的 dict，本项目**没有真实防火墙/EDR 联动**，只写自己的 `blocked_ips` 表。

**Q8：`ai_result` 字段是空的。**
大模型没按 `研判结果：攻击成功` 的格式输出（`xdr_pipeline.py:286`）。看该条的 `model_response` 原文确认；`system_prompt`（`xdr_pipeline.py:233-237`）里的格式要求是唯一的约束手段。

**Q9：新增的技能删不掉，重启又回来了。**
`load_skills()`（`skills.py:83-102`）每次都会把 `_default_skills()` 里缺的 id 补回去。要永久删，得同时从 `_default_skills()` 里删。

**Q10：`import app` 之后程序不退出 / 端口被占。**
`app.py:1879` 在模块级启动调度线程。另外 `.xdr_scheduler.lock`、`.vuln_scheduler.lock` 残留会让新进程跳过调度器启动——`start_server.py:11-19` 的作用就是在启动前清这两个锁。

**Q11：漏洞库文件越堆越多。**
`_save_library_document`（`vuln_updater.py:439-479`）每次更新都 append 一条新索引、写新文件，从不清理旧版本。要控制规模需手动删 `data/library/` 下的历史 json 并在 `vuln_index.json` 里移除对应项。

**Q13：为什么服务刚起来就有新告警，或者刚起来就发现花了一笔 LLM 调用？**
因为调度线程**首轮立即执行**：`_scheduler_loop`（`app.py:1828-1849`）进入 `while` 后马上调 `_can_run_xdr_pipeline()`，配置齐全就直接 `_xdr_fetch_once(count=50, force_full=True)`，60 秒的间隔是**两次拉取之间**的等待，不是启动前的等待。详见 §8.3 #38。

**Q14：`import app` 之后脚本好像卡住/发了网络请求？**
同上。`import app` 的副作用包括启动调度线程并立刻拉 50 条告警研判。只想读配置就别 `import app`，直接读 `data/*.json`（实验 5 第 ① 步就是这么做的）。

**Q15：`docs/` 和 `docs/文档/` 是什么关系？**
内容完全相同（4 个文件字节数一致），`docs/文档.zip` 是它们的压缩包，供提交用。

**Q16：封禁 IP 时提示「拒绝封禁：属于内网/受保护地址」？**
正常，这是 2026-09-28 加的**处置硬校验**（`skills.is_protected_ip`，对标 SOAR 最佳实践）：RFC1918 私网 / 回环 / 链路本地 / 保留段的 IP 一律拒绝封禁，防止把内网用户或网关拉黑导致断网。演示内网靶机场景时设环境变量 `ALLOW_INTERNAL_BLOCK=1` 可解除。

**Q17：`data/llm_usage.jsonl` 是什么？**
2026-09-28 加的 **LLM 成本日志**（对标 Black Hat 2025 的 M507/AI-SOC-Agent 逐告警成本记录）：`llm_client` 每次真实调用都追加一行 `{ts, model, latency_ms, usage}`，用于统计每次研判花了多少 token/时间。best-effort 写入，失败不影响主流程。

---

## 8. 文档与代码出入登记表

> 核实时间 2026-09-20。已修正的项在交付文档中就地改掉了（改法见"修正"列），本表是完整存档。
> **教训：交付文档整体滞后于代码。凡涉及"行数 / 接口清单 / 配置优先级 / 运行命令"，一律以代码为准。**

### 8.1 会直接让人踩坑的（已修正）

| # | 文档位置 | 文档写的 | 实际 | 修正 |
|---|----------|----------|------|------|
| 1 | `02_开发文档.md` §1.3/§3.2/§3.3/§9.2 | `pip install -r requirements.txt`（并给出了文件内容） | **`requirements.txt` 不存在** | 已按 §3.3 与 `DEPLOY.md:29` 的内容创建该文件，与实际 import 核对一致 |
| 2 | `02_开发文档.md` §8.2、§5.1 PIP-04、`01_设计文档.md` §5.5 | `POST /api/xdr/scheduler/restart` | **该路由不存在**（只有 `GET /api/xdr/scheduler/status`） | 已改为说明 XDR 调度器为 60s 常驻线程、无重启接口；要重启就重启进程 |
| 3 | `02_开发文档.md` §4.4 | XDR 连接：`.env` > `data/xdr_config.json` | **反了**：Web 只读 `data/xdr_config.json`（`app.py:1642-1651`），`.env` 仅 CLI 用 | 已改正优先级说明 |
| 4 | `02_开发文档.md` §4.4 | LLM：`assistant_config.json` > `.env` 单模型 | `.env` 的 `MODEL_*` 只被 `xdr_pipeline.py` CLI 用，Web 只读 `assistant_config.json` | 已改正 |
| 5 | `02_开发文档.md` §6.1、§7.4 | "Flask 默认开启 debug reload，改代码刷新即可" | **`app.py:1885` 是 `debug=False`，不会热重载** | 已改为"需重启进程" |
| 6 | `02_开发文档.md` §9.3 | `python build_static.py` 生成 `static/index.html` | `build_static.py:4` 的 `BASE` 是**硬编码 macOS 路径** `/Users/zhangshanshan/...`，本机必然失败 | 已加注"需先把 BASE 改成本机路径" |
| 7 | `02_开发文档.md` §9.1 | `start_dashboard.cmd` 含 `chcp`/`DB_HOST`/`DB_PORT`/`DB_NAME`/`python -u app.py`/`pause` | 实物只有 4 行：`@echo off` / `cd /d %~dp0` / `set DB_USER=qwet` / `set DB_PASSWORD=123456` / `python start_server.py` | 已按实物替换 |
| 8 | `02_开发文档.md` §7.2 | 12 个前端 DOM ID（`stats-cards`/`alarms-table`/`alarm-filter`/`vuln-stats`/`assets-list`/`assets-probe`/`attack-chart` 等） | 其中 **7 个在 `templates/index.html` 里不存在**（实测为 0 命中）；真实 ID 是 `alarm-table-body`/`alarm-search`/`ai-filter`/`attck-matrix`/`asset-table-body`/`library-table`/`vuln-sources` 等 | 已替换为实测存在的 ID |
| 9 | `02_开发文档.md` §2 | `data/vuln_index.json` | 实际在 `data/library/vuln_index.json`（`vuln_updater.py:26`） | 已改正 |
| 10 | `02_开发文档.md` §8.3 | 助理请求体 `{"message":"..."}` | 实际参数名是 `messages`（数组），`app.py:1267` | 已改正 |
| 11 | `01_设计文档.md` §4.5 | `.env` 位置"项目根目录" | 实际是 `security_agent_dashboard/.env` | 已改正 |
| 12 | `01_设计文档.md` §5.1 | "共 **54 个** REST 接口，全部前缀 `/api/`" | 54 个 `@app.route`，其中 `/` 是页面路由 → **53 个 `/api/` 接口** | 已改正 |
| 13 | `01_设计文档.md` §5.5/§5.6/§5.8 | 接口清单 | 漏了 `/api/xdr/ingest`、`/api/skills/detect`、`/api/skills/<id>/invoke`、`/api/assistant/infected_students`、`/api/vulns/update/status`、`/api/vulns/library*`(5 个)、`/api/vulns/daily-stats`；`/api/vulns`、`/api/vulns/config` 路径不存在 | 已按代码改正 |
| 14 | `01_设计文档.md` §3.1 | 模块行数：app.py ~1400、vuln_updater ~400、vuln_scheduler ~200、vuln_stats_skill ~80 | 实测 **app.py 1933**、**vuln_updater 580**、**vuln_scheduler 280**、**vuln_stats_skill 162** | 已改正 |
| 15 | `03_测试文档.md` §8.3、`04_总结报告.md` §4.2 | "文件锁 `.vuln_scheduler.lock` 保证防重入，手动触发 3 次只有 1 个执行" | **防重入靠内存标志 `_state['updating']`**（`vuln_scheduler.py:158-159`）；文件锁的作用是防多进程各起一个调度线程 | 已改正机制说明 |
| 16 | `03_测试文档.md` §12.1、§4.1 | "接口测试（pytest）10+ 自动"、"保存为 tests/test_api.py" | **全项目无任何测试文件**（`04_总结报告.md` §5.3 自己也承认"无真正的单元测试"） | 已标注为"待补，当前为手动验证" |
| 17 | `04_总结报告.md` §5.1 | "指数退避重试 3 次（2s/4s/8s）" | 实际 `sleep((2**attempt)*5)` = **5s / 10s**，仅 429 触发，共 3 次尝试（`llm_client.py:114-115`） | 已改正 |
| 18 | `01_设计文档.md` §2.3 | XDR 调度守护 = `vuln_scheduler.ensure_scheduler_alive()`，锁 `.xdr_scheduler.lock` | `ensure_scheduler_alive()`（`vuln_scheduler.py:260-271`）是**漏洞库**调度器的看门狗，锁是 `.vuln_scheduler.lock`；XDR 调度器（`app.py:1852-1869`）**没有看门狗**，锁是 `.xdr_scheduler.lock` | 已改正 |
| 19 | `01_设计文档.md` §4.2、`03_测试文档.md` §9.3 | `alerts` 表字段清单 | 漏了 `description` / `attack_url` / `response_status` 3 列（`db.py:83-89` 的 ALTER 补列；`request_json`、`ai_result` 文档已有） | 已补齐 |
| 20 | `02_开发文档.md` §3.1 | `beautifulsoup4` 是"上传 HTML 时条件必需" | 看板**不用 bs4**：`extract_text`（`app.py:874-886`）对 `.html` 按纯文本读；bs4 只被一次性脚本（`rebuild_attack.py` 等）使用 | 已改注"仅历史脚本需要" |
| 21 | `01_设计文档.md` §1.3、`04_总结报告.md` §4.1 | 漏洞数据源"3 个（NVD/CISA/CIRCL）" | 代码里有 **4 个**，第 4 个 OSV 默认关闭（`vuln_updater.py:50-55`） | 已改为"4 个（其中 OSV 默认关闭）" |

### 8.2 行为/表述不准确（已在交付文档加注）

| # | 文档位置 | 问题 | 真相 |
|---|----------|------|------|
| 22 | `03_测试文档.md` §12.2 | "Flask dev server 单线程" | Flask `run()` 内部 `options.setdefault("threaded", True)`（实测 Flask 3.1.0 源码），**默认是多线程** WSGI server |
| 23 | `03_测试文档.md` §6.1 | 规则模式用例表列了"今天有多少告警""查看高危告警""哪些 IP 被封禁了""ATT&CK 哪个技术最多""切换到告警展示" | 这些**没有对应技能**。默认只有 4 个技能（`skills.py:15-62`）：IP 封禁、IP 查身份、今日受攻击学生、漏洞每日统计。表里多数用例会落到 LLM 分支（需配模型） |
| 24 | `03_测试文档.md` §10.5 A03 | "db.py 全部 `%s` 占位，参数化查询" | 值确实全部参数化，但 `db.py:520` 用 `% placeholders` 拼接**占位符字符串**（值仍走参数），`db.py:37` 用 f-string 拼库名。安全性不受影响，但"全部 %s"表述不严谨 |
| 25 | `04_总结报告.md` §2.2、§4.1 | 核心模块"合计 ~4020 行"、"8 个模块 ~4000 行" | 8 个模块实测合计 **4813 行**（不含 `vuln_stats_skill.py` 162 行） |
| 26 | `04_总结报告.md` §2.2 | "前端模板 ~3000+" | 实测 `templates/index.html` 700 行；HTML+CSS+JS 合计 **5437 行** |

### 8.3 代码本身的问题（不是文档错，但学习时要留意）

| # | 位置 | 问题 | 影响 |
|---|------|------|------|
| 27 | `app.py:1863` | `atexit.register(...)` 但 `atexit` **从未导入** | `NameError` 被 `except Exception: pass` 吞掉。调度器仍启动，但进程退出不清理 `.xdr_scheduler.lock`。修法见实验 6（**已于 09-28 修复，见 §11 U6**） |
| 28 | `app.py:1887-1932` | `_normalize_attck_id` 与 `enrich_attck_info` **重复定义**（`app.py:10-20`、`313-347` 已有） | patch 脚本残留。Python 后定义覆盖前者，行为一致，但白白多出 46 行（**已于 09-28 删除，见 §11 U6**） |
| 29 | `app.py:1884-1886` | `if __name__ == '__main__':` 下连着两行 `app.run(...)` | 第二行**永远不可达**（含 `threaded=True` 那行），属笔误；实际靠 Flask 默认 threaded=True 兜住了（**已于 09-28 删除，见 §11 U6**） |
| 30 | `app.py:54-183` + `db.py:219-290` | `_SAMPLE_ALARMS` 经 `record_from_sample` 由 `seed_sample_alarms` 入库——但 **`seed_sample_alarms` 全项目无调用** | 10 条示例告警及其 `verdict` 是死数据；而 `app.py:353` 每次启动都执行 `delete_sample_alarms()` 删 `ALT-%` 记录，所以示例数据**永远进不了库** |
| 31 | `skills.py:205-265` vs `app.py:1381-1421` | 同一「受攻击学生」业务两套实现：一套按 **target_ip** 查 `identity_db.json`，一套按 **src_ip** 查 RAG 召回的 CSV 文本 | 两个入口（助理技能 vs `GET /api/assistant/infected_students`）给出**不同答案**。前者答"哪些学生被攻击"，后者答"哪些学生终端中毒" |
| 32 | `app.py:1064-1072` | LLM 命令路径的 `false_positive` 动作**只改状态、不建加白规则**；而 `POST /api/alarms/<id>/false_positive`（`app.py:488-494`）会建规则并批量加白 | 同一语义两条路径副作用不同，违反最小惊讶原则 |
| 33 | `app.py:1274-1284` | 遗留调试日志用 `app.logger.warning` 打印整轮 `messages` 与识别结果 | 会进日志，且量大；应降级或删除 |
| 34 | `app.py:1723` | `/api/xdr/ingest` 默认路径 `/private/tmp/pipeline_result.json` | macOS 残留，本机默认必失败（需显式传 `path`） |
| 35 | `db.py:204-208` | `xdr_user` 硬编码 `'N/A'`，`xdr_parent_process`/`xdr_file_path` 硬编码空串 | 前端"用户 / 父进程 / 文件路径"这三个字段实际无数据 |
| 36 | `xdr_pipeline.py:259` | `build_judgment_request` 返回 `model_config: {"temperature": 0.3}` | **不生效** —— `call_model_judgment` 只取 `messages` 传给 `llm_client`，真实温度由 `llm_client.py:79` 硬编码决定 |
| 37 | `db.py:535-536` | 决策保护只覆盖 `status == 'false_positive'` | 人工 `blocked`/`closed` 的告警重新拉取后会退回 `open`（缓解：09-28 后加白规则命中告警在拉取阶段就被 U2 预评分跳过，不会重置状态；其余场景仍需注意） |
| 38 | `app.py:1828-1834` + `app.py:1879` | **服务启动瞬间就会发起一次 50 条的真实拉取+研判**：调度线程 `_scheduler_loop` 首轮立即执行（不等 60 秒），且 `last_run_at` 为 `None` → `force_full=True` | 与 `01_设计文档.md` §2.3「每 60 秒定时增量拉取」的表述不一致。副作用：启动即消耗最多 50 次 LLM 调用；也意味着"刚启动就有告警进来了"是正常现象。要抑制可在 `app.py:1834` 调小 `count` 或在循环前先睡一轮 |

---

## 9. 调试速查

### 9.1 常用命令

```bash
cd E:/tzb/AI_xinyu/security_agent_dashboard

# 启动（Windows 一键，内置 DB 账号）
./start_dashboard.cmd

# 前台启动看实时日志
DB_USER=qwet DB_PASSWORD=123456 python -u app.py

# 健康检查三连
curl -s http://127.0.0.1:5000/api/stats
curl -s http://127.0.0.1:5000/api/xdr/scheduler/status
curl -s http://127.0.0.1:5000/api/vulns/scheduler/status

# 手动触发一次研判（真实调用，花钱）
curl -s -X POST http://127.0.0.1:5000/api/xdr/pipeline \
  -H 'Content-Type: application/json' -d '{"count":1}'

# 只测技能识别，不调 LLM
curl -s -X POST http://127.0.0.1:5000/api/skills/detect \
  -H 'Content-Type: application/json' \
  -d '{"text":"封禁 IP 1.2.3.4"}'

# 助理对话（注意参数名是 messages）
curl -s -X POST http://127.0.0.1:5000/api/assistant/chat \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"今天哪个学生受到了攻击"}]}'

# 日志
tail -f dashboard.log          # start_server.py 重定向的 stdout
tail -f flask.log              # Flask 侧
tail -f judgment.log           # 研判相关
tail -f data/vuln_scheduler.log # 漏洞调度器专用日志
```

### 9.2 数据库速查

```sql
-- 告警总览
SELECT id, name, severity, src_ip, target_ip, status, ai_result, ai_judged
FROM alerts ORDER BY update_time DESC LIMIT 10;

-- AI 结论分布（看提取成功率）
SELECT ai_result, COUNT(*) FROM alerts GROUP BY ai_result;

-- 有结论但没提取出 ai_result 的（结构提取失败样本）
SELECT id, LEFT(model_response, 200) FROM alerts
WHERE ai_judged = 1 AND (ai_result IS NULL OR ai_result = '');

-- 增量水位线
SELECT MAX(update_time) FROM alerts;

-- 封禁 / 加白
SELECT * FROM blocked_ips ORDER BY created_at DESC;
SELECT id, src_ip, dst_ip, name_pattern, enabled FROM whitelist_rules;
```

### 9.3 症状 → 病灶对照

| 症状 | 先查 | 常见根因 |
|------|------|----------|
| 页面无告警 | `SELECT COUNT(*) FROM alerts` + `POST /api/alarms/refresh` | 内存态未刷新；或 `delete_sample_alarms()` 把示例数据删了 |
| 拉取返回 `code != Success` | `xdr_pipeline.py:370-371` | 签名/时间戳偏移；XDR 侧 pageSize 上限（代码强制 `max(5, page_size)`） |
| 签名 401 | 系统时间 | `sign-date` 用 UTC（`xdr_pipeline.py:63-64`），本机时区/时间错会导致签名过期 |
| 大模型 502 | `app.py:1315-1336` | 上游返回体错；`llm_client` 自动补 `/v1` 可能造成 URL 404 |
| 大模型 429 | — | 自动退避 5s/10s 后仍失败才抛 |
| 漏洞库不更新 | `GET /api/vulns/scheduler/status` 的 `healthy` | 配置 `enabled=false`，或锁被别的进程持有 |
| 调度器不启动 | `cat .xdr_scheduler.lock` / `.vuln_scheduler.lock` | 残留锁里的 PID 仍活着；`start_server.py` 会自动清 |
| 上传 PDF 提取为空 | — | 没装 `pdfplumber`；`_extract_text_pdf`（`app.py:851-862`）静默返回空串 |
| 中文域名/文件名乱码 | — | `secure_filename()` 会剥离非 ASCII 字符（`app.py:917`） |

---

## 10. 一句话总结每层

| 层 | 一句话 |
|----|--------|
| XDR 对接 | 自研 HMAC-SHA256 签名器，支持连接码 AES 解密，零 SDK 依赖 |
| 研判编排 | 串行 for 循环 + 三段限速 sleep，先写原始告警再调 LLM，单条失败不影响整体 |
| 知识库 | 正则切词 + 同义词表 + 命中计数排序，非向量检索；上限 2500 字符 |
| 数据层 | MySQL 三表 + 全字段 upsert + 一套字段名转换层 + 一层"保护人的决策"的回填逻辑 |
| 服务层 | 1933 行单文件 Flask，54 个路由，3 个后台线程，状态全在内存全局变量 |
| 处置层 | 全部本地写库 + 内网硬校验，无真实 SOAR 联动（封禁是伪造的成功响应） |
| 前端 | 零构建原生 JS，700 行模板 + 2912 行 JS，可导出为单文件离线版 |

---

## 11. 对标开源升级记录（2026-09-28）

> 背景：调研了 GitHub 上同类/相关开源项目后，把「可直接落地、可回滚、不碰密钥」的改进落进了代码。
> **仓库仍无任何 git commit**（没有 `git checkout` 可用），所以每项改动都写明改动点；回滚 = 按说明还原对应函数/行。

### 11.1 对标了什么

| 项目 | 定位 | 本项目借鉴的设计 |
|------|------|------------------|
| [beenuar/AiSOC](https://github.com/beenuar/AiSOC)（MIT，自托管 AI SOC） | 告警融合 + 置信度评分 + agent 辅助 triage | **确定性评分层放在 agent 推理之前**（deterministic scoring → agentic reasoning）；triage 输出 TP/FP/benign 分档 + 置信度 → 对应本项目 U2（加白预评分）与 U3（置信度） |
| [M507/AI-SOC-Agent](https://github.com/M507/AI-SOC-Agent)（Black Hat USA 2025） | AI SOC agent + MCP server，自动调查/研判/响应 | **人工审批队列**（高危动作先审后执行）与**逐告警成本日志**（约 $0.18/条、50 秒/条的用量记录）→ 对应本项目 U1（处置硬校验是第一道防线）与 U5（llm_usage.jsonl）；vendor-neutral 接口层与分层 runbook 列入路线图 |
| [Shuffle/Shuffle](https://github.com/Shuffle/Shuffle)（2.4k★，SOAR） | 通用安全自动化编排，App/Action 插件机制 | 响应动作应插件化并带 dry-run——本项目的 `skills.py` handler 已具雏形，U1 给封禁动作补上了「安全拦截」语义 |
| [SOCFortress/coPilot](https://github.com/SOCFortress/coPilot)（529★） | 开源安全工具的 single pane of glass | 工程规范：`.gitignore`/`.env.example`/测试/容器化齐备 → 对应本项目 U6 |
| [center-for-threat-informed-defense/attack-flow](https://github.com/center-for-threat-informed-defense/attack-flow)（776★，MITRE） | 用 JSON Schema（AF 语言）把攻击链建模成节点+边 | 「多条告警 → 攻击链」应先定数据模型再做可视化——对应 `E:\tzb` 的攻击链还原工作，列入路线图，本次未实现 |

### 11.2 改了什么（U1–U6）

**U1 处置硬校验（防内网误封，对标 SOAR 安全阀）**
- `skills.py`：新增 `is_protected_ip(ip)`——RFC1918 私网 / 回环 / 链路本地 / 保留 / 组播 / 未指定地址一律判受保护；环境变量 `ALLOW_INTERNAL_BLOCK=1` 可解除。`execute_skill()` 的 `block_ip` 分支执行前先校验。
- `app.py` 四个封禁入口全部接入同一校验：`api_alarm_block`、`api_block_ip`、`api_firewall_block`、`execute_command` 的 `block_ip` 动作（LLM 路径同样被拦）。拒绝时返回 400 + 明确错误信息。
- 回滚：删除 `is_protected_ip` 及四处 `if skills.is_protected_ip(...)` 块。

**U2 确定性预评分（加白告警跳过 LLM，省钱，对标 AiSOC deterministic scoring）**
- `xdr_pipeline.py`：新增 `_matches_whitelist(item, rules)` 用原始 XDR item 匹配加白规则（src/dst IP、端口、名称模式，空字段=任意，与 app 层语义一致）；`run_pipeline` 在循环前加载规则，**每条告警先过预评分，命中则完全不调 LLM**，verdict 写「命中加白规则…确定性跳过」，`ai_judged=1`（后续拉取也会跳过）。
- 效果：演示库里已有 4 条加白规则，命中告警不再消耗模型调用；其余告警行为不变。
- 回滚：删除 `_matches_whitelist` 与 `run_pipeline` 中 `hit_rule` 分支。

**U3 置信度全链路（对标 AiSOC confidence scoring）**
- `xdr_pipeline.py`：system prompt 追加「研判结果下一行输出 置信度: 0-100」；新增 `extract_confidence(resp)`（容忍全角冒号/百分号，越界返回 None）。
- `db.py`：`alerts` 表经既有的 ALTER 幂等补列机制新增 `ai_confidence INT`（实测已自动建列）；`upsert_alarm` 字段表与 `record_from_xdr_result` 同步带出该字段。旧数据该列为 NULL。
- 回滚：删列 `ALTER TABLE alerts DROP COLUMN ai_confidence` + 还原三处代码。

**U4 RAG 修复（中文 bigram 切词 + 强特征加权 + CVE 去重）**
- `knowledge_context.py`：①`_tokenize` 对 >4 字的纯中文串做 bigram 滑窗拆分（CJK 检索经典做法），≤4 字保持整词，bigram 层面再滤停用词——修复了实验 2 发现的「20 字整段 token」缺陷；②`_score` 对 IP / CVE / ATT&CK ID 强特征命中记 3 分、普通词 1 分；③`_load_vuln_items` 按 cve_id 去重（CVSS 有分优先、modified 较新优先），消除多源重复 CVE；④关键词列表去重并截断到 `_MAX_KEYWORDS=60` 控制评分成本。
- 输出契约不变（`{text, vuln_matches, library_matches, keywords}`），两个调用方无需改动。
- 回滚：还原 `_tokenize`/`_score`/`_load_vuln_items` 三函数为旧版（旧版逻辑见 git 历史前的本文件备份，或按本条描述逆向）。

**U5 LLM 成本日志（对标 M507 逐告警成本记录）**
- `llm_client.py`：新增 `_log_usage()`，每次真实调用追加一行 JSONL 到 `data/llm_usage.jsonl`：`{ts, model, latency_ms, usage}`（FastGPT 与 OpenAI 兼容两条路径都接）。best-effort，失败静默。
- 回滚：删除 `_log_usage` 及两处调用。

**U6 工程规范（对标 SOCFortress/Shuffle 的开源标配）**
- 新增 `.gitignore`（密钥/运行产物/大文件全排除——**远程推送前必须的护栏**）、`.env.example`、`Dockerfile`、`docker-compose.yml`（app + MySQL 8 + 健康检查 + data 卷）、`.dockerignore`。
- `app.py` 三处已知缺陷顺手修复（对应 §8.3）：**#27** 补 `import atexit`（退出时能清理 `.xdr_scheduler.lock`）；**#28** 删除末尾 46 行重复定义的 `_normalize_attck_id`/`enrich_attck_info`；**#29** 删除 `__main__` 里永远不可达的第二行 `app.run`。
- 新增 `tests/`（unittest，pytest 兼容）：**33 个用例全绿**——切词/加权/去重/契约（test_knowledge_context）、签名确定性/结论与置信度提取/加白预评分（test_xdr_pipeline）、硬校验/技能识别（test_skills）、Flask 路由冒烟含内网封禁拒绝（test_app，需本地 MySQL，不可用时自动 skip）。§8.1 #16「仓库无测试」自此过时。
- 新增环境变量 `DISABLE_XDR_SCHEDULER=1`：`app.py` 模块级 `start_xdr_scheduler()` 前的开关——**测试/离线导入 app 时必须设置**，否则导入瞬间就会真实拉取 50 条并调模型（§8.3 #38 的防线）。
- 回滚：删除对应新文件；三处缺陷还原方式见 §8.3 描述。

### 11.3 升级后验证记录（实测）

- `python -m py_compile app.py db.py llm_client.py xdr_pipeline.py skills.py knowledge_context.py` 全过；
- `DISABLE_XDR_SCHEDULER=1 DB_USER=qwet DB_PASSWORD=123456 python -m unittest discover -s tests` → **Ran 33 tests, OK**（同时确认 `ai_confidence` 列自动建成）；
- 实验 1/2/7 复测输出已更新到 §6 对应小节（bigram 生效、top-5 CVE 全唯一）；
- 未实测项：`docker compose up`（本机未执行构建，compose 仅供部署参考，用时先跑一遍）、真实 LLM 的置信度输出（需真实研判一条验证 prompt 遵循度，见实验 5）。

### 11.4 看完开源后仍值得做的（路线图，未实现）

1. **人工审批队列**（M507 的 approval queue）：高危处置（封禁/隔离）先进待审队列，人工确认后执行——与 `E:\tzb` v5.0/v7.0 的「复核卡片」设计一脉相承；U1 的硬校验只是第一道闸。
2. **攻击链数据模型**（attack-flow 的 AF Schema）：把「时间序 + ATT&CK + 实体接力」的链还原结果落成节点+边 JSON，可视化自然就有抓手。
3. **vendor-neutral 接口层**（M507 的 `src/api/` 抽象）：把 XDR/防火墙/EDR 封成统一 client 接口，换平台只加 integration 目录。
4. **真语义 RAG**：bigram + 加权已是合格的 BM25 式基线；下一步才是 embedding 混合召回（`docs/04` v2.0 规划）。
5. **MCP 化**：把「查告警/封禁/加白/统计」暴露成 MCP tools，LLM 客户端可直接调查——与平台画布的「工作流工具」发布思路同构。

---

**下一步**：从 [§6 实验 1](#实验-1离线跑通-rag-召回零风险先做这个) 开始，30 分钟内你就能亲手跑出这条系统里最"聪明"的那部分。
