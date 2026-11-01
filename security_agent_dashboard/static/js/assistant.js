// 安全运营智能助理（规则 + 大模型双模式）
(function() {
    'use strict';

    var messagesEl, inputEl, panelEl, fabEl, closeBtn;
    var settingsBtn, settingsEl, modelToggle, modelSelect, modelForm, modelSection, skillsSection;
    var configName, configProvider, configBaseUrl, configKey, configModel, configId;
    var addBtn, saveBtn, cancelBtn, deleteBtn, testBtn;
    var tabModelBtn, tabSkillsBtn;
    var skillsList, skillForm, skillConfigAdd, skillConfigSave, skillConfigCancel, skillConfigDelete;
    var skillConfigName, skillConfigDesc, skillConfigHandler, skillConfigKeywords, skillConfigId;
    var isOpen = false, settingsOpen = false, modelMode = false;
    var fabDragged = false;
    var modelConfigs = [], skillConfigs = [];

    function $(s) { return document.querySelector(s); }
    function $$(s) { return document.querySelectorAll(s); }

    function escapeHtml(str) {
        return String(str).replace(/[&<>"']/g, function(m) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
        });
    }

    function apiGet(path) {
        var sep = path.indexOf('?') >= 0 ? '&' : '?';
        return fetch(path + sep + '_=' + Date.now(), { headers: { 'Accept': 'application/json' } }).then(function(r) {
            if (!r.ok) throw new Error(path + ' returned ' + r.status);
            return r.json();
        });
    }

    function apiPost(path, body) {
        var sep = path.indexOf('?') >= 0 ? '&' : '?';
        return fetch(path + sep + '_=' + Date.now(), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify(body || {})
        }).then(function(r) {
            if (!r.ok) {
                return r.json().then(function(data) {
                    throw new Error(data.error || (path + ' returned ' + r.status));
                }).catch(function() {
                    throw new Error(path + ' returned ' + r.status);
                });
            }
            return r.json();
        });
    }

    function apiDelete(path) {
        var sep = path.indexOf('?') >= 0 ? '&' : '?';
        return fetch(path + sep + '_=' + Date.now(), { method: 'DELETE', headers: { 'Accept': 'application/json' } }).then(function(r) {
            if (!r.ok) {
                return r.json().then(function(data) {
                    throw new Error(data.error || (path + ' returned ' + r.status));
                }).catch(function() {
                    throw new Error(path + ' returned ' + r.status);
                });
            }
            return r.json();
        });
    }

    function refreshAppState() {
        if (typeof window.loadPlatformData === 'function') window.loadPlatformData();
    }

    // ---------------- 模型配置 ----------------

    function loadModelConfigs() {
        apiGet('/api/config/models').then(function(list) {
            modelConfigs = list || [];
            renderModelSelect();
            if (modelConfigs.length === 0) {
                showModelForm({});
            } else {
                var active = modelConfigs.find(function(c) { return c.active; });
                if (active) showModelForm(active);
                else hideModelForm();
            }
        }).catch(function(e) { console.error('加载模型配置失败', e); });
    }

    function renderModelSelect() {
        var html = '<option value="">未配置模型</option>';
        modelConfigs.forEach(function(c) {
            html += '<option value="' + escapeHtml(c.id) + '"' + (c.active ? ' selected' : '') + '>' +
                escapeHtml(c.name || (c.provider + ' / ' + c.model)) + '</option>';
        });
        modelSelect.innerHTML = html;
    }

    function showModelForm(cfg) {
        cfg = cfg || {};
        configId.value = cfg.id || '';
        configName.value = cfg.name || '';
        configProvider.value = cfg.provider || 'openai';
        configBaseUrl.value = cfg.base_url || '';
        configKey.value = '';
        configModel.value = cfg.model || '';
        modelForm.style.display = 'block';
        deleteBtn.style.display = cfg.id ? 'inline-block' : 'none';
        testBtn.style.display = cfg.id ? 'inline-block' : 'none';
    }

    function hideModelForm() {
        modelForm.style.display = 'none';
    }

    function saveModelConfig() {
        var body = {
            name: configName.value.trim(),
            provider: configProvider.value,
            base_url: configBaseUrl.value.trim(),
            model: configModel.value.trim(),
            active: true
        };
        var key = configKey.value.trim();
        if (key) body.api_key = key;
        if (!body.name) return alert('请输入名称');
        if (!body.model) return alert('请输入模型名');
        var id = configId.value;
        if (id) body.id = id;
        apiPost('/api/config/models', body).then(function(saved) {
            loadModelConfigs();
            modelSelect.value = saved.id;
            setModelMode(modelToggle.checked);
        }).catch(function(e) { alert('保存失败：' + e.message); });
    }

    function deleteModelConfig() {
        var id = configId.value;
        if (!id) return;
        if (!confirm('确定删除该模型配置？')) return;
        apiDelete('/api/config/models/' + encodeURIComponent(id)).then(function() {
            loadModelConfigs();
            hideModelForm();
        }).catch(function(e) { alert('删除失败：' + e.message); });
    }

    function testModelConfig() {
        var id = configId.value;
        if (!id) return;
        addMessage('bot', '正在测试模型连接，请稍候…');
        apiPost('/api/assistant/chat', { messages: [{ role: 'user', content: '你好，请简短回复。' }] })
            .then(function(res) {
                addMessage('bot', '测试成功：<br>' + escapeHtml(res.reply || res.error || '无回复'));
            }).catch(function(e) { addMessage('bot', '测试失败：' + escapeHtml(e.message)); });
    }

    function setActiveModel(id) {
        if (!id) return;
        apiPost('/api/config/models', { id: id, active: true }).then(function() {
            loadModelConfigs();
        }).catch(function(e) { console.error('设置活动模型失败', e); });
    }

    function setProviderDefaults(provider) {
        var defaults = {
            openai: { base_url: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
            minimax: { base_url: 'https://api.minimaxi.chat/v1', model: 'abab6.5s-chat' },
            kimi: { base_url: 'https://api.moonshot.cn/v1', model: 'moonshot-v1-8k' }
        };
        var d = defaults[provider];
        if (!d) return;
        if (!configBaseUrl.value) configBaseUrl.value = d.base_url;
        if (!configModel.value) configModel.value = d.model;
    }

    function toggleSettings() {
        settingsOpen = !settingsOpen;
        settingsEl.classList.toggle('open', settingsOpen);
        if (settingsOpen) { loadModelConfigs(); loadSkills(); }
    }

    function setModelMode(enabled) {
        modelMode = enabled;
        modelToggle.checked = enabled;
        localStorage.setItem('assistant_model_mode', enabled ? '1' : '0');
        if (enabled && modelConfigs.length === 0) {
            addMessage('bot', '大模型模式已开启，但还没有配置模型。请在上方“模型设置”中添加一个模型。');
        }
    }

    // ---------------- 聊天 UI ----------------

    function init() {
        messagesEl = $('#assistant-messages');
        inputEl = $('#assistant-input');
        panelEl = $('#assistant-panel');
        fabEl = $('#assistant-fab');
        closeBtn = $('#assistant-close');
        if (!messagesEl || !inputEl || !panelEl || !fabEl) return;

        // 技能配置元素
        modelSection = $('#assistant-model-section');
        skillsSection = $('#assistant-skills-section');
        tabModelBtn = $('#tab-model');
        tabSkillsBtn = $('#tab-skills');
        skillsList = $('#skills-list');
        skillForm = $('#assistant-skill-form');
        skillConfigAdd = $('#skill-config-add');
        skillConfigSave = $('#skill-config-save');
        skillConfigCancel = $('#skill-config-cancel');
        skillConfigDelete = $('#skill-config-delete');
        skillConfigName = $('#skill-config-name');
        skillConfigDesc = $('#skill-config-desc');
        skillConfigHandler = $('#skill-config-handler');
        skillConfigKeywords = $('#skill-config-keywords');
        skillConfigId = $('#skill-config-id');

        fabEl.addEventListener('click', onFabClick);
        initFabDrag();
        restoreFabPosition();
        closeBtn.addEventListener('click', toggleChat);
        $('#assistant-send').addEventListener('click', sendMessage);
        inputEl.addEventListener('keydown', function(e) { if (e.key === 'Enter') sendMessage(); });

        $$('.assistant-hints button').forEach(function(btn) {
            btn.addEventListener('click', function() {
                inputEl.value = btn.textContent;
                sendMessage();
            });
        });

        // settings
        settingsBtn = $('#assistant-settings-btn');
        settingsEl = $('#assistant-settings');
        modelToggle = $('#assistant-model-toggle');
        modelSelect = $('#assistant-model-select');
        modelForm = $('#assistant-model-form');
        configName = $('#model-config-name');
        configProvider = $('#model-config-provider');
        configBaseUrl = $('#model-config-baseurl');
        configKey = $('#model-config-key');
        configModel = $('#model-config-model');
        configId = $('#model-config-id');
        saveBtn = $('#model-config-save');
        cancelBtn = $('#model-config-cancel');
        deleteBtn = $('#model-config-delete');
        testBtn = $('#model-config-test');
        addBtn = $('#model-config-add');

        if (settingsBtn) settingsBtn.addEventListener('click', toggleSettings);
        if (saveBtn) saveBtn.addEventListener('click', saveModelConfig);
        if (cancelBtn) cancelBtn.addEventListener('click', hideModelForm);
        if (deleteBtn) deleteBtn.addEventListener('click', deleteModelConfig);
        if (testBtn) testBtn.addEventListener('click', testModelConfig);
        if (modelSelect) {
            modelSelect.addEventListener('change', function() {
                var cfg = modelConfigs.find(function(c) { return c.id === modelSelect.value; });
                if (cfg) { showModelForm(cfg); setActiveModel(cfg.id); }
                else hideModelForm();
            });
        }
        if (addBtn) {
            addBtn.addEventListener('click', function() {
                modelSelect.value = '';
                showModelForm({});
                setProviderDefaults(configProvider.value);
                configName.focus();
            });
        }
        if (configProvider) {
            configProvider.addEventListener('change', function() {
                setProviderDefaults(configProvider.value);
            });
        }
        if (modelToggle) {
            modelToggle.addEventListener('change', function() { setModelMode(modelToggle.checked); });
            var saved = localStorage.getItem('assistant_model_mode');
            if (saved === '1') modelToggle.checked = true;
            setModelMode(modelToggle.checked);
        }

        // 技能 Tab
        if (tabModelBtn && tabSkillsBtn) {
            tabModelBtn.addEventListener('click', function() {
                modelSection.style.display = 'block';
                skillsSection.style.display = 'none';
                tabModelBtn.className = 'btn btn-sm btn-primary';
                tabSkillsBtn.className = 'btn btn-sm btn-ghost';
            });
            tabSkillsBtn.addEventListener('click', function() {
                modelSection.style.display = 'none';
                skillsSection.style.display = 'block';
                tabModelBtn.className = 'btn btn-sm btn-ghost';
                tabSkillsBtn.className = 'btn btn-sm btn-primary';
                loadSkills();
            });
        }
        if (skillConfigAdd) skillConfigAdd.addEventListener('click', function() { showSkillForm({}); });
        if (skillConfigSave) skillConfigSave.addEventListener('click', saveSkill);
        if (skillConfigCancel) skillConfigCancel.addEventListener('click', hideSkillForm);
        if (skillConfigDelete) skillConfigDelete.addEventListener('click', deleteSkill);

        addMessage('bot', '你好，我是安全运营智能助理。可以问我平台数据，也可以让我执行封禁、告警加白、IP 查询等操作。');
    }

    function isInPageView() {
        return panelEl && panelEl.parentElement && panelEl.parentElement.id === 'view-assistant';
    }

    function toggleChat() {
        if (isInPageView()) {
            if (typeof window.setView === 'function') window.setView('dashboard');
            return;
        }
        isOpen = !isOpen;
        if (isOpen) positionPanelNearFab();
        panelEl.classList.toggle('open', isOpen);
        fabEl.classList.toggle('open', isOpen);
        if (isOpen) setTimeout(function() { inputEl.focus(); }, 100);
    }


    function onFabClick(e) {
        if (fabDragged) { fabDragged = false; return; }
        toggleChat();
    }

    function restoreFabPosition() {
        try {
            var pos = JSON.parse(localStorage.getItem('assistant_fab_pos'));
            if (pos && typeof pos.right === 'number' && typeof pos.bottom === 'number') {
                setFabPosition(pos.right, pos.bottom);
            }
        } catch (e) {}
    }

    function setFabPosition(right, bottom) {
        var size = 56;
        right = Math.max(0, Math.min(window.innerWidth - size, right));
        bottom = Math.max(0, Math.min(window.innerHeight - size, bottom));
        fabEl.style.right = right + 'px';
        fabEl.style.bottom = bottom + 'px';
        fabEl.style.left = 'auto';
        fabEl.style.top = 'auto';
    }

    function saveFabPosition() {
        var rect = fabEl.getBoundingClientRect();
        var right = window.innerWidth - rect.right;
        var bottom = window.innerHeight - rect.bottom;
        localStorage.setItem('assistant_fab_pos', JSON.stringify({ right: right, bottom: bottom }));
    }

    function initFabDrag() {
        var startX, startY, offsetX, offsetY, dragging = false;
        var dragThreshold = 5;
        fabEl.addEventListener('pointerdown', function(e) {
            if (e.button !== 0) return;
            e.preventDefault();
            var rect = fabEl.getBoundingClientRect();
            startX = e.clientX;
            startY = e.clientY;
            offsetX = rect.right - e.clientX;
            offsetY = rect.bottom - e.clientY;
            dragging = true;
            fabDragged = false;
            fabEl.classList.add('dragging');
            try { fabEl.setPointerCapture(e.pointerId); } catch (err) {}
        });
        fabEl.addEventListener('pointermove', function(e) {
            if (!dragging) return;
            e.preventDefault();
            var dx = e.clientX - startX;
            var dy = e.clientY - startY;
            if (Math.sqrt(dx * dx + dy * dy) > dragThreshold) fabDragged = true;
            var right = window.innerWidth - e.clientX - offsetX;
            var bottom = window.innerHeight - e.clientY - offsetY;
            setFabPosition(right, bottom);
        });
        fabEl.addEventListener('pointerup', function(e) {
            if (!dragging) return;
            dragging = false;
            fabEl.classList.remove('dragging');
            try { fabEl.releasePointerCapture(e.pointerId); } catch (err) {}
            saveFabPosition();
        });
        fabEl.addEventListener('pointercancel', function(e) {
            if (!dragging) return;
            dragging = false;
            fabEl.classList.remove('dragging');
            try { fabEl.releasePointerCapture(e.pointerId); } catch (err) {}
            saveFabPosition();
        });
    }

    function positionPanelNearFab() {
        var fabRect = fabEl.getBoundingClientRect();
        var desiredRight = window.innerWidth - fabRect.right;
        var desiredBottom = window.innerHeight - fabRect.bottom;
        var isMobile = window.innerWidth <= 760;
        var minGap = isMobile ? 12 : 24;
        var panelW = isMobile ? window.innerWidth - 24 : 380;
        var panelH = isMobile ? window.innerHeight - 80 : 520;
        desiredRight = Math.max(minGap, Math.min(window.innerWidth - panelW - minGap, desiredRight));
        desiredBottom = Math.max(minGap, Math.min(window.innerHeight - panelH - minGap, desiredBottom));
        panelEl.style.right = desiredRight + 'px';
        panelEl.style.bottom = desiredBottom + 'px';
    }

    window.closeAssistantChat = function() {
        isOpen = false;
        if (panelEl) panelEl.classList.remove('open');
        if (fabEl) fabEl.classList.remove('open');
    };

    window.toggleAssistantChat = toggleChat;

    function addMessage(role, html) {
        var div = document.createElement('div');
        div.className = 'assistant-message ' + role;
        div.innerHTML = '<div class="bubble">' + html + '</div>';
        messagesEl.appendChild(div);
        messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    function showLoading() {
        var id = 'assistant-loading-' + Date.now();
        var div = document.createElement('div');
        div.id = id;
        div.className = 'assistant-message bot';
        div.innerHTML = '<div class="bubble loading"><span></span><span></span><span></span></div>';
        messagesEl.appendChild(div);
        messagesEl.scrollTop = messagesEl.scrollHeight;
        return id;
    }

    function removeLoading(id) {
        var el = document.getElementById(id);
        if (el) el.remove();
    }

    function sendMessage() {
        var text = inputEl.value.trim();
        if (!text) return;
        addMessage('user', escapeHtml(text));
        inputEl.value = '';
        var loadingId = showLoading();
        detectSkill(text).then(function(res) {
            if (res.matched) {
                // 技能匹配时仍走 /api/assistant/chat，让后端注入 user_text 并解析时间范围
                removeLoading(loadingId);
                return sendModelMessage(text);
            }
            removeLoading(loadingId);
            if (modelMode) return sendModelMessage(text);
            var pid = showLoading();
            processMessage(text).then(function(replyHtml) {
                removeLoading(pid);
                addMessage('bot', replyHtml);
            }).catch(function(e) {
                removeLoading(pid);
                addMessage('bot', '操作失败：' + escapeHtml(e.message || '未知错误'));
            });
        }).catch(function(e) {
            removeLoading(loadingId);
            addMessage('bot', '操作失败：' + escapeHtml(e.message || '未知错误'));
        });
    }

    function sendModelMessage(text) {
        var loadingId = showLoading();
        apiPost('/api/assistant/chat', { messages: [{ role: 'user', content: text }] })
            .then(function(res) {
                removeLoading(loadingId);
                if (res.error) {
                    addMessage('bot', '模型调用失败：' + escapeHtml(res.error));
                    return;
                }
                if (res.command) {
                    executeCommand(res.command);
                }
                addMessage('bot', escapeHtml(res.reply || ''));
                refreshAppState();
            }).catch(function(e) {
                removeLoading(loadingId);
                addMessage('bot', '模型调用失败：' + escapeHtml(e.message || '未知错误'));
            });
    }

    function executeCommand(cmd) {
        switch (cmd.action) {
            case 'block_ip':
                apiPost('/api/firewall/block', { ip: cmd.ip, reason: '智能助理封禁' })
                    .then(function(res) { refreshAppState(); addMessage('bot', escapeHtml(res.message || res.error || '执行失败')); });
                break;
            case 'unblock_ip':
                apiDelete('/api/blocked/' + encodeURIComponent(cmd.ip))
                    .then(function() { refreshAppState(); addMessage('bot', '已执行：解封 IP ' + escapeHtml(cmd.ip)); });
                break;
            case 'false_positive':
                apiPost('/api/alarms/' + encodeURIComponent(cmd.id) + '/false_positive', { reason: '智能助理告警加白' })
                    .then(function() { refreshAppState(); addMessage('bot', '已执行：告警 ' + escapeHtml(cmd.id) + ' 加入加白'); });
                break;
            case 'close_alarm':
                apiPost('/api/alarms/' + encodeURIComponent(cmd.id) + '/status', { status: 'closed' })
                    .then(function() { refreshAppState(); addMessage('bot', '已执行：关闭告警 ' + escapeHtml(cmd.id)); });
                break;
            default:
                addMessage('bot', '未知操作：' + escapeHtml(cmd.action));
        }
    }

    function navigateTo(viewId) {
        if (typeof window.setView === 'function') { window.setView(viewId); return true; }
        return false;
    }

    function detectIntent(text) {
        var t = text.toLowerCase();
        var ipMatch = t.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        var alarmMatch = t.match(/(alt-\d{8}-\d{3})/i);
        var hasNav = /打开|查看|切换到?|跳转到?|去.*页面|进入/.test(t);

        if (hasNav) {
            if (/总览|dashboard|首页|主页/.test(t)) return { action: 'navigate', view: 'dashboard' };
            if (/告警|alarm/.test(t)) return { action: 'navigate', view: 'alarms' };
            if (/封禁|blocked|黑名单|阻断/.test(t)) return { action: 'navigate', view: 'blocking' };
            if (/att.ck|attack|战术|矩阵/.test(t)) return { action: 'navigate', view: 'attck' };
            if (/误报|加白|false.positive/.test(t)) return { action: 'navigate', view: 'falsepositive' };
            if (/报告|report/.test(t)) return { action: 'navigate', view: 'reports' };
            if (/资产|asset|网站|域名/.test(t)) return { action: 'navigate', view: 'assets' };
        }

        if (/统计|多少|数量|几个|概况|指标/.test(t) && !/ip/.test(t)) return { action: 'stats' };

        if (/封禁|block|拉黑|阻断/.test(t)) {
            if (alarmMatch) return { action: 'block_alarm', id: alarmMatch[1] };
            if (ipMatch) return { action: 'block', ip: ipMatch[1] };
        }
        if (/解封|unblock|放行|释放/.test(t) && ipMatch) return { action: 'unblock', ip: ipMatch[1] };
        if (/误报|加白|false.?positive/.test(t) && alarmMatch) return { action: 'false_positive', id: alarmMatch[1] };
        if (/关闭|close/.test(t) && alarmMatch) return { action: 'close', id: alarmMatch[1] };

        if (/哪些.*封禁|封禁.*哪些|封禁列表|blocked/.test(t) || (/封禁|block/.test(t) && /列表|list|哪些/.test(t))) {
            return { action: 'blocked_list' };
        }
        if (/att.ck|attack/.test(t) && (/最多|统计|排名|技术/.test(t))) return { action: 'attack_stats' };
        if (/资产|asset|网站|域名/.test(t) && (/哪些|列表|状态|有/.test(t) || /多少/.test(t))) return { action: 'assets' };
        if (/同学|学生|终端.*(中毒|感染|木马|病毒)|哪些.*(同学|学生).*(中毒|感染|中病毒)/.test(t)) {
            return { action: 'infected_students' };
        }
        if (/告警|alarm/.test(t) || /严重|高危|critical|high/.test(t)) {
            var status = '', severity = '';
            if (/待处理|未处理|open/.test(t)) status = 'open';
            if (/已封禁|blocked/.test(t)) status = 'blocked';
            if (/误报|加白|false.?positive/.test(t)) status = 'false_positive';
            if (/已关闭|closed/.test(t)) status = 'closed';
            if (/严重|critical/.test(t)) severity = 'critical';
            else if (/高危|high/.test(t)) severity = 'high';
            else if (/中危|medium/.test(t)) severity = 'medium';
            else if (/低危|low/.test(t)) severity = 'low';
            return { action: 'alarms', q: text, status: status, severity: severity };
        }
        return { action: 'unknown' };
    }

    function processMessage(text) {
        var intent = detectIntent(text);
        switch (intent.action) {
            case 'stats': return intentStats();
            case 'alarms': return intentAlarms(intent.q, intent.status, intent.severity);
            case 'block': return intentBlockIp(intent.ip);
            case 'block_alarm': return intentBlockAlarm(intent.id);
            case 'unblock': return intentUnblockIp(intent.ip);
            case 'false_positive': return intentFalsePositive(intent.id);
            case 'close': return intentCloseAlarm(intent.id);
            case 'blocked_list': return intentBlockedList();
            case 'attack_stats': return intentAttackStats();
            case 'assets': return intentAssets();
            case 'infected_students': return intentInfectedStudents();
            case 'navigate': return intentNavigate(intent.view);
            default: return Promise.resolve('抱歉，我没听懂。可以试试："今天有多少告警"、"封禁 IP 1.2.3.4"、"把 ALT-20260821-005 加入加白"。');
        }
    }

    function intentStats() {
        return apiGet('/api/stats').then(function(s) {
            return '当前安全态势：<br>' +
                '· 告警总数：<b>' + s.total + '</b><br>' +
                '· 高危/严重告警：<b>' + s.high + '</b><br>' +
                '· 待处理告警：<b>' + s.open + '</b><br>' +
                '· 已封禁 IP：<b>' + s.blocked + '</b><br>' +
                '· 告警加白：<b>' + s.false_positive + '</b>';
        });
    }

    function intentAlarms(q, status, severity) {
        var params = [];
        if (status) params.push('status=' + encodeURIComponent(status));
        if (severity) params.push('severity=' + encodeURIComponent(severity));
        var url = '/api/alarms' + (params.length ? '?' + params.join('&') : '');
        return apiGet(url).then(function(list) {
            if (!list.length) return '未找到匹配告警。';
            var total = list.length;
            var head = list.slice(0, 5);
            var lines = head.map(function(a) {
                var sevMap = { critical: '严重', high: '高危', medium: '中危', low: '低危' };
                return a.id + ' [' + (sevMap[a.severity] || a.severity) + '] ' + a.type + ' | ' + a.src + ' → ' + a.target + ' | ' + a.status;
            });
            var reply = '共找到 <b>' + total + '</b> 条告警' + (status ? '（状态：' + status + '）' : '') + (severity ? '（等级：' + severity + '）' : '') + '：<br>' + lines.join('<br>');
            if (total > 5) reply += '<br>... 还有 ' + (total - 5) + ' 条';
            return reply;
        });
    }

    function intentBlockIp(ip) {
        return apiPost('/api/firewall/block', { ip: ip, reason: '智能助理手动封禁' }).then(function(res) {
            refreshAppState();
            return escapeHtml(res.message || res.error || '执行失败');
        });
    }

    function intentBlockAlarm(id) {
        return apiPost('/api/alarms/' + encodeURIComponent(id) + '/block').then(function(res) {
            refreshAppState();
            var alarm = res.alarm || {};
            return '已根据告警 <b>' + escapeHtml(id) + '</b> 封禁源 IP <b>' + escapeHtml(alarm.src || '') + '</b>。';
        });
    }

    function intentUnblockIp(ip) {
        return apiDelete('/api/blocked/' + encodeURIComponent(ip)).then(function() {
            refreshAppState();
            return '已解封 IP <b>' + escapeHtml(ip) + '</b>。';
        });
    }

    function intentFalsePositive(id) {
        return apiPost('/api/alarms/' + encodeURIComponent(id) + '/false_positive', { reason: '智能助理告警加白' }).then(function() {
            refreshAppState();
            return '已将告警 <b>' + escapeHtml(id) + '</b> 加入加白。';
        });
    }

    function intentCloseAlarm(id) {
        return apiPost('/api/alarms/' + encodeURIComponent(id) + '/status', { status: 'closed' }).then(function() {
            refreshAppState();
            return '已关闭告警 <b>' + escapeHtml(id) + '</b>。';
        });
    }


    function intentInfectedStudents() {
        return apiGet('/api/assistant/infected_students').then(function(list) {
            if (!list.length) return '当前没有检测到终端中毒/恶意软件感染的告警。';
            var lines = list.map(function(s) {
                var name = s.student_name || '未知';
                return '· ' + escapeHtml(name) + '（学号：' + escapeHtml(s.student_id || '-') + '，院系：' + escapeHtml(s.department || '-') + '）— 终端 IP ' + escapeHtml(s.ip) + '，告警：' + escapeHtml(s.name);
            });
            return '检测到以下同学的终端存在中毒/恶意软件感染风险：<br>' + lines.join('<br>');
        });
    }

    function intentBlockedList() {
        return apiGet('/api/blocked').then(function(list) {
            if (!list.length) return '当前没有 IP 被封禁。';
            var lines = list.map(function(b) { return b.ip + ' | ' + b.reason + ' | ' + b.time; });
            return '当前共有 <b>' + list.length + '</b> 个 IP 被封禁：<br>' + lines.join('<br>');
        });
    }

    function intentAttackStats() {
        return apiGet('/api/attack/stats').then(function(data) {
            var top = data.top || [];
            if (!top.length) return '当前没有 ATT&CK 映射数据。';
            var lines = top.map(function(item) { return item[0] + '：' + item[1] + ' 次'; });
            return 'ATT&CK 高频技术 TOP ' + top.length + '：<br>' + lines.join('<br>');
        });
    }

    function intentAssets() {
        return apiGet('/api/assets').then(function(list) {
            if (!list.length) return '当前没有监测资产。';
            var lines = list.map(function(a) {
                return a.id + ' | ' + a.domain + ' | ' + a.ip + ':' + a.port + ' | WAF ' + a.waf + ' | SSL ' + a.ssl_days + ' 天';
            });
            return '当前共有 <b>' + list.length + '</b> 个 Web 资产：<br>' + lines.join('<br>');
        });
    }

    // ---------------- 技能配置与执行 ----------------

    function loadSkills() {
        apiGet('/api/skills').then(function(list) {
            skillConfigs = list || [];
            renderSkills();
        }).catch(function(e) { console.error('加载技能失败', e); });
    }

    function renderSkills() {
        if (!skillsList) return;
        if (!skillConfigs.length) {
            skillsList.innerHTML = '<div class="hint">暂无技能</div>';
            return;
        }
        skillsList.innerHTML = skillConfigs.map(function(s) {
            return '<div class="skill-item" style="display:flex;align-items:center;gap:8px;margin-bottom:6px;padding:6px;border:1px solid #eee;border-radius:4px;">' +
                '<input type="checkbox" class="skill-enabled" data-id="' + escapeHtml(s.id) + '"' + (s.enabled ? ' checked' : '') + '>' +
                '<span style="flex:1;">' + escapeHtml(s.name) + ' <span class="hint">(' + escapeHtml(s.handler) + ')</span></span>' +
                '<button class="btn btn-sm btn-ghost edit-skill" data-id="' + escapeHtml(s.id) + '">编辑</button>' +
                '</div>';
        }).join('');
        skillsList.querySelectorAll('.skill-enabled').forEach(function(cb) {
            cb.addEventListener('change', function() {
                var id = cb.getAttribute('data-id');
                var cfg = skillConfigs.find(function(c) { return c.id === id; });
                if (!cfg) return;
                cfg.enabled = cb.checked;
                apiPost('/api/skills', cfg).then(function() { loadSkills(); }).catch(function(e) { alert('保存失败：' + e.message); });
            });
        });
        skillsList.querySelectorAll('.edit-skill').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var id = btn.getAttribute('data-id');
                var cfg = skillConfigs.find(function(c) { return c.id === id; });
                if (cfg) showSkillForm(cfg);
            });
        });
    }

    function showSkillForm(cfg) {
        cfg = cfg || {};
        skillConfigId.value = cfg.id || '';
        skillConfigName.value = cfg.name || '';
        skillConfigDesc.value = cfg.description || '';
        skillConfigHandler.value = cfg.handler || 'block_ip';
        skillConfigKeywords.value = (cfg.trigger_keywords || []).join(',');
        skillForm.style.display = 'block';
        skillConfigDelete.style.display = cfg.id ? 'inline-block' : 'none';
    }

    function hideSkillForm() {
        skillForm.style.display = 'none';
    }

    function saveSkill() {
        var body = {
            name: skillConfigName.value.trim(),
            description: skillConfigDesc.value.trim(),
            handler: skillConfigHandler.value,
            trigger_keywords: skillConfigKeywords.value.split(',').map(function(k) { return k.trim(); }).filter(function(k) { return k; }),
            enabled: true,
            params: skillConfigHandler.value === 'block_ip'
                ? [{"name":"ip","type":"ip","required":true,"description":"要封禁的IP"},{"name":"reason","type":"string","required":false,"description":"封禁原因"}]
                : [{"name":"ip","type":"ip","required":true,"description":"要查询的IP"}]
        };
        if (!body.name) return alert('请输入技能名称');
        var id = skillConfigId.value;
        if (id) body.id = id;
        apiPost('/api/skills', body).then(function() {
            hideSkillForm();
            loadSkills();
        }).catch(function(e) { alert('保存失败：' + e.message); });
    }

    function deleteSkill() {
        var id = skillConfigId.value;
        if (!id) return;
        if (!confirm('确定删除该技能？')) return;
        apiDelete('/api/skills/' + encodeURIComponent(id)).then(function() {
            hideSkillForm();
            loadSkills();
        }).catch(function(e) { alert('删除失败：' + e.message); });
    }

    function detectSkill(text) {
        return apiPost('/api/skills/detect', { text: text }).catch(function(e) {
            console.error('技能检测失败', e);
            return { matched: false };
        });
    }

    function invokeSkill(id, params) {
        return apiPost('/api/skills/' + encodeURIComponent(id) + '/invoke', params || {}).then(function(res) {
            if (res.ok) {
                addMessage('bot', escapeHtml(res.message || '已执行'));
            } else {
                addMessage('bot', '技能执行失败：' + escapeHtml(res.error || '未知错误'));
            }
            refreshAppState();
        }).catch(function(e) {
            addMessage('bot', '技能调用失败：' + escapeHtml(e.message || '未知错误'));
        });
    }

   function intentNavigate(viewId) {
       var titles = {
          dashboard: '安全运营总览', alarms: '告警中心', blocking: 'IP 封禁',
            attck: 'ATT&CK 映射', falsepositive: '告警加白', reports: '报告生成', assets: 'Web 资产监测'
        };
        if (navigateTo(viewId)) return Promise.resolve('已切换到<b>' + (titles[viewId] || viewId) + '</b>页面。');
        return Promise.resolve('已尝试切换页面。');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        setTimeout(init, 0);
    }
})();
