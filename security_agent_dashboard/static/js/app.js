(function() {
    'use strict';

    // 平台数据由后端 API 加载
    var alarmData = [];

    var techniqueNames = {
        'T1071.001': '应用层协议: Web 协议',
        'T1110': '暴力破解',
        'T1498': '网络拒绝服务',
        'T1059.003': '命令和脚本解释器: Windows Cmd',
        'T1078': '有效账户',
        'T1041': '通过 C2 通道渗出',
        'T1021.002': '远程服务: SMB/Windows Admin Shares',
        'T1505.003': 'Web Shell',
        'T1091': '可复制到可移动媒体',
        'T1003': 'OS 凭证转储',
        'T1566.001': '钓鱼: 鱼叉式钓鱼附件',
       'T1053': '计划任务/作业'
   };

   var tacticGroups = {
       '侦察': [],
       '资源开发': [],
       '初始访问': [],
       '执行': [],
       '持久化': [],
       '权限提升': [],
       '隐藏痕迹': [],
       '防御削弱': [],
       '凭证访问': [],
       '发现': [],
       '横向移动': [],
       '收集': [],
       '命令与控制': [],
       '外渗': [],
       '影响': []
   };

    var parentInfo = {};
   var _attackTechniques = {};

    function applyAttackData(data) {
        if (!Array.isArray(data)) return;
       data.forEach(function(item) {
           if (!item.id || !Array.isArray(item.tactics)) return;
            _attackTechniques[item.id] = item;
            var displayName = item.nameZh || item.name || item.id;
            techniqueNames[item.id] = displayName;
            if (item.parentId) {
                parentInfo[item.id] = {
                    parentId: item.parentId,
                    parentNameZh: item.parentNameZh || item.parentName || item.parentId
                };
            }
           item.tactics.forEach(function(tactic) {
                if (!tacticGroups[tactic]) tacticGroups[tactic] = [];
                if (tacticGroups[tactic].indexOf(item.id) === -1) tacticGroups[tactic].push(item.id);
            });
        });
        var filter = $('#tactic-filter');
        filter.innerHTML = '<option value="">全部战术</option>';
        Object.keys(tacticGroups).forEach(function(t) {
            var opt = document.createElement('option');
            opt.value = t;
            opt.textContent = t;
            filter.appendChild(opt);
        });
        renderAttck();
        renderTacticBars();
        renderAlarms();
    }

    function loadAttackData() {
        function apply(data) { applyAttackData(data); }
        if (window.__attackData) {
            apply(window.__attackData);
        } else {
            fetch('./static/data/attack_subtechniques.json')
                .then(function(r) { if (!r.ok) throw new Error('status ' + r.status); return r.json(); })
                .then(apply)
                .catch(function(e) { console.warn('加载 ATT&CK JSON 失败，使用内置数据', e); });
        }
    }

    var blocked = [];

    var whitelistRules = [];

    var falsePositiveReasons = [
        '已确认内部运维账号',
        '业务高峰导致正常流量激增',
        '内部压力测试',
        '第三方安全扫描授权',
        '规则误命中：白名单已更新'
    ];

    function $(selector) { return document.querySelector(selector); }
    function $$(selector) { return document.querySelectorAll(selector); }

    function escapeHtml(str) {
        return String(str).replace(/[&<>"']/g, function(m) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
        });
    }

    function showToast(message, type) {
        var toast = $('#toast');
        toast.textContent = message;
        toast.classList.add('show');
        setTimeout(function() { toast.classList.remove('show'); }, 2200);
    }

    function formatSeverity(sev) {
        var map = { critical: '严重', high: '高危', medium: '中危', low: '低危' };
        return '<span class="severity ' + sev + '"><span class="dot"></span>' + (map[sev] || sev) + '</span>';
    }

   function formatStatus(status) {
       var map = { pending: '待处置', open: '待处置', blocked: '已处置', false_positive: '加白告警', closed: '已处置' };
       return map[status] || status;
   }

    function formatAiResult(result) {
        if (!result) return '';
        var cls = result === '攻击成功' ? 'success' : ((result === '失败' || result === '攻击失败') ? 'failed' : (result === '尝试' ? 'attempt' : ''));
        if (!cls) return '';
        return '<span class="ai-result-badge ' + cls + '">' + escapeHtml(result) + '</span>';
    }

    function createIcon(name) {
        return '<i data-lucide="' + name + '"></i>';
    }

    function refreshIcons() {
    try {
        if (window.lucide && typeof lucide.createIcons === 'function') {
            lucide.createIcons();
        }
    } catch (e) {
        console.warn('lucide icons failed', e);
    }
}

// ===== 后端 API 交互 =====
function apiGet(path) {
    return fetch(path, { headers: { 'Accept': 'application/json' } }).then(function(r) {
        if (!r.ok) throw new Error(path + ' returned ' + r.status);
        return r.json();
    });
}

function apiPost(path, body) {
    return fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(body || {})
    }).then(function(r) {
        if (!r.ok) throw new Error(path + ' returned ' + r.status);
        return r.json();
    });
}

function apiDelete(path) {
    return fetch(path, { method: 'DELETE', headers: { 'Accept': 'application/json' } }).then(function(r) {
        if (!r.ok) throw new Error(path + ' returned ' + r.status);
        return r.json();
    });
}

function apiPut(path, body) {
    return fetch(path, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(body || {})
    }).then(function(r) {
        if (!r.ok) throw new Error(path + ' returned ' + r.status);
        return r.json();
    });
}

function loadPlatformData() {
    return Promise.all([
        apiGet('/api/alarms'),
        apiGet('/api/blocked'),
        loadWhitelistRules()
    ]).then(function(results) {
        alarmData = results[0] || [];
        blocked = results[1] || [];
        refreshAll();
    }).catch(function(e) {
        console.error('加载平台数据失败', e);
        showToast('加载平台数据失败');
    });
}

function loadWhitelistRules() {
    return apiGet('/api/whitelist').then(function(rules) {
        whitelistRules = rules || [];
    }).catch(function(e) {
        console.error('加载加白规则失败', e);
        whitelistRules = [];
    });
}

window.loadPlatformData = loadPlatformData;

function refreshAll() {
    updateStats();
    renderAlarms();
    renderBlocked();
    renderFalsePositive();
    renderWhitelistRules();
    renderRecentAlarms();
    renderTacticBars();
    renderAttck();
    refreshIcons();
}

function setView(viewId) {
    var assistantView = $('#view-assistant');
    var assistantPanel = $('#assistant-panel');
    var assistantFab = $('#assistant-fab');

    if (viewId === 'assistant') {
        $$('.view').forEach(function(v) { v.classList.remove('active'); });
        if (assistantView && assistantPanel && assistantPanel.parentElement !== assistantView) {
            assistantView.appendChild(assistantPanel);
        }
        if (assistantView) assistantView.classList.add('active');
        if (assistantPanel) assistantPanel.classList.add('open');
        if (assistantFab) assistantFab.classList.add('assistant-page-mode');
        document.body.classList.add('assistant-view-active');
        $$('.nav-item').forEach(function(n) { n.classList.remove('active'); });
        var anav = $('.nav-item[data-view="assistant"]');
        if (anav) anav.classList.add('active');
        $('#page-title').textContent = '安全运营智能助理';
        window.scrollTo(0, 0);
        return;
    }

    // 离开智能助理页面时，将面板移回 body 并恢复悬浮状态
    if (assistantView && assistantView.classList.contains('active')) {
        assistantView.classList.remove('active');
        if (assistantPanel && assistantPanel.parentElement === assistantView) {
            document.body.appendChild(assistantPanel);
        }
        if (assistantPanel) assistantPanel.classList.remove('open');
        if (assistantFab) assistantFab.classList.remove('assistant-page-mode');
        document.body.classList.remove('assistant-view-active');
        if (typeof window.closeAssistantChat === 'function') window.closeAssistantChat();
    }

    $$('.view').forEach(function(v) { v.classList.remove('active'); });
    $('#view-' + viewId).classList.add('active');
    $$('.nav-item').forEach(function(n) { n.classList.remove('active'); });
    var nav = $('.nav-item[data-view="' + viewId + '"]');
    if (nav) nav.classList.add('active');
 var titles = {
     dashboard: '安全运营总览',
      alarms: '告警中心',
      blocking: 'IP 封禁',
      attck: 'ATT&CK 映射',
      falsepositive: '加白告警',
      reports: '报告生成',
      assets: 'Web 资产监测',
      library: '资料库',
      vulns: '漏洞库'
  };
   $('#page-title').textContent = titles[viewId] || '安全运营总览';
   if (viewId === 'library' && typeof window.loadLibraryView === 'function') window.loadLibraryView();
   if (viewId === 'vulns' && typeof window.loadVulnsView === 'function') window.loadVulnsView();
   window.scrollTo(0, 0);
}

window.setView = setView;

$$('.nav-item').forEach(function(btn) {
        btn.addEventListener('click', function() { setView(btn.dataset.view); });
    });

    $$('[data-goto]').forEach(function(btn) {
        btn.addEventListener('click', function() { setView(btn.dataset.goto); });
    });

    function updateStats() {
        var total = alarmData.length;
        var high = alarmData.filter(function(a) { return a.severity === 'critical' || a.severity === 'high'; }).length;
        var fp = alarmData.filter(function(a) { return a.status === 'false_positive'; }).length;
        var blockedCount = blocked.length;
        var openCount = alarmData.filter(function(a) { return a.status === 'open'; }).length;
        $('#stat-total').textContent = total;
        $('#stat-high').textContent = high;
        $('#stat-blocked').textContent = blockedCount;
        $('#stat-fp').textContent = fp;
        $('#rule-active').textContent = blockedCount;
        var badge = $('#nav-alarm-count');
        badge.textContent = openCount;
        badge.style.display = openCount > 0 ? 'inline-flex' : 'none';
    }

    function renderRecentAlarms() {
        var container = $('#recent-alarms');
        var recent = alarmData.filter(function(a) {
            return a.status === 'open' && (a.severity === 'critical' || a.severity === 'high');
        }).slice(0, 5);
        var html = recent.map(function(a) {
            return '<div class="alarm-item ' + a.severity + '">' +
                '<div>' +
                    '<div class="alarm-title">' + escapeHtml(a.name || a.type) + ' ' + (a.aiJudged ? '<span class="ai-badge">AI 研判</span>' : '<span class="rule-badge">规则触发</span>') + '</div>' +
                    '<div class="alarm-meta">' + escapeHtml(a.id) + ' · ' + escapeHtml(a.src) + ' → ' + escapeHtml(a.target) + ' · ' + escapeHtml(a.time) + '</div>' +
                '</div>' +
                '<div class="alarm-actions">' +
                    '<button class="icon-btn" title="封禁 IP" onclick="window.blockAlarmIp(\'' + a.id + '\')"><i data-lucide="shield-ban"></i></button>' +
                    '<button class="icon-btn" title="标记加白" onclick="window.markFpById(\'' + a.id + '\')"><i data-lucide="x-circle"></i></button>' +
                '</div>' +
            '</div>';
        }).join('');
        container.innerHTML = html || '<p class="hint">暂无高危待处置告警</p>';
        refreshIcons();
    }

    function parseAttckIds(raw) {
        if (!raw) return [];
        return raw.split(',').map(function(s) { return s.trim(); }).filter(Boolean).map(function(id) {
            return id.replace(/^TA\d{4}\./, '');
        });
    }

    function attckTactics(a) {
        var tactics = {};
        if (a.attck_info && Array.isArray(a.attck_info.tactics)) {
            a.attck_info.tactics.forEach(function(t) { tactics[t] = true; });
        }
        parseAttckIds(a.attck).forEach(function(id) {
            for (var tactic in tacticGroups) {
                if (tacticGroups[tactic].indexOf(id) !== -1) {
                    tactics[tactic] = true;
                    break;
                }
            }
        });
        return Object.keys(tactics);
    }

    function renderTacticBars() {
        var counts = {};
        alarmData.forEach(function(a) {
            attckTactics(a).forEach(function(tactic) {
                counts[tactic] = (counts[tactic] || 0) + 1;
            });
        });
        var values = Object.keys(counts).map(function(k) { return counts[k]; });
        var max = Math.max.apply(null, values.concat([1]));
        var container = $('#tactic-bars');
        var html = Object.keys(tacticGroups).map(function(tactic) {
            var count = counts[tactic] || 0;
            var pct = Math.round((count / max) * 100);
            return '<div class="tactic-bar">' +
                '<div class="tactic-name">' + escapeHtml(tactic) + '</div>' +
                '<div class="tactic-track"><div class="tactic-fill" style="width: ' + pct + '%"></div></div>' +
                '<div class="tactic-count">' + count + '</div>' +
            '</div>';
        }).join('');
        container.innerHTML = html;
    }

    function filterAlarms() {
        var sev = $('#severity-filter').value;
        var status = $('#status-filter').value;
        var ai = $('#ai-filter').value;
        var q = $('#alarm-search').value.toLowerCase();
        return alarmData.filter(function(a) {
            var matchSev = !sev || a.severity === sev;
            var matchStatus = !status || status.split(',').indexOf(a.status) !== -1;
            var matchAi = !ai || (ai === 'ai' && a.aiJudged) || (ai === 'manual' && !a.aiJudged);
            var normAttck = (a.attck || '').match(/T\d+(?:\.\d+)?$/);
            var fields = [a.id, a.name || a.type, a.type, a.src, a.target, a.attck || '', a.attck_info && a.attck_info.nameZh || '', a.attck_info && a.attck_info.tactics && a.attck_info.tactics.join(' ') || '', normAttck ? normAttck[0] : ''];
            var matchQ = !q || fields.some(function(x) { return String(x).toLowerCase().indexOf(q) !== -1; });
            return matchSev && matchStatus && matchAi && matchQ;
        });
    }

    function renderAlarms() {
        var tbody = $('#alarm-table-body');
        var filtered = filterAlarms();
        var html = filtered.map(function(a) {
            var aiBadge = a.aiJudged ? '<span class="ai-badge" onclick="window.showAiVerdict(\'' + a.id + '\')" title="点击查看完整研判">AI 研判</span>' : '<span class="rule-badge">规则触发</span>';
            var xdrSummary = escapeHtml(a.xdr.device) + ' · ' + escapeHtml(a.xdr.process) + ' · ' + escapeHtml(a.xdr.networkConnection);
            var blockBtn = (a.status !== 'blocked' && a.status !== 'false_positive') ?
                '<button class="btn btn-danger btn-sm" onclick="window.blockAlarmIp(\'' + a.id + '\')">封禁IP</button>' : '';
            var detailBtn = '<button class="btn btn-ghost btn-sm" onclick="window.toggleDetail(\'' + a.id + '\', this)">详情</button>';
            var xdrGrid = Object.keys(a.xdr).filter(function(k) { return a.xdr[k]; }).map(function(k) {
                var labels = { device: '终端/设备', user: '用户账号', process: '进程', parentProcess: '父进程', commandLine: '命令行', filePath: '文件路径', networkConnection: '网络连接' };
                return '<div><span>' + (labels[k] || k) + '</span><b>' + escapeHtml(a.xdr[k]) + '</b></div>';
            }).join('');
            var aiResultCell = a.aiJudged ? (formatAiResult(a.ai_result) || '<span class="ai-result-badge">-</span>') : '<span class="rule-badge">-</span>';

            // Extract original HTTP request/response from the alarm proof evidence
            var proofNode = (a.proof && a.proof.data && a.proof.data.proof) ? a.proof.data.proof : (a.proof || {});
            var httpRequest = '';
            if (proofNode.requestHead) httpRequest += proofNode.requestHead;
            if (proofNode.requestBody) httpRequest += (httpRequest ? '\n\n' : '') + proofNode.requestBody;
            var httpResponse = '';
            if (proofNode.responseHead) httpResponse += proofNode.responseHead;
            if (proofNode.responseBody) httpResponse += (httpResponse ? '\n\n' : '') + proofNode.responseBody;

            var aiDetail = a.aiJudged ? (
                '<div class="ai-detail">' +
                    '<h4>AI 研判结论</h4>' +
                    '<pre class="ai-verdict">' + escapeHtml(a.ai_result || '无') + '</pre>' +
                '</div>'
            ) : '';
            var processDetail = a.aiJudged ? (
                '<div class="ai-detail">' +
                    '<h4>研判过程</h4>' +
                    '<pre class="ai-raw">' + escapeHtml(a.model_response || '无') + '</pre>' +
                '</div>'
            ) : '';
            var reqDetail = (httpRequest) ? (
                '<div class="ai-detail">' +
                    '<h4>请求</h4>' +
                    '<pre>' + escapeHtml(httpRequest) + '</pre>' +
                '</div>'
            ) : '';
            var respDetail = (httpResponse) ? (
                '<div class="ai-detail">' +
                    '<h4>响应</h4>' +
                    '<pre>' + escapeHtml(httpResponse) + '</pre>' +
                '</div>'
            ) : '';
            var attckDetail = formatAttckDetail(a);
            return '<tr>' +
                '<td>' + formatSeverity(a.severity) + '</td>' +
                '<td>' + escapeHtml(a.id) + '</td>' +
                '<td>' + aiBadge + '</td>' +
                '<td>' + aiResultCell + '</td>' +
                '<td>' + escapeHtml(a.name || a.type) + '</td>' +
                '<td>' + formatAttckCell(a.attck, a.attck_info) + '</td>' +
                '<td class="xdr-summary" title="' + escapeHtml(xdrSummary) + '">' + escapeHtml(xdrSummary) + '</td>' +
                '<td>' + escapeHtml(a.src) + '</td>' +
                '<td>' + escapeHtml(a.target) + '</td>' +
                '<td>' + escapeHtml(a.time) + '</td>' +
                '<td>' + formatStatus(a.status) + (a.whitelisted ? '<span class="whitelist-badge" title="' + escapeHtml(a.whitelist_reason || '命中加白规则') + '">已加白</span>' : '') + '</td>' +
                '<td><div class="alarm-actions">' + blockBtn + detailBtn + '</div></td>' +
            '</tr>' +
            '<tr class="detail-row" id="detail-' + a.id + '" style="display:none;">' +
                '<td colspan="12">' +
                    aiDetail +
                    processDetail +
                    reqDetail +
                    respDetail +
                    attckDetail +
                    '<div class="xdr-detail">' +
                        '<h4>XDR 上下文</h4>' +
                        '<div class="xdr-grid">' + xdrGrid + '</div>' +
                    '</div>' +
                '</td>' +
            '</tr>';
        }).join('');
        tbody.innerHTML = html || '<tr><td colspan="12" class="hint" style="text-align:center">无匹配告警</td></tr>';
        refreshIcons();
    }

    window.toggleDetail = function(id, btn) {
        var row = $('#detail-' + id);
        if (!row) return;
        if (row.style.display === 'none') {
            row.style.display = 'table-row';
            if (btn) btn.textContent = '收起';
        } else {
            row.style.display = 'none';
            if (btn) btn.textContent = '详情';
        }
    };

    function renderBlocked() {
        var tbody = $('#blocked-table-body');
        var html = blocked.map(function(b) {
            return '<tr>' +
                '<td>' + escapeHtml(b.ip) + '</td>' +
                '<td>' + escapeHtml(b.reason) + '</td>' +
                '<td>' + escapeHtml(b.time) + '</td>' +
                '<td>' + escapeHtml(b.alarm || '-') + '</td>' +
                '<td><button class="btn btn-text" onclick="window.unblockIp(\'' + b.ip + '\')">解封</button></td>' +
            '</tr>';
        }).join('');
        tbody.innerHTML = html || '<tr><td colspan="5" class="hint" style="text-align:center">暂无封禁 IP</td></tr>';
    }

    window.blockAlarmIp = function(id) {
    var a = alarmData.find(function(x) { return x.id === id; });
    if (!a) return;
    if (blocked.some(function(b) { return b.ip === a.src; })) {
        showToast('IP ' + a.src + ' 已在封禁列表中');
        return;
    }
    apiPost('/api/alarms/' + encodeURIComponent(id) + '/block').then(function(res) {
        if (res.ok === false) throw new Error(res.error || 'block failed');
        alarmData = res.alarm ? alarmData.map(function(x) { return x.id === id ? res.alarm : x; }) : alarmData;
        blocked = res.blocked || blocked;
        refreshAll();
        showToast('已封禁 IP ' + a.src);
    }).catch(function(e) {
        console.error('封禁失败', e);
        showToast('封禁失败：' + e.message);
    });
};

    window.unblockIp = function(ip) {
    apiDelete('/api/blocked/' + encodeURIComponent(ip)).then(function(res) {
        blocked = res.blocked || [];
        return loadPlatformData();
    }).then(function() {
        showToast('已解封 IP ' + ip);
    }).catch(function(e) {
        console.error('解封失败', e);
        showToast('解封失败：' + e.message);
    });
};

    $('#block-btn').addEventListener('click', function() {
    var ip = $('#block-ip-input').value.trim();
    var reason = $('#block-reason-input').value.trim();
    if (!ip || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
        showToast('请输入合法的 IPv4 地址');
        return;
    }
    if (blocked.some(function(b) { return b.ip === ip; })) {
        showToast('该 IP 已被封禁');
        return;
    }
    apiPost('/api/blocked', { ip: ip, reason: reason || '手动封禁' }).then(function(res) {
        $('#block-ip-input').value = '';
        $('#block-reason-input').value = '';
        return loadPlatformData();
    }).then(function() {
        showToast('已封禁 IP ' + ip);
    }).catch(function(e) {
        console.error('封禁失败', e);
        showToast('封禁失败：' + e.message);
    });
});

    $('#export-blocked-btn').addEventListener('click', function() {
        var lines = blocked.map(function(b) { return b.ip + ',' + b.reason + ',' + b.time; }).join('\n');
        var blob = new Blob(['ip,reason,time\n' + lines], { type: 'text/csv' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'blocked_ips.csv';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast('已导出封禁列表');
    });

function renderFalsePositive() {
    var tbody = $('#fp-table-body');
    var candidates = alarmData.filter(function(a) { return a.status !== 'false_positive' && a.status !== 'closed'; });
    var reasonsOptions = falsePositiveReasons.map(function(r) { return '<option value="' + escapeHtml(r) + '">' + escapeHtml(r) + '</option>'; }).join('');
    var html = candidates.map(function(a) {
        return '<tr>' +
            '<td><input type="checkbox" class="fp-check" data-id="' + a.id + '"></td>' +
            '<td>' + formatSeverity(a.severity) + '</td>' +
            '<td>' + escapeHtml(a.id) + '</td>' +
            '<td>' + escapeHtml(a.type) + '</td>' +
            '<td>' + escapeHtml(a.src) + '</td>' +
            '<td>' + escapeHtml(a.time) + '</td>' +
            '<td><select class="fp-reason" data-id="' + a.id + '">' + reasonsOptions + '</select></td>' +
            '<td>' +
                '<button class="btn btn-text" onclick="window.markFpById(\'' + a.id + '\')">标记加白</button>' +
                '<button class="btn btn-text" onclick="window.closeAlarm(\'' + a.id + '\')">关闭</button>' +
            '</td>' +
        '</tr>';
    }).join('');
    tbody.innerHTML = html || '<tr><td colspan="8" class="hint" style="text-align:center">暂无疑似加白告警</td></tr>';
}

function renderWhitelistRules() {
    var tbody = $('#whitelist-rules-body');
    if (!tbody) return;
    var html = whitelistRules.map(function(r) {
        var conds = [];
        if (r.src_ip) conds.push('源 IP: ' + escapeHtml(r.src_ip));
        if (r.dst_ip) conds.push('目的 IP: ' + escapeHtml(r.dst_ip));
        if (r.src_port) conds.push('源端口: ' + escapeHtml(r.src_port));
        if (r.dst_port) conds.push('目的端口: ' + escapeHtml(r.dst_port));
        if (r.name_pattern) conds.push('告警名: ' + escapeHtml(r.name_pattern));
        if (conds.length === 0) conds.push('<span class="hint">任意告警</span>');
        return '<tr>' +
            '<td><input type="checkbox" ' + (r.enabled ? 'checked' : '') + ' onchange="window.toggleWhitelistRule(\'' + r.id + '\', this.checked)"></td>' +
            '<td>' + conds.join('<br>') + '</td>' +
            '<td>' + escapeHtml(r.reason || '-') + '</td>' +
            '<td>' + escapeHtml(r.created_at || '-') + '</td>' +
            '<td>' +
                '<button class="btn btn-text btn-danger" onclick="window.deleteWhitelistRule(\'' + r.id + '\')">删除</button>' +
            '</td>' +
        '</tr>';
    }).join('');
    tbody.innerHTML = html || '<tr><td colspan="5" class="hint" style="text-align:center">暂无加白规则</td></tr>';
}

    window.markFpById = function(id) {
    var a = alarmData.find(function(x) { return x.id === id; });
    if (!a) return;
    var reasonEl = document.querySelector('.fp-reason[data-id="' + id + '"]');
    var reason = reasonEl ? reasonEl.value : '手动标记加白';
    apiPost('/api/alarms/' + encodeURIComponent(id) + '/false_positive', { reason: reason }).then(function(res) {
        if (res.ok === false) throw new Error(res.error || 'mark false positive failed');
        return loadPlatformData();
    }).then(function() {
        showToast('已标记加白: ' + id);
    }).catch(function(e) {
        console.error('标记加白失败', e);
        showToast('标记加白失败：' + e.message);
    });
};

    window.closeAlarm = function(id) {
    apiPost('/api/alarms/' + encodeURIComponent(id) + '/status', { status: 'closed' }).then(function(res) {
        if (res.ok === false) throw new Error(res.error || 'close failed');
        return loadPlatformData();
    }).then(function() {
        showToast('已关闭: ' + id);
    }).catch(function(e) {
        console.error('关闭失败', e);
        showToast('关闭失败：' + e.message);
    });
};

    $('#fp-select-all').addEventListener('change', function(e) {
        $$('.fp-check').forEach(function(cb) { cb.checked = e.target.checked; });
    });

    $('#batch-fp-btn').addEventListener('click', function() {
    var checked = $$('.fp-check:checked');
    if (checked.length === 0) {
        showToast('请先选择要标记的告警');
        return;
    }
    var ids = Array.prototype.map.call(checked, function(cb) { return cb.dataset.id; });
    var reasons = {};
    ids.forEach(function(id) {
        var reasonEl = document.querySelector('.fp-reason[data-id="' + id + '"]');
        reasons[id] = reasonEl ? reasonEl.value : '批量标记加白';
    });
    Promise.all(ids.map(function(id) {
        return apiPost('/api/alarms/' + encodeURIComponent(id) + '/false_positive', { reason: reasons[id] });
    })).then(function() {
        return loadPlatformData();
    }).then(function() {
        showToast('已批量标记 ' + ids.length + ' 条加白告警');
    }).catch(function(e) {
        console.error('批量标记加白失败', e);
        showToast('批量标记加白失败：' + e.message);
    });
});

    function parentColor(pid) {
        var palette = ['#3b82f6','#22c55e','#ef4444','#f59e0b','#a855f7','#ec4899','#14b8a6','#6366f1','#84cc16','#f97316','#06b6d4','#8b5cf6','#d946ef','#10b981','#f43f5e','#0ea5e9','#64748b','#b91c1c','#1d4ed8','#047857'];
        var num = 0;
        for (var i = 0; i < pid.length; i++) num = ((num << 5) - num) + pid.charCodeAt(i);
        return palette[Math.abs(num) % palette.length];
    }

    function renderAttck() {
        var container = $('#attck-matrix');
        var counts = {};
        alarmData.forEach(function(a) {
            if (!a.attck) return;
            var normId = (a.attck.match(/T\d+(?:\.\d+)?$/) || [a.attck])[0];
            counts[normId] = (counts[normId] || 0) + 1;
        });
        var html = Object.keys(tacticGroups).map(function(tactic) {
            var techs = tacticGroups[tactic];
            var groups = {};
            techs.forEach(function(tech) {
                var pid = (parentInfo[tech] && parentInfo[tech].parentId) || tech;
                if (!groups[pid]) groups[pid] = { techs: [], info: parentInfo[tech] };
                groups[pid].techs.push(tech);
            });
            var groupHtml = Object.keys(groups).map(function(pid) {
                var group = groups[pid];
                var color = parentColor(pid);
                var parentLabel = (group.info && group.info.parentNameZh) || pid;
                var isLeaf = group.techs.length === 1 && group.techs[0] === pid;
                var parentHtml = '';
                if (!isLeaf) {
                    parentHtml = '<div class="attck-parent" style="border-left-color:' + color + '">' + escapeHtml(parentLabel) + '</div>';
                }
                var childTechs = group.techs.filter(function(tech) { return tech !== pid; });
                if (childTechs.length === 0) childTechs = group.techs.slice();
                var itemsHtml = childTechs.map(function(tech) {
                    var count = counts[tech] || 0;
                    var name = escapeHtml(techniqueNames[tech] || tech);
                    var countHtml = count ? '<span class="count">' + count + '</span>' : '';
                    var leafStyle = isLeaf ? 'border-left-color:' + color : '';
                    var alarmClass = count ? ' has-alarms' : '';
                    return '<div class="attck-technique' + alarmClass + '" data-tech="' + escapeHtml(tech) + '" style="' + leafStyle + '" onclick="window.filterByTech(\'' + tech + '\')">' +
                        '<span>' + escapeHtml(tech) + ' ' + name + '</span>' + countHtml +
                    '</div>';
                }).join('');
                return parentHtml + itemsHtml;
            }).join('');
            if (techs.length === 0) {
                groupHtml = '<div class="attck-technique" style="opacity:.5;cursor:default"><span>暂无映射</span></div>';
            }
            return '<div class="attck-tactic">' +
                '<h3>' + escapeHtml(tactic) + '</h3>' + groupHtml +
            '</div>';
        }).join('');
        container.innerHTML = html;
    }

    window.filterByTech = function(tech) {
        var normId = (tech.match(/T\d+(?:\.\d+)?$/) || [tech])[0];
        setView('alarms');
        $('#alarm-search').value = normId;
        renderAlarms();
        showToast('已按技术 ' + tech + ' 过滤告警');
    };

    function formatAttckCell(attck, info) {
        if (!attck) return '<span class="hint">-</span>';
        var normId = (attck.match(/T\d+(?:\.\d+)?$/) || [attck])[0];
        var lookupInfo = info || _attackTechniques[normId];
        var label = (lookupInfo && lookupInfo.nameZh) || techniqueNames[normId] || (lookupInfo && lookupInfo.name) || attck;
        var tactics = (lookupInfo && lookupInfo.tactics) || [];
        var tacticTip = tactics.length ? '所属战术：' + tactics.join(' / ') : '暂无战术映射';
        return '<a class="attck-cell" href="javascript:void(0)" onclick="window.showTechInMatrix(\'' + escapeHtml(normId) + '\')" title="' + escapeHtml(tacticTip) + '">' +
            '<span class="attck-id">' + escapeHtml(attck) + '</span>' +
            '<span class="attck-name">' + escapeHtml(label) + '</span>' +
        '</a>';
    }

    function formatAttckDetail(a) {
        var attck = a.attck;
        var info = a.attck_info;
        if (!attck) {
            return '<div class="ai-detail"><h4>ATT&amp;CK 映射</h4><p class="hint">未映射到 ATT&amp;CK 技术</p></div>';
        }
        var normId = (attck.match(/T\d+(?:\.\d+)?$/) || [attck])[0];
        var lookupInfo = info || _attackTechniques[normId];
        var label = (lookupInfo && lookupInfo.nameZh) || techniqueNames[normId] || (lookupInfo && lookupInfo.name) || attck;
        var tactics = (lookupInfo && lookupInfo.tactics) || [];
        var tacticTags = tactics.map(function(t) { return '<span class="attck-tag">' + escapeHtml(t) + '</span>'; }).join('') || '<span class="hint">暂无战术映射</span>';
        var parentHtml = '';
        if (info && info.parentId && info.parentId !== attck) {
            parentHtml = '<div><span>父技术</span><b>' + escapeHtml(info.parentId) + ' ' + escapeHtml(info.parentNameZh || info.parentName || '') + '</b></div>';
        }
        return '<div class="ai-detail">' +
            '<h4>ATT&amp;CK 映射 <a class="attck-link" href="javascript:void(0)" onclick="window.showTechInMatrix(\'' + escapeHtml(normId) + '\')">查看矩阵 <i data-lucide="external-link"></i></a></h4>' +
            '<div class="xdr-grid">' +
            '<div><span>技术 ID</span><b>' + escapeHtml(attck) + '</b></div>' +
            '<div><span>中文名</span><b>' + escapeHtml(label) + '</b></div>' +
            (info && info.name ? '<div><span>英文名</span><b>' + escapeHtml(info.name) + '</b></div>' : '') +
            '<div><span>所属战术</span><b>' + tacticTags + '</b></div>' +
            '<div><span>技术类型</span><b>' + (lookupInfo && lookupInfo.parentId && lookupInfo.parentId !== lookupInfo.id ? '子技术' : '技术') + '</b></div>' +
            parentHtml +
            '</div>' +
        '</div>';
    }

    window.showTechInMatrix = function(tech) {
        if (!tech) return;
        var normId = (tech.match(/T\d+(?:\.\d+)?$/) || [tech])[0];
        setView('attck');
        $('#tactic-filter').value = '';
        $$('.attck-tactic').forEach(function(el) { el.style.display = 'block'; });
        $('#attck-search').value = normId;
        var event = new Event('input', { bubbles: true });
        $('#attck-search').dispatchEvent(event);
        $$('.attck-technique').forEach(function(el) {
            el.classList.remove('attck-highlight');
            if (el.dataset.tech === normId) {
                el.classList.add('attck-highlight');
                el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        });
    };

    var tacticFilter = $('#tactic-filter');
    Object.keys(tacticGroups).forEach(function(t) {
        var opt = document.createElement('option');
        opt.value = t;
        opt.textContent = t;
        tacticFilter.appendChild(opt);
    });

    $('#tactic-filter').addEventListener('change', function() {
        var val = $('#tactic-filter').value;
        $$('.attck-tactic').forEach(function(el) {
            var title = el.querySelector('h3').textContent;
            el.style.display = (!val || title === val) ? 'block' : 'none';
        });
    });

    $('#attck-search').addEventListener('input', function(e) {
        var q = e.target.value.toLowerCase();
        $$('.attck-technique').forEach(function(el) {
            el.style.display = el.textContent.toLowerCase().indexOf(q) !== -1 ? 'flex' : 'none';
        });
    });

    function rangeLabel(range) {
        var map = { day: '今日', week: '本周', month: '本月' };
        return map[range] || range;
    }

    function topTechniques() {
        var counts = {};
        alarmData.forEach(function(a) {
            parseAttckIds(a.attck).forEach(function(id) {
                counts[id] = (counts[id] || 0) + 1;
            });
        });
        var sorted = Object.keys(counts).map(function(k) { return [k, counts[k]]; }).sort(function(a, b) { return b[1] - a[1]; }).slice(0, 5);
        return sorted.map(function(item) {
            return '- ' + item[0] + ' ' + (techniqueNames[item[0]] || item[0]) + ': ' + item[1] + ' 次';
        }).join('\n') || '- 无';
    }

    function generateReport() {
        var range = $('#report-range').value;
        var template = $('#report-template').value;
        var total = alarmData.length;
        var critical = alarmData.filter(function(a) { return a.severity === 'critical'; }).length;
        var high = alarmData.filter(function(a) { return a.severity === 'high'; }).length;
        var open = alarmData.filter(function(a) { return a.status === 'open'; }).length;
        var fp = alarmData.filter(function(a) { return a.status === 'false_positive'; }).length;
        var blockedCount = blocked.length;
        var text = '';
        if (template === 'executive') {
            text = '【高管摘要】安全运营报告\n周期：' + rangeLabel(range) + '\n\n核心指标：\n- 告警总数：' + total +
                '\n- 高危/严重告警：' + (critical + high) + '\n- 待处置告警：' + open + '\n- 已封禁 IP：' + blockedCount + '\n- 加白告警：' + fp +
                '\n\n关键风险：\n' + (critical > 0 ? '1. 检测到严重级别告警，建议立即启动应急响应。\n' : '1. 当前无严重级别告警，整体态势平稳。\n') +
                '2. 已封禁 ' + blockedCount + ' 个恶意 IP，防火墙策略生效中。\n\n下一步行动：\n- 清零高危待处置告警\n- 复盘加白规则，降低噪声';
        } else if (template === 'operational') {
            var lines = alarmData.map(function(a) {
                return '- [' + a.severity.toUpperCase() + '] ' + a.id + ' ' + a.type + ' | ' + a.src + ' → ' + a.target + ' | ' + a.status;
            }).join('\n');
            text = '【运营日报】\n周期：' + rangeLabel(range) + '\n\n告警明细：\n' + lines +
                '\n\n处置动作：\n- 封禁 IP：' + blockedCount + '\n- 标记加白：' + fp + '\n- 关闭告警：' + alarmData.filter(function(a) { return a.status === 'closed'; }).length;
        } else {
            var tacticCounts = {};
            alarmData.forEach(function(a) {
                attckTactics(a).forEach(function(tactic) {
                    tacticCounts[tactic] = (tacticCounts[tactic] || 0) + 1;
                });
            });
            var attckSummary = Object.keys(tacticGroups).map(function(tactic) {
                var cnt = tacticCounts[tactic] || 0;
                return cnt ? '- ' + tactic + ': ' + cnt : '';
            }).filter(function(s) { return s; }).join('\n');
            text = '【ATT&CK 复盘】\n周期：' + rangeLabel(range) + '\n\n战术分布：\n' + (attckSummary || '- 暂无映射数据') + '\n\n高频技术：\n' + topTechniques();
        }
        $('#report-content').textContent = text;
        $('#report-preview-panel').style.display = 'block';
        showToast('报告生成完成');
    }

    $('#generate-report-btn').addEventListener('click', generateReport);
    $('#copy-report-btn').addEventListener('click', function() {
        var content = $('#report-content').textContent;
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(content).then(function() { showToast('报告已复制'); });
            } else {
                var ta = document.createElement('textarea');
                ta.value = content;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
                showToast('报告已复制');
            }
        } catch (err) {
            showToast('复制失败');
        }
    });

    // ===== Web 资产监测（纯前端模拟） =====
    var assets = [];
    var selectedAssetId = null;
    var ASSETS_KEY = 'secops_assets';

    function loadAssets() {
        try {
            var stored = localStorage.getItem(ASSETS_KEY);
            assets = stored ? JSON.parse(stored) : getDefaultAssets();
        } catch (e) {
            assets = getDefaultAssets();
        }
        assets.forEach(function(asset) {
            if (typeof asset.business_status_code !== 'number') {
                asset.business_status_code = asset.expected_status || 200;
            }
            if (typeof asset.waf_status_code !== 'number') {
                asset.waf_status_code = 200;
            }
            if (!asset.business_status) {
                asset.business_status = asset.status || 'unknown';
            }
            if (!asset.waf_status) {
                asset.waf_status = 'unknown';
            }
        });
        renderAssets();
        updateAssetStats();
    }

    function saveAssets() {
        try {
            localStorage.setItem(ASSETS_KEY, JSON.stringify(assets));
        } catch (e) { /* ignore */ }
    }

    function getDefaultAssets() {
        // 新余学院各二级学院示例资产，附带初始探测数据便于大屏展示
        var presets = [
            { name: '新余学院官网', url: 'https://www.xyc.edu.cn', business_http_status: 200, waf_http_status: 403, response_time_ms: 128, ssl_days_left: 62, waf_detected: ['waf'] },
            { name: '文学与传媒学院', url: 'https://wxy.xyc.edu.cn', business_http_status: 200, waf_http_status: 403, response_time_ms: 156, ssl_days_left: 58, waf_detected: ['waf'] },
            { name: '外国语学院', url: 'https://wgy.xyc.edu.cn', business_http_status: 200, waf_http_status: 403, response_time_ms: 142, ssl_days_left: 71, waf_detected: ['waf'] },
            { name: '经济与管理学院', url: 'https://jjxy.xyc.edu.cn', business_http_status: 200, waf_http_status: 403, response_time_ms: 98, ssl_days_left: 45, waf_detected: ['waf'] },
            { name: '机电工程学院', url: 'https://jdxy.xyc.edu.cn', business_http_status: 200, waf_http_status: 403, response_time_ms: 187, ssl_days_left: 52, waf_detected: ['waf'] },
            { name: '数学与计算机学院', url: 'https://sxxy.xyc.edu.cn', business_http_status: 200, waf_http_status: 200, response_time_ms: 210, ssl_days_left: 39, waf_detected: [] },
            { name: '新能源科学与工程学院', url: 'https://xny.xyc.edu.cn', business_http_status: 503, waf_http_status: 403, response_time_ms: 2450, ssl_days_left: 33, waf_detected: ['waf'] },
            { name: '建筑工程学院', url: 'https://jzxy.xyc.edu.cn', business_http_status: 200, waf_http_status: 403, response_time_ms: 134, ssl_days_left: 66, waf_detected: ['waf'] },
            { name: '医学院', url: 'https://yxy.xyc.edu.cn', business_http_status: 200, waf_http_status: 403, response_time_ms: 119, ssl_days_left: 28, waf_detected: ['waf'] },
            { name: '艺术学院', url: 'https://ysxy.xyc.edu.cn', business_http_status: 200, waf_http_status: 403, response_time_ms: 167, ssl_days_left: 54, waf_detected: ['waf'] },
            { name: '体育学院', url: 'https://tyxy.xyc.edu.cn', business_http_status: 200, waf_http_status: 403, response_time_ms: 145, ssl_days_left: 14, waf_detected: ['waf'] },
            { name: '马克思主义学院', url: 'https://marx.xyc.edu.cn', business_http_status: 200, waf_http_status: 403, response_time_ms: 132, ssl_days_left: 88, waf_detected: ['waf'] },
            { name: '国际教育学院', url: 'https://gjjy.xyc.edu.cn', business_http_status: 200, waf_http_status: 403, response_time_ms: 121, ssl_days_left: 95, waf_detected: ['waf'] },
            { name: '护理与康复学院', url: 'https://hlxy.xyc.edu.cn', business_http_status: 200, waf_http_status: 200, response_time_ms: 198, ssl_days_left: 21, waf_detected: [] }
        ];
        var time = nowStr();
        return presets.map(function(item, idx) {
            var num = idx + 1;
            var idSuffix = num < 10 ? '00' + num : (num < 100 ? '0' + num : num);
            var business_status = item.business_http_status === 200 ? 'normal' : 'abnormal';
            var waf_status = item.waf_http_status === 403 ? 'normal' : 'abnormal';
            var message = '业务 HTTP ' + item.business_http_status + ' / WAF HTTP ' + item.waf_http_status + ' / 响应 ' + item.response_time_ms + 'ms';
            var record = {
                time: time,
                business_status: business_status,
                business_http_status: item.business_http_status,
                waf_status: waf_status,
                waf_http_status: item.waf_http_status,
                response_time_ms: item.response_time_ms,
                ssl_days_left: item.ssl_days_left,
                message: message,
                waf_detected: item.waf_detected
            };
            return {
                id: 'AST-XYC-' + idSuffix,
                name: item.name,
                url: item.url,
                business_status_code: 200,
                waf_status_code: 200,
                expected_status: 200,
                expected_waf: true,
                enabled: true,
                created_at: time,
                last_check: time,
                business_status: business_status,
                waf_status: waf_status,
                status: business_status,
                http_status: item.business_http_status,
                business_http_status: item.business_http_status,
                waf_http_status: item.waf_http_status,
                response_time_ms: item.response_time_ms,
                waf_detected: item.waf_detected,
                ssl_days_left: item.ssl_days_left,
                message: message,
                history: [record]
            };
        });
    }

    function probeAsset(asset) {
        return apiPost('/api/assets/probe', {
            url: asset.url,
            expected_status: asset.expected_status || asset.business_status_code || 200,
            expected_waf: asset.expected_waf !== false,
            waf_status_code: asset.waf_status_code || 200
        }).then(function(res) {
            if (res.ok && res.result) {
                return res.result;
            }
            throw new Error(res.error || '探测失败');
        }).catch(function(err) {
            console.error('探测请求失败', err);
            return {
                time: nowStr(),
                business_status: 'unknown',
                business_http_status: null,
                waf_status: 'unknown',
                waf_http_status: null,
                response_time_ms: null,
                ssl_days_left: null,
                message: '探测失败：' + (err.message || '网络错误')
            };
        });
    }

    function refreshAssetState(asset, result) {
        asset.last_check = result.time;
        asset.business_status = result.business_status;
        asset.business_http_status = result.business_http_status;
        asset.waf_status = result.waf_status;
        asset.waf_http_status = result.waf_http_status;
        asset.response_time_ms = result.response_time_ms;
        asset.ssl_days_left = result.ssl_days_left;
        asset.message = result.message;
        asset.status = result.business_status;
        asset.http_status = result.business_http_status;
        var history = asset.history || [];
        history.unshift(result);
        if (history.length > 20) history = history.slice(0, 20);
        asset.history = history;
    }

    function updateAssetStats() {
        var total = assets.length;
        var businessNormal = assets.filter(function(a) { return a.business_status === 'normal'; }).length;
        var wafNormal = assets.filter(function(a) { return a.waf_status === 'normal'; }).length;
        var issue = assets.filter(function(a) {
            return a.business_status === 'abnormal' || a.waf_status === 'abnormal';
        }).length;
        $('#stat-asset-total').textContent = total;
        $('#stat-asset-healthy').textContent = businessNormal;
        $('#stat-asset-waf').textContent = wafNormal;
        $('#stat-asset-issue').textContent = issue;
        var badge = $('#nav-asset-count');
        badge.textContent = issue;
        badge.style.display = issue > 0 ? 'inline-flex' : 'none';
        renderDashAssets();
        renderDashAssetAlerts();
    }

    function renderDashAssets() {
        var grid = $('#dash-asset-grid');
        var healthyEl = $('#dash-asset-healthy');
        var issueEl = $('#dash-asset-issue');
        if (!grid) return;
        var healthy = 0, issue = 0;
        assets.forEach(function(a) {
            if (a.business_status === 'normal' && a.waf_status === 'normal') healthy++;
            else issue++;
        });
        if (healthyEl) healthyEl.textContent = healthy;
        if (issueEl) issueEl.textContent = issue;

        function metricClass(val, threshold, invert) {
            if (val === null || val === undefined) return '';
            if (invert) {
                if (val >= threshold) return 'danger';
                if (val >= threshold / 2) return 'warning';
            } else {
                if (val <= 0) return 'danger';
                if (val <= threshold) return 'warning';
            }
            return 'success';
        }

        var html = assets.map(function(a) {
            var isIssue = a.business_status !== 'normal' || a.waf_status !== 'normal';
            var statusText = isIssue ? '异常' : '正常';
            var statusClass = isIssue ? 'abnormal' : 'normal';
            var displayUrl = a.url.replace(/^https?:\/\//, '').replace(/\/$/, '');
            var response = typeof a.response_time_ms === 'number' ? a.response_time_ms : null;
            var ssl = typeof a.ssl_days_left === 'number' ? a.ssl_days_left : null;
            var responseClass = metricClass(response, 1000, true);
            var sslClass = ssl === null ? '' : (ssl <= 14 ? 'warning' : (ssl <= 0 ? 'danger' : 'success'));
            var businessClass = a.business_status === 'normal' ? 'success' : (a.business_status === 'abnormal' ? 'danger' : '');
            var wafClass = a.waf_status === 'normal' ? 'success' : (a.waf_status === 'abnormal' ? 'danger' : '');
            return '<div class="asset-dash-card ' + (isIssue ? 'issue' : '') + '" data-asset-id="' + escapeHtml(a.id) + '">' +
                '<div class="asset-dash-header">' +
                    '<div>' +
                        '<div class="asset-dash-name">' + escapeHtml(a.name) + '</div>' +
                        '<div class="asset-dash-url">' + escapeHtml(displayUrl) + '</div>' +
                    '</div>' +
                    '<span class="asset-status-indicator ' + statusClass + '">' + statusText + '</span>' +
                '</div>' +
                '<div class="asset-dash-status-row">' +
                    '<span class="asset-dash-metric ' + businessClass + '"><i data-lucide="activity"></i>业务 ' + (a.business_http_status || a.http_status || '-') + '</span>' +
                    '<span class="asset-dash-metric ' + wafClass + '"><i data-lucide="shield"></i>WAF ' + (a.waf_http_status || '-') + '</span>' +
                    '<span class="asset-dash-metric ' + responseClass + '"><i data-lucide="clock"></i>' + (response === null ? '-' : response + 'ms') + '</span>' +
                    '<span class="asset-dash-metric ' + sslClass + '"><i data-lucide="lock"></i>SSL ' + (ssl === null ? '-' : ssl + '天') + '</span>' +
                '</div>' +
            '</div>';
        }).join('');

        grid.innerHTML = html || '<p class="hint" style="padding:32px 0;text-align:center;">暂无监测资产，前往 Web 资产页添加。</p>';
        refreshIcons();

        grid.querySelectorAll('.asset-dash-card').forEach(function(card) {
            card.addEventListener('click', function() {
                var id = card.getAttribute('data-asset-id');
                setView('assets');
                if (id) {
                    setTimeout(function() {
                        selectedAssetId = id;
                        renderAssets();
                        var detail = $('#asset-detail-panel');
                        if (detail) detail.style.display = 'block';
                    }, 50);
                }
            });
        });
    }

    function renderDashAssetAlerts() {
        var container = $('#dash-asset-alerts');
        var countEl = $('#dash-asset-alert-count');
        if (!container) return;
        var alerts = [];
        assets.forEach(function(a) {
            var displayUrl = a.url.replace(/^https?:\/\//, '').replace(/\/$/, '');
            if (a.business_status === 'abnormal') {
                alerts.push({
                    id: a.id,
                    name: a.name,
                    url: displayUrl,
                    icon: 'activity',
                    severity: 'critical',
                    severityText: '严重',
                    title: '业务访问异常',
                    desc: '业务 HTTP 状态 ' + (a.business_http_status || '-') + '，响应 ' + (a.response_time_ms || '-') + 'ms',
                    time: a.last_check || a.created_at || '-'
                });
            }
            if (a.waf_status === 'abnormal') {
                alerts.push({
                    id: a.id,
                    name: a.name,
                    url: displayUrl,
                    icon: 'shield-alert',
                    severity: 'high',
                    severityText: '高危',
                    title: 'WAF 防护失效',
                    desc: 'SQL 注入探测未被拦截，WAF HTTP ' + (a.waf_http_status || '-'),
                    time: a.last_check || a.created_at || '-'
                });
            }
            var ssl = typeof a.ssl_days_left === 'number' ? a.ssl_days_left : null;
            if (ssl !== null && ssl <= 14) {
                alerts.push({
                    id: a.id,
                    name: a.name,
                    url: displayUrl,
                    icon: 'lock',
                    severity: ssl <= 7 ? 'high' : 'warning',
                    severityText: ssl <= 7 ? '高危' : '警告',
                    title: 'SSL 证书即将过期',
                    desc: '剩余有效期 ' + ssl + ' 天，建议尽快续期',
                    time: a.last_check || a.created_at || '-'
                });
            }
        });
        if (countEl) countEl.textContent = alerts.length;
        if (alerts.length === 0) {
            container.innerHTML = '<div class="asset-alert-empty"><i data-lucide="check-circle-2"></i><span>暂无 Web 资产告警</span></div>';
            refreshIcons();
            return;
        }
        var html = alerts.slice(0, 8).map(function(a) {
            return '<div class="asset-alert-card ' + a.severity + '" data-asset-id="' + escapeHtml(a.id) + '">' +
                '<div class="asset-alert-icon"><i data-lucide="' + a.icon + '"></i></div>' +
                '<div class="asset-alert-body">' +
                    '<div class="asset-alert-top">' +
                        '<span class="asset-alert-severity ' + a.severity + '">' + a.severityText + '</span>' +
                        '<span class="asset-alert-time">' + escapeHtml(a.time) + '</span>' +
                    '</div>' +
                    '<div class="asset-alert-title">' + escapeHtml(a.title) + '</div>' +
                    '<div class="asset-alert-asset">' + escapeHtml(a.name) + ' <span class="asset-alert-url">' + escapeHtml(a.url) + '</span></div>' +
                    '<div class="asset-alert-desc">' + escapeHtml(a.desc) + '</div>' +
                '</div>' +
            '</div>';
        }).join('');
        container.innerHTML = html;
        refreshIcons();
        container.querySelectorAll('.asset-alert-card').forEach(function(card) {
            card.addEventListener('click', function() {
                var id = card.getAttribute('data-asset-id');
                setView('assets');
                if (id) {
                    setTimeout(function() {
                        selectedAssetId = id;
                        renderAssets();
                        var detail = $('#asset-detail-panel');
                        if (detail) detail.style.display = 'block';
                    }, 50);
                }
            });
        });
    }

    function formatAssetStatus(status) {
        var map = { normal: '正常', abnormal: '异常', unknown: '未探测' };
        return '<span class="asset-status ' + status + '"><span class="status-pill-dot"></span>' + (map[status] || status) + '</span>';
    }

    function formatWafStatus(status) {
        var map = { normal: '正常', abnormal: '异常', unknown: '未探测' };
        return '<span class="waf-status ' + status + '"><span class="status-pill-dot"></span>' + (map[status] || status) + '</span>';
    }

    function formatWafVendors(vendors) {
        if (!vendors || vendors.length === 0) return '-';
        return vendors.join(', ');
    }

    function formatSslDays(days) {
        if (days === null || days === undefined) return '-';
        if (days < 0) return '<span style="color:var(--danger-2)">已过期</span>';
        if (days < 14) return '<span style="color:var(--warning)">' + days + ' 天</span>';
        return days + ' 天';
    }

    function renderAssets() {
        var tbody = $('#asset-table-body');
        var q = $('#asset-search').value.toLowerCase();
        var filtered = assets.filter(function(a) {
            return !q || (a.name + ' ' + a.url).toLowerCase().indexOf(q) !== -1;
        });
        var html = filtered.map(function(a) {
            return '<tr>' +
                '<td>' + escapeHtml(a.name) + '</td>' +
                '<td><a href="' + escapeHtml(normalizeUrl(a.url)) + '" target="_blank" rel="noopener" class="asset-link">' + escapeHtml(a.url) + '</a></td>' +
                '<td>' + formatAssetStatus(a.business_status || 'unknown') + '<div class="hint" style="margin:0;font-size:11px;">HTTP ' + (a.business_http_status !== null && a.business_http_status !== undefined ? a.business_http_status : '-') + '</div></td>' +
                '<td>' + formatWafStatus(a.waf_status || 'unknown') + '<div class="hint" style="margin:0;font-size:11px;">HTTP ' + (a.waf_http_status !== null && a.waf_http_status !== undefined ? a.waf_http_status : '-') + '</div></td>' +
                '<td>' +
                    '<div class="asset-actions">' +
                        '<button class="btn btn-ghost btn-sm" onclick="window.checkAsset(\'' + a.id + '\')">探测</button>' +
                        '<button class="btn btn-text" onclick="window.showAssetHistory(\'' + a.id + '\')">历史</button>' +
                        '<button class="btn btn-text" onclick="window.deleteAsset(\'' + a.id + '\')">删除</button>' +
                    '</div>' +
                '</td>' +
            '</tr>';
        }).join('');
        tbody.innerHTML = html || '<tr><td colspan="5" class="hint" style="text-align:center">暂无监测资产</td></tr>';
        refreshIcons();
    }

    function normalizeUrl(url) {
        url = (url || '').trim();
        if (!url) return '#';
        if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
        return url;
    }

    function addAsset() {
        var name = $('#asset-name').value.trim();
        var url = $('#asset-url').value.trim();
        var businessStatusCode = parseInt($('#asset-business-status-code').value, 10) || 200;
        var wafStatusCode = parseInt($('#asset-waf-status-code').value, 10) || 200;
        if (!name || !url) {
            showToast('请输入资产名称和 URL');
            return;
        }
        var newAsset = {
            id: 'AST-' + Date.now(),
            name: name,
            url: url,
            business_status_code: businessStatusCode,
            waf_status_code: wafStatusCode,
            expected_status: businessStatusCode,
            expected_waf: true,
            enabled: true,
            created_at: nowStr(),
            last_check: null,
            business_status: 'unknown',
            business_http_status: null,
            waf_status: 'unknown',
            waf_http_status: null,
            status: 'unknown',
            http_status: null,
            response_time_ms: null,
            waf_detected: [],
            ssl_days_left: null,
            message: '',
            history: []
        };
        assets.push(newAsset);
        saveAssets();
        $('#asset-name').value = '';
        $('#asset-url').value = '';
        renderAssets();
        updateAssetStats();
        showToast('资产已添加');
    }

    $('#add-asset-btn').addEventListener('click', addAsset);
    $('#asset-search').addEventListener('input', renderAssets);

    $('#check-all-assets-btn').addEventListener('click', function() {
        var enabledAssets = assets.filter(function(a) { return a.enabled; });
        if (enabledAssets.length === 0) {
            showToast('没有启用的资产');
            return;
        }
        showToast('正在批量探测 ' + enabledAssets.length + ' 个资产...');
        apiPost('/api/assets/batch-probe', { assets: enabledAssets }).then(function(res) {
            if (res.ok && Array.isArray(res.results)) {
                res.results.forEach(function(r) {
                    var asset = assets.find(function(a) { return a.id === r.id; });
                    if (asset) refreshAssetState(asset, r);
                });
                saveAssets();
                renderAssets();
                updateAssetStats();
                showToast('批量探测完成');
            } else {
                throw new Error(res.error || '批量探测失败');
            }
        }).catch(function(err) {
            console.error('批量探测失败', err);
            showToast('批量探测失败：' + (err.message || '网络错误'));
        });
    });

    window.checkAsset = function(id) {
        var asset = assets.find(function(a) { return a.id === id; });
        if (!asset) return;
        showToast('正在探测...');
        probeAsset(asset).then(function(result) {
            refreshAssetState(asset, result);
            saveAssets();
            renderAssets();
            updateAssetStats();
            showToast('探测完成: ' + (asset.status || 'unknown'));
            if (selectedAssetId === id) showAssetHistory(id);
        });
    };

    window.deleteAsset = function(id) {
        if (!confirm('确定删除该资产？')) return;
        assets = assets.filter(function(a) { return a.id !== id; });
        saveAssets();
        renderAssets();
        updateAssetStats();
        if (selectedAssetId === id) {
            $('#asset-detail-panel').style.display = 'none';
            selectedAssetId = null;
        }
        showToast('资产已删除');
    };

    window.showAssetHistory = function(id) {
        selectedAssetId = id;
        var asset = assets.find(function(a) { return a.id === id; });
        if (!asset) return;
        $('#asset-detail-panel').style.display = 'block';
        $('#asset-detail-title').textContent = escapeHtml(asset.name) + ' · 探测历史';
        renderAssetHistory(asset.history || []);
    };

    function renderAssetHistory(history) {
        var container = $('#asset-detail-content');
        if (!history || history.length === 0) {
            container.innerHTML = '<p class="history-empty">暂无探测历史</p>';
            return;
        }
        var maxMs = Math.max.apply(null, history.map(function(h) { return h.response_time_ms || 0; }).concat([1]));
        var html = '<div class="history-list">';
        html += history.map(function(h) {
            var pct = Math.min(100, Math.round(((h.response_time_ms || 0) / maxMs) * 100));
            var fillClass = pct > 80 ? 'very-slow' : (pct > 50 ? 'slow' : '');
            return '<div class="history-item">' +
                '<span class="time">' + escapeHtml(h.time) + '</span>' +
                '<div class="meta">' +
                    formatAssetStatus(h.business_status || h.status || 'unknown') +
                    '<span>业务 HTTP ' + (h.business_http_status || h.http_status || '-') + '</span>' +
                    '<span>WAF HTTP ' + (h.waf_http_status || '-') + '</span>' +
                '</div>' +
                '<div class="response-bar">' +
                    '<div class="track"><div class="fill ' + fillClass + '" style="width:' + pct + '%"></div></div>' +
                '<span>' + (h.response_time_ms !== null && h.response_time_ms !== undefined ? h.response_time_ms + 'ms' : '-') + '</span>' +
                '</div>' +
            '</div>';
        }).join('');
        html += '</div>';
        container.innerHTML = html;
    }

    var originalSetView = setView;
    setView = function(viewId) {
        originalSetView(viewId);
        if (viewId === 'assets') loadAssets();
    };
    function nowStr() {
        var d = new Date();
        function pad(n) { return n < 10 ? '0' + n : '' + n; }
        return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
            pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    }

    $('#alarm-search').addEventListener('input', renderAlarms);
    $('#severity-filter').addEventListener('change', renderAlarms);
    $('#status-filter').addEventListener('change', renderAlarms);
    $('#ai-filter').addEventListener('change', renderAlarms);
    $('#fp-search').addEventListener('input', function(e) {
        var q = e.target.value.toLowerCase();
        $$('#fp-table-body tr').forEach(function(tr) {
            tr.style.display = tr.textContent.toLowerCase().indexOf(q) !== -1 ? '' : 'none';
        });
    });
    $('#refresh-btn').addEventListener('click', function() {
        showToast('数据已刷新');
        loadPlatformData();
        loadAssets();
    });

    // 后端每 60 秒拉取一次 XDR 告警，前端每 30 秒自动同步展示
    setInterval(function() { loadPlatformData(); }, 30000);

    $('#wl-create-btn').addEventListener('click', function() {
        var rule = {
            src_ip: $('#wl-src-ip').value.trim(),
            dst_ip: $('#wl-dst-ip').value.trim(),
            src_port: $('#wl-src-port').value.trim(),
            dst_port: $('#wl-dst-port').value.trim(),
            name_pattern: $('#wl-name').value.trim(),
            reason: $('#wl-reason').value.trim() || '手动添加'
        };
        if (!rule.src_ip && !rule.dst_ip && !rule.src_port && !rule.dst_port && !rule.name_pattern) {
            showToast('请至少填写一个匹配条件');
            return;
        }
        apiPost('/api/whitelist', rule).then(function(res) {
            if (res.ok === false) throw new Error(res.error || '创建失败');
            return loadPlatformData();
        }).then(function() {
            showToast('加白规则已创建');
            $('#wl-src-ip').value = '';
            $('#wl-dst-ip').value = '';
            $('#wl-src-port').value = '';
            $('#wl-dst-port').value = '';
            $('#wl-name').value = '';
            $('#wl-reason').value = '';
        }).catch(function(e) {
            console.error('创建加白规则失败', e);
            showToast('创建加白规则失败：' + e.message);
        });
    });


    // AI 研判悬浮弹窗（位于 IIFE 内部，可访问 alarmData）
    window.showAiVerdict = function(id) {
        var a = alarmData.find(function(x) { return x.id === id; });
        if (!a) return;
        var reqEl = document.getElementById('ai-verdict-request');
        var textEl = document.getElementById('ai-verdict-text');
        var respEl = document.getElementById('ai-verdict-response');
        var reqSection = document.getElementById('ai-verdict-request-section');
        var requestText = '';
        if (a.request_json) {
            try {
                requestText = typeof a.request_json === 'string' ? JSON.stringify(JSON.parse(a.request_json), null, 2) : JSON.stringify(a.request_json, null, 2);
            } catch (err) {
                requestText = String(a.request_json);
            }
        } else if (a.request) {
            try {
                requestText = typeof a.request === 'string' ? JSON.stringify(JSON.parse(a.request), null, 2) : JSON.stringify(a.request, null, 2);
            } catch (err) {
                requestText = String(a.request);
            }
        }
        if (reqEl) reqEl.textContent = requestText || '无请求数据';
        if (reqSection) reqSection.style.display = requestText ? '' : 'none';
        if (textEl) textEl.textContent = a.verdict || '无研判结论';
        if (respEl) respEl.textContent = a.model_response || '无模型响应';
        var modal = document.getElementById('ai-verdict-modal');
        if (modal) modal.classList.add('active');
        if (typeof refreshIcons === 'function') refreshIcons();
    };
    window.closeAiVerdict = function() {
        var modal = document.getElementById('ai-verdict-modal');
        if (modal) modal.classList.remove('active');
    };
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') window.closeAiVerdict();
    });

    window.toggleWhitelistRule = function(id, enabled) {
        apiPut('/api/whitelist/' + encodeURIComponent(id), { enabled: enabled }).then(function(res) {
            if (res.ok === false) throw new Error(res.error || '更新失败');
            return loadPlatformData();
        }).then(function() {
            showToast('规则状态已更新');
        }).catch(function(e) {
            console.error('更新规则失败', e);
            showToast('更新规则失败：' + e.message);
        });
    };

    window.deleteWhitelistRule = function(id) {
        if (!confirm('确定删除该加白规则？')) return;
        apiDelete('/api/whitelist/' + encodeURIComponent(id)).then(function(res) {
            if (res.ok === false) throw new Error(res.error || '删除失败');
            return loadPlatformData();
        }).then(function() {
            showToast('规则已删除');
        }).catch(function(e) {
            console.error('删除规则失败', e);
            showToast('删除规则失败：' + e.message);
        });
    };

    loadPlatformData();
    loadAttackData();
    loadAssets();
})();
