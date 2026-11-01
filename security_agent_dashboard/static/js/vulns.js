(function() {
    'use strict';

    var items = [];
    var sources = [];
    var currentId = null;

    function $(s) { return document.querySelector(s); }
    function $$(s) { return document.querySelectorAll(s); }

    function escapeHtml(str) {
        return String(str).replace(/[&<>"']/g, function(m) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
        });
    }

    function showToast(msg) {
        var toast = $('#toast');
        if (!toast) return;
        toast.textContent = msg;
        toast.classList.add('show');
        setTimeout(function() { toast.classList.remove('show'); }, 2200);
    }

    function apiGet(path) {
        return fetch(path, { headers: { 'Accept': 'application/json' } }).then(function(r) {
            if (!r.ok) throw new Error(path + ' returned ' + r.status);
            return r.json();
        });
    }

    function apiPost(path, body) {
        return fetch(path, {
            method: 'POST',
            headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
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

    function refreshIcons() {
        try { if (window.lucide && lucide.createIcons) lucide.createIcons(); } catch (e) {}
    }

    function getSourceName(sourceId) {
        var s = sources.find(function(x) { return x.id === sourceId; });
        return s ? s.name : sourceId;
    }

    function loadSources() {
        apiGet('/api/vulns/sources').then(function(list) {
            sources = list || [];
            renderSources();
        }).catch(function(e) {
            console.error('加载漏洞源失败', e);
            showToast('加载漏洞源失败');
        });
    }

    function renderSources() {
        var container = $('#vuln-sources');
        if (!container) return;
        if (!sources.length) {
            container.innerHTML = '<span class="hint">暂无可选源</span>';
            return;
        }
        var html = sources.map(function(s) {
            return '<label class="vuln-source-label" title="' + escapeHtml(s.description) + '">' +
                '<input type="checkbox" name="vuln-source" value="' + escapeHtml(s.id) + '"' + (s.default ? ' checked' : '') + '>' +
                '<span>' + escapeHtml(s.name) + '</span>' +
                '</label>';
        }).join('');
        container.innerHTML = html;
    }

    function loadVulns() {
        apiGet('/api/vulns/library').then(function(list) {
            items = list || [];
            renderVulns(items);
        }).catch(function(e) {
            console.error('加载漏洞库失败', e);
            showToast('加载漏洞库失败');
        });
    }

    window.loadVulnsView = function() {
        loadSources();
        loadVulns();
        loadSchedulerStatus();
    };

    function renderVulns(list) {
        var tbody = $('#vuln-table-body');
        if (!tbody) return;
        if (!list.length) {
            tbody.innerHTML = '<tr><td colspan="5" class="hint" style="text-align:center">漏洞库为空，请选择数据源并点击"更新漏洞库"</td></tr>';
            return;
        }
        var html = list.map(function(item) {
            var count = item.count !== undefined ? item.count : '-';
            var generated = item.generated_at || '-';
            return '<tr>' +
                '<td>' + escapeHtml(getSourceName(item.source_id) || item.source_id || '未知') + '</td>' +
                '<td>' + escapeHtml(String(count)) + '</td>' +
                '<td>' + escapeHtml(item.uploaded_at) + '</td>' +
                '<td>' + escapeHtml(item.size_human) + '</td>' +
                '<td>' +
                    '<button class="btn btn-ghost btn-sm" onclick="window.previewVulnDoc(\'' + item.id + '\')">预览</button>' +
                    '<button class="btn btn-primary btn-sm" onclick="window.analyzeVulnDoc(\'' + item.id + '\')">AI 研判</button>' +
                    '<a class="btn btn-ghost btn-sm" href="/api/vulns/library/' + item.id + '" download>下载</a>' +
                    '<button class="btn btn-danger btn-sm" onclick="window.deleteVulnDoc(\'' + item.id + '\')">删除</button>' +
                '</td>' +
            '</tr>';
        }).join('');
        tbody.innerHTML = html;
        refreshIcons();
    }

    function getSelectedSources() {
        var boxes = $$('input[name="vuln-source"]:checked');
        return Array.prototype.map.call(boxes, function(b) { return b.value; });
    }

    var schedulerStatus = {};
    var updatePollTimer = null;

    function loadSchedulerStatus() {
        apiGet('/api/vulns/scheduler/status').then(function(status) {
            schedulerStatus = status || {};
            renderSchedulerStatus(status);
        }).catch(function(e) { console.error('加载调度器状态失败', e); });
    }

    function renderSchedulerStatus(status) {
        status = status || {};
        var enabled = !!status.enabled;
        var toggle = $('#vuln-auto-toggle');
        var interval = $('#vuln-interval-select');
        var statusText = $('#vuln-status-text');
        var statusBar = $('#vuln-status-bar');
        if (toggle) toggle.checked = enabled;
        if (interval) interval.value = String(status.interval_seconds || 21600);
        if (statusBar) statusBar.style.display = 'block';
        var label = enabled ? ('自动更新已开启' + (status.running ? '（运行中）' : '（未运行）')) : '自动更新已关闭';
        if (statusText) statusText.textContent = label;
        var lastRun = $('#vuln-last-run');
        if (lastRun) lastRun.textContent = '上次运行：' + (status.last_run_at || '-');
        var nextRun = $('#vuln-next-run');
        if (nextRun) nextRun.textContent = '下次运行：' + (status.next_run_at || '-');
    }

    function postSchedulerConfig(changes) {
        apiPost('/api/vulns/scheduler/config', changes).then(function(cfg) {
            schedulerStatus = cfg;
            renderSchedulerStatus(cfg);
            showToast('配置已保存');
        }).catch(function(e) { showToast('保存配置失败：' + e.message); });
    }

    function pollUpdateStatus() {
        if (updatePollTimer) clearTimeout(updatePollTimer);
        apiGet('/api/vulns/update/status').then(function(status) {
            var progress = $('#vuln-update-progress');
            if (progress) progress.textContent = status.updating ? (status.progress || '更新中…') : '';
            if (status.updating) {
                updatePollTimer = setTimeout(pollUpdateStatus, 2000);
            } else {
                var btn = $('#vuln-update-btn');
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '<i data-lucide="refresh-cw"></i><span>更新漏洞库</span>';
                    refreshIcons();
                }
                if (status.error) {
                    showToast('更新失败：' + status.error);
                } else if (status.result) {
                    var ok = (status.result.sources || []).filter(function(s) { return s.status === 'success'; }).length;
                    var err = (status.result.sources || []).filter(function(s) { return s.status === 'error'; }).length;
                    showToast('更新完成：成功 ' + ok + ' 个，失败 ' + err + ' 个');
                    loadVulns();
                    loadSchedulerStatus();
                }
            }
        }).catch(function(e) {
            console.error('查询更新状态失败', e);
            updatePollTimer = setTimeout(pollUpdateStatus, 3000);
        });
    }

    function doUpdate() {
        var selected = getSelectedSources();
        if (!selected.length) {
            showToast('请至少选择一个漏洞数据源');
            return;
        }
        var btn = $('#vuln-update-btn');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i data-lucide="loader-2"></i><span>更新中…</span>';
            refreshIcons();
        }
        showToast('开始从 ' + selected.length + ' 个数据源更新漏洞库');
        apiPost('/api/vulns/update', { sources: selected, days: 7 }).then(function(result) {
            if (!result.started) {
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '<i data-lucide="refresh-cw"></i><span>更新漏洞库</span>';
                    refreshIcons();
                }
                showToast('更新未启动：' + (result.error || '未知'));
                return;
            }
            showToast('后台更新已启动');
            pollUpdateStatus();
        }).catch(function(e) {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<i data-lucide="refresh-cw"></i><span>更新漏洞库</span>';
                refreshIcons();
            }
            showToast('更新失败：' + e.message);
        });
    }


    window.deleteVulnDoc = function(id) {
        if (!confirm('确定删除该漏洞资料？')) return;
        apiDelete('/api/vulns/library/' + id).then(function() {
            items = items.filter(function(x) { return x.id !== id; });
            renderVulns(items);
            showToast('已删除');
        }).catch(function(e) { showToast('删除失败：' + e.message); });
    };

    window.previewVulnDoc = function(id) {
        var item = items.find(function(x) { return x.id === id; });
        if (!item) return;
        currentId = id;
        $('#vuln-preview-title').textContent = item.name;
        $('#vuln-preview-panel').style.display = 'block';
        $('#vuln-preview-content').textContent = '加载中…';
        $('#vuln-analyze-result').innerHTML = '';
        apiGet('/api/vulns/library/' + id + '/content').then(function(res) {
            renderVulnPreviewContent(item, res.content || '');
        }).catch(function(e) {
            $('#vuln-preview-content').textContent = '加载失败：' + e.message;
        });
    };

    function renderVulnPreviewContent(item, rawText) {
        var container = $('#vuln-preview-content');
        if (!container) return;
        var data;
        try {
            data = JSON.parse(rawText);
        } catch (err) {
            container.textContent = rawText || '（无内容）';
            return;
        }
        var feed = data.feed || item.source_id || '未知源';
        var title = data.title || item.name || '漏洞资料';
        var generated = data.generated_at || item.generated_at || '-';
        var count = data.count || (data.vulnerabilities ? data.vulnerabilities.length : 0) || 0;
        var vulnerabilities = Array.isArray(data.vulnerabilities) ? data.vulnerabilities : [];

        function severityClass(s) {
            s = String(s || '').toLowerCase();
            if (s.indexOf('critical') !== -1 || s.indexOf('严重') !== -1) return 'severity-critical';
            if (s.indexOf('high') !== -1 || s.indexOf('高') !== -1) return 'severity-high';
            if (s.indexOf('medium') !== -1 || s.indexOf('中') !== -1) return 'severity-medium';
            if (s.indexOf('low') !== -1 || s.indexOf('低') !== -1) return 'severity-low';
            return 'severity-unknown';
        }

        var html = '<div class="vuln-preview-summary">' +
            '<h3>' + escapeHtml(title) + '</h3>' +
            '<div class="vuln-meta">' +
            '<span>源：' + escapeHtml(feed) + '</span>' +
            '<span>数量：' + count + '</span>' +
            '<span>生成时间：' + escapeHtml(generated) + '</span>' +
            '</div>' +
            '</div>';

        if (!vulnerabilities.length) {
            html += '<p class="hint">该资料未包含结构化漏洞列表。</p>';
            html += '<details><summary>原始 JSON（调试用）</summary><pre class="vuln-raw-json">' + escapeHtml(rawText) + '</pre></details>';
            container.innerHTML = html;
            return;
        }

        html += '<div class="vuln-preview-scroll">';
        html += '<table class="vuln-preview-table">';
        html += '<thead><tr>' +
            '<th style="width:160px">CVE ID</th>' +
            '<th style="width:80px">严重等级</th>' +
            '<th style="width:70px">CVSS</th>' +
            '<th style="width:120px">发布时间</th>' +
            '<th>描述</th>' +
            '</tr></thead>';
        html += '<tbody>';
        vulnerabilities.forEach(function(v) {
            var cveId = v.cve_id || v.cveID || v.cve || v.id || '-';
            var severity = v.severity || '-';
            var cvss = v.cvss_score !== undefined && v.cvss_score !== null ? v.cvss_score : '-';
            var published = v.published || v.publishedDate || v.pub_date || '-';
            var description = v.description || v.summary || '无描述';
            if (description.length > 160) description = description.substring(0, 160) + '…';
            html += '<tr>' +
                '<td class="cve-id">' + (cveId !== '-' ? '<a href="https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(cveId) + '" target="_blank" rel="noopener">' + escapeHtml(cveId) + '</a>' : escapeHtml(cveId)) + '</td>' +
                '<td><span class="severity-badge ' + severityClass(severity) + '">' + escapeHtml(severity) + '</span></td>' +
                '<td class="cve-cvss">' + escapeHtml(String(cvss)) + '</td>' +
                '<td class="cve-date">' + escapeHtml(String(published).slice(0, 16)) + '</td>' +
                '<td class="cve-desc" title="' + escapeHtml(v.description || v.summary || '') + '">' + escapeHtml(description) + '</td>' +
                '</tr>';
        });
        html += '</tbody></table>';
        html += '</div>';
        html += '<details><summary>原始 JSON</summary><pre class="vuln-raw-json">' + escapeHtml(rawText) + '</pre></details>';
        container.innerHTML = html;
    }

    window.analyzeVulnDoc = function(id) {
        var item = items.find(function(x) { return x.id === id; });
        if (!item) return;
        currentId = id;
        $('#vuln-preview-title').textContent = item.name;
        $('#vuln-preview-panel').style.display = 'block';
        $('#vuln-preview-content').textContent = '正在提取内容…';
        $('#vuln-analyze-result').innerHTML = '<div class="bubble loading"><span></span><span></span><span></span></div>';
        apiPost('/api/vulns/library/' + id + '/analyze', null).then(function(res) {
            $('#vuln-preview-content').textContent = 'AI 研判完成，结果见下方。';
            $('#vuln-analyze-result').innerHTML = '<div class="bubble">' + escapeHtml(res.reply || '').replace(/\n/g, '<br>') + '</div>';
        }).catch(function(e) {
            $('#vuln-preview-content').textContent = 'AI 研判失败：' + e.message;
            $('#vuln-analyze-result').innerHTML = '';
        });
    };

    function init() {
        var btn = $('#vuln-update-btn');
        var close = $('#vuln-preview-close');
        var analyzeBtn = $('#vuln-analyze-btn');

        if (btn) btn.addEventListener('click', doUpdate);
        var autoToggle = $('#vuln-auto-toggle');
        var intervalSelect = $('#vuln-interval-select');
        if (autoToggle) {
            autoToggle.addEventListener('change', function() {
                postSchedulerConfig({ enabled: autoToggle.checked });
            });
        }
        if (intervalSelect) {
            intervalSelect.addEventListener('change', function() {
                postSchedulerConfig({ interval_seconds: parseInt(intervalSelect.value, 10) });
            });
        }
        if (close) {
            close.addEventListener('click', function() {
                $('#vuln-preview-panel').style.display = 'none';
            });
        }
        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', function() {
                if (!currentId) {
                    showToast('请先选择要研判的资料');
                    return;
                }
                window.analyzeVulnDoc(currentId);
            });
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        setTimeout(init, 0);
    }
})();
