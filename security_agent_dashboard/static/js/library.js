 (function() {
     'use strict';

     var items = [];
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
             headers: { 'Accept': 'application/json' },
             body: body
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

     function loadLibrary() {
         apiGet('/api/library').then(function(list) {
             items = list || [];
             renderLibrary(items);
         }).catch(function(e) {
             console.error('加载资料库失败', e);
             showToast('加载资料库失败');
         });
     }

     function renderLibrary(list) {
         var tbody = $('#library-table-body');
         if (!tbody) return;
         if (!list.length) {
             tbody.innerHTML = '<tr><td colspan="5" class="hint" style="text-align:center">资料库为空，请上传文件</td></tr>';
             return;
         }
         var html = list.map(function(item) {
             return '<tr>' +
                 '<td>' + escapeHtml(item.name) + '</td>' +
                 '<td>' + escapeHtml(item.type) + '</td>' +
                 '<td>' + escapeHtml(item.size_human) + '</td>' +
                 '<td>' + escapeHtml(item.uploaded_at) + '</td>' +
                 '<td>' +
                     '<div class="library-actions">' +
                     '<button class="btn btn-ghost btn-sm" onclick="window.previewLibraryFile(\'' + item.id + '\')">预览</button>' +
                     '<button class="btn btn-primary btn-sm" onclick="window.analyzeLibraryFile(\'' + item.id + '\')">AI 研判</button>' +
                     '<a class="btn btn-ghost btn-sm" href="/api/library/' + item.id + '" download>下载</a>' +
                     '<button class="btn btn-danger btn-sm" onclick="window.deleteLibraryFile(\'' + item.id + '\')">删除</button>' +
                     '</div>' +
                 '</td>' +
             '</tr>';
         }).join('');
         tbody.innerHTML = html;
         refreshIcons();
     }

     function doUpload(file) {
         if (!file) return;
         var fd = new FormData();
         fd.append('file', file);
         apiPost('/api/library/upload', fd).then(function(item) {
             showToast('上传成功：' + item.name);
             items.unshift(item);
             renderLibrary(items);
             $('#library-file-input').value = '';
         }).catch(function(e) {
             showToast('上传失败：' + e.message);
         });
     }

     window.deleteLibraryFile = function(id) {
         if (!confirm('确定删除该资料？')) return;
         apiDelete('/api/library/' + id).then(function() {
             items = items.filter(function(x) { return x.id !== id; });
             renderLibrary(items);
             showToast('已删除');
         }).catch(function(e) { showToast('删除失败：' + e.message); });
     };

     window.previewLibraryFile = function(id) {
         var item = items.find(function(x) { return x.id === id; });
         if (!item) return;
         currentId = id;
         $('#library-preview-title').textContent = item.name;
         $('#library-preview-panel').style.display = 'block';
         $('#library-preview-content').textContent = '加载中…';
         $('#library-analyze-result').innerHTML = '';
         apiGet('/api/library/' + id + '/content').then(function(res) {
             $('#library-preview-content').textContent = res.content || '（无文本内容）';
         }).catch(function(e) {
             $('#library-preview-content').textContent = '加载失败：' + e.message;
         });
     };

     window.analyzeLibraryFile = function(id) {
         var item = items.find(function(x) { return x.id === id; });
         if (!item) return;
         currentId = id;
         $('#library-preview-title').textContent = item.name;
         $('#library-preview-panel').style.display = 'block';
         $('#library-preview-content').textContent = '正在提取内容…';
         $('#library-analyze-result').innerHTML = '<div class="bubble loading"><span></span><span></span><span></span></div>';
         apiPost('/api/library/' + id + '/analyze', null).then(function(res) {
             $('#library-preview-content').textContent = 'AI 研判完成，结果见下方。';
             $('#library-analyze-result').innerHTML = '<div class="bubble">' + escapeHtml(res.reply || '').replace(/\n/g, '<br>') + '</div>';
         }).catch(function(e) {
             $('#library-preview-content').textContent = 'AI 研判失败：' + e.message;
             $('#library-analyze-result').innerHTML = '';
         });
     };

     function init() {
         var btn = $('#library-upload-btn');
         var input = $('#library-file-input');
         var dropZone = $('#library-drop-zone');
         var search = $('#library-search');
         var close = $('#library-preview-close');

         if (btn && input) {
             btn.addEventListener('click', function() { input.click(); });
             input.addEventListener('change', function() { doUpload(input.files[0]); });
         }

         if (dropZone) {
             dropZone.addEventListener('click', function() { if (input) input.click(); });
             dropZone.addEventListener('dragover', function(e) { e.preventDefault(); dropZone.classList.add('dragover'); });
             dropZone.addEventListener('dragleave', function() { dropZone.classList.remove('dragover'); });
             dropZone.addEventListener('drop', function(e) {
                 e.preventDefault();
                 dropZone.classList.remove('dragover');
                 if (e.dataTransfer.files.length) doUpload(e.dataTransfer.files[0]);
             });
         }

         if (search) {
             search.addEventListener('input', function() {
                 var q = search.value.trim();
                 if (!q) { renderLibrary(items); return; }
                 apiGet('/api/library/search?q=' + encodeURIComponent(q)).then(function(list) {
                     renderLibrary(list);
                 }).catch(function(e) { console.error('搜索失败', e); });
             });
         }

        if (close) {
            close.addEventListener('click', function() {
                $('#library-preview-panel').style.display = 'none';
            });
        }

        var analyzeBtn = $('#library-analyze-btn');
        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', function() {
                if (!currentId) {
                    showToast('请先选择要研判的资料');
                    return;
                }
                window.analyzeLibraryFile(currentId);
            });
        }
    }

    window.loadLibraryView = loadLibrary;

     if (document.readyState === 'loading') {
         document.addEventListener('DOMContentLoaded', init);
     } else {
         setTimeout(init, 0);
     }
 })();
