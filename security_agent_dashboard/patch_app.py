#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

PATH = '/Users/zhangshanshan/Documents/AI_xinyu/security_agent_dashboard/static/js/app.js'

with open(PATH, 'r', encoding='utf-8') as f:
    content = f.read()

old_tactic = """   var tacticGroups = {
       '初始访问': ['T1566.001'],
       '执行': ['T1059.003', 'T1053'],
       '持久化': ['T1505.003'],
       '权限提升': ['T1078'],
       '防御规避': ['T1078'],
       '凭证访问': ['T1003', 'T1110'],
       '发现': [],
       '横向移动': ['T1021.002', 'T1091'],
       '收集': [],
       '命令与控制': ['T1071.001'],
       '外渗': ['T1041'],
       '影响': ['T1498']
   };"""

new_tactic = """   var tacticGroups = {
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

    var parentInfo = {};"""

old_apply = """            if (!item.id || !Array.isArray(item.tactics)) return;
            if (!techniqueNames[item.id]) techniqueNames[item.id] = item.name || item.id;
           item.tactics.forEach(function(tactic) {"""

new_apply = """            if (!item.id || !Array.isArray(item.tactics)) return;
            var displayName = item.nameZh || item.name || item.id;
            techniqueNames[item.id] = displayName;
            if (item.parentId) {
                parentInfo[item.id] = {
                    parentId: item.parentId,
                    parentNameZh: item.parentNameZh || item.parentName || item.parentId
                };
            }
           item.tactics.forEach(function(tactic) {"""

old_render = """    function renderAttck() {
        var container = $('#attck-matrix');
        var counts = {};
        alarmData.forEach(function(a) {
            if (a.attck) counts[a.attck] = (counts[a.attck] || 0) + 1;
        });
        var html = Object.keys(tacticGroups).map(function(tactic) {
            var techs = tacticGroups[tactic];
            var itemsHtml = '';
            if (techs.length === 0) {
                itemsHtml = '<div class="attck-technique" style="opacity:.5;cursor:default"><span>暂无映射</span></div>';
            } else {
                itemsHtml = techs.map(function(tech) {
                    var count = counts[tech] || 0;
                    var name = escapeHtml(techniqueNames[tech] || tech);
                    var countHtml = count ? '<span class="count">' + count + '</span>' : '';
                    return '<div class="attck-technique" onclick="window.filterByTech(\\'' + tech + '\\')">' +
                        '<span>' + escapeHtml(tech) + ' ' + name + '</span>' + countHtml +
                    '</div>';
                }).join('');
            }
            return '<div class="attck-tactic">' +
                '<h3>' + escapeHtml(tactic) + '</h3>' + itemsHtml +
            '</div>';
        }).join('');
        container.innerHTML = html;
    }"""

new_render = """    function parentColor(pid) {
        var palette = ['#3b82f6','#22c55e','#ef4444','#f59e0b','#a855f7','#ec4899','#14b8a6','#6366f1','#84cc16','#f97316','#06b6d4','#8b5cf6','#d946ef','#10b981','#f43f5e','#0ea5e9','#64748b','#b91c1c','#1d4ed8','#047857'];
        var num = 0;
        for (var i = 0; i < pid.length; i++) num = ((num << 5) - num) + pid.charCodeAt(i);
        return palette[Math.abs(num) % palette.length];
    }

    function renderAttck() {
        var container = $('#attck-matrix');
        var counts = {};
        alarmData.forEach(function(a) {
            if (a.attck) counts[a.attck] = (counts[a.attck] || 0) + 1;
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
                var itemsHtml = group.techs.map(function(tech) {
                    var count = counts[tech] || 0;
                    var name = escapeHtml(techniqueNames[tech] || tech);
                    var countHtml = count ? '<span class="count">' + count + '</span>' : '';
                    var leafStyle = isLeaf ? 'border-left-color:' + color : '';
                    return '<div class="attck-technique" style="' + leafStyle + '" onclick="window.filterByTech(\\'' + tech + '\\')">' +
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
    }"""

assert old_tactic in content, 'tacticGroups not found'
assert old_apply in content, 'applyAttackData not found'
assert old_render in content, 'renderAttck not found'

content = content.replace(old_tactic, new_tactic)
content = content.replace(old_apply, new_apply)
content = content.replace(old_render, new_render)

with open(PATH, 'w', encoding='utf-8') as f:
    f.write(content)

print('app.js patched')
