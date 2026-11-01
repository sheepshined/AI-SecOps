#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""基于行号修改 app.js： tacticGroups / applyAttackData / renderAttck。"""

PATH = '/Users/zhangshanshan/Documents/AI_xinyu/security_agent_dashboard/static/js/app.js'

with open(PATH, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_tactic = [
    '   var tacticGroups = {\n',
    "       '侦察': [],\n",
    "       '资源开发': [],\n",
    "       '初始访问': [],\n",
    "       '执行': [],\n",
    "       '持久化': [],\n",
    "       '权限提升': [],\n",
    "       '隐藏痕迹': [],\n",
    "       '防御削弱': [],\n",
    "       '凭证访问': [],\n",
    "       '发现': [],\n",
    "       '横向移动': [],\n",
    "       '收集': [],\n",
    "       '命令与控制': [],\n",
    "       '外渗': [],\n",
    "       '影响': []\n",
    '   };\n',
    '\n',
    '    var parentInfo = {};\n',
]

new_apply = [
    '            var displayName = item.nameZh || item.name || item.id;\n',
    '            techniqueNames[item.id] = displayName;\n',
    '            if (item.parentId) {\n',
    '                parentInfo[item.id] = {\n',
    '                    parentId: item.parentId,\n',
    '                    parentNameZh: item.parentNameZh || item.parentName || item.parentId\n',
    '                };\n',
    '            }\n',
]

new_render = [
    '    function parentColor(pid) {\n',
    "        var palette = ['#3b82f6','#22c55e','#ef4444','#f59e0b','#a855f7','#ec4899','#14b8a6','#6366f1','#84cc16','#f97316','#06b6d4','#8b5cf6','#d946ef','#10b981','#f43f5e','#0ea5e9','#64748b','#b91c1c','#1d4ed8','#047857'];\n",
    '        var num = 0;\n',
    '        for (var i = 0; i < pid.length; i++) num = ((num << 5) - num) + pid.charCodeAt(i);\n',
    "        return palette[Math.abs(num) % palette.length];\n",
    '    }\n',
    '\n',
    '    function renderAttck() {\n',
    "        var container = $('#attck-matrix');\n",
    '        var counts = {};\n',
    '        alarmData.forEach(function(a) {\n',
    '            if (a.attck) counts[a.attck] = (counts[a.attck] || 0) + 1;\n',
    '        });\n',
    '        var html = Object.keys(tacticGroups).map(function(tactic) {\n',
    '            var techs = tacticGroups[tactic];\n',
    '            var groups = {};\n',
    '            techs.forEach(function(tech) {\n',
    '                var pid = (parentInfo[tech] && parentInfo[tech].parentId) || tech;\n',
    '                if (!groups[pid]) groups[pid] = { techs: [], info: parentInfo[tech] };\n',
    '                groups[pid].techs.push(tech);\n',
    '            });\n',
    '            var groupHtml = Object.keys(groups).map(function(pid) {\n',
    '                var group = groups[pid];\n',
    '                var color = parentColor(pid);\n',
    '                var parentLabel = (group.info && group.info.parentNameZh) || pid;\n',
    '                var isLeaf = group.techs.length === 1 && group.techs[0] === pid;\n',
    '                var parentHtml = \'\';\n',
    '                if (!isLeaf) {\n',
    '                    parentHtml = \'<div class="attck-parent" style="border-left-color:\' + color + \'">\' + escapeHtml(parentLabel) + \'</div>\';\n',
    '                }\n',
    '                var itemsHtml = group.techs.map(function(tech) {\n',
    '                    var count = counts[tech] || 0;\n',
    '                    var name = escapeHtml(techniqueNames[tech] || tech);\n',
    "                    var countHtml = count ? '<span class=\"count\">' + count + '</span>' : '';\n",
    '                    var leafStyle = isLeaf ? \'border-left-color:\' + color : \'\';\n',
    "                    return '<div class=\"attck-technique\" style=\"' + leafStyle + '\" onclick=\"window.filterByTech(\\'' + tech + '\\')\">' +\n",
    "                        '<span>' + escapeHtml(tech) + ' ' + name + '</span>' + countHtml +\n",
    "                    '</div>';\n",
    '                }).join(\'\');\n',
    '                return parentHtml + itemsHtml;\n',
    '            }).join(\'\');\n',
    '            if (techs.length === 0) {\n',
    '                groupHtml = \'<div class="attck-technique" style="opacity:.5;cursor:default"><span>暂无映射</span></div>\';\n',
    '            }\n',
    "            return '<div class=\"attck-tactic\">' +\n",
    "                '<h3>' + escapeHtml(tactic) + '</h3>' + groupHtml +\n",
    "            '</div>';\n",
    '        }).join(\'\');\n',
    '        container.innerHTML = html;\n',
    '    }\n',
]

# 行号转 0-based
# tacticGroups: 33-46
# applyAttackData 替换行: 52
# renderAttck: 440-466
lines[439:466] = new_render
lines[51:52] = new_apply
lines[32:46] = new_tactic

with open(PATH, 'w', encoding='utf-8') as f:
    f.writelines(lines)

print('app.js patched by line')
