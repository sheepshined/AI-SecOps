#!/usr/bin/env python3
import json

BASE = '/Users/zhangshanshan/Documents/AI_xinyu/security_agent_dashboard'

def read(name):
    with open(BASE + '/' + name, 'r', encoding='utf-8') as f:
        return f.read()

def write(name, content):
    with open(BASE + '/' + name, 'w', encoding='utf-8') as f:
        f.write(content)

def build_static_index():
    html = read('templates/index.html')
    html = html.replace("{{ url_for('static', filename='css/style.css') }}", './css/style.css')
    data = json.loads(read('static/data/attack_subtechniques.json'))
    tag = '<script>window.__attackData = ' + json.dumps(data, ensure_ascii=False) + ';</script>'
    html = html.replace(
        '<script src="{{ url_for(\'static\', filename=\'js/app.js\') }}"></script>',
        tag + '\n    <script src="./js/app.js"></script>'
    )
    # 修复其余 JS 脚本引用，避免生成的静态 HTML 里残留 Jinja url_for
    html = html.replace(
        '<script src="{{ url_for(\'static\', filename=\'js/assistant.js\') }}"></script>',
        '<script src="./js/assistant.js"></script>'
    )
    html = html.replace(
        '<script src="{{ url_for(\'static\', filename=\'js/library.js\') }}"></script>',
        '<script src="./js/library.js"></script>'
    )
    html = html.replace(
        '<script src="{{ url_for(\'static\', filename=\'js/vulns.js\') }}"></script>',
        '<script src="./js/vulns.js"></script>'
    )
    write('static/index.html', html)

def build_standalone():
    html = read('templates/index.html')
    css = read('static/css/style.css')
    js = read('static/js/app.js')
    assistant_js = read('static/js/assistant.js')
    library_js = read('static/js/library.js')
    vulns_js = read('static/js/vulns.js')
    data = json.loads(read('static/data/attack_subtechniques.json'))
    data_tag = '<script>window.__attackData = ' + json.dumps(data, ensure_ascii=False) + ';</script>'
    html = html.replace(
        '<link rel="stylesheet" href="{{ url_for(\'static\', filename=\'css/style.css\') }}">',
        '<style>\n' + css + '\n</style>'
    )
    html = html.replace(
        '<script src="{{ url_for(\'static\', filename=\'js/app.js\') }}"></script>',
        data_tag + '\n    <script>\n' + js + '\n    </script>'
    )
    html = html.replace(
        '<script src="{{ url_for(\'static\', filename=\'js/assistant.js\') }}"></script>',
        '<script>\n' + assistant_js + '\n    </script>'
    )
    html = html.replace(
        '<script src="{{ url_for(\'static\', filename=\'js/library.js\') }}"></script>',
        '<script>\n' + library_js + '\n    </script>'
    )
    html = html.replace(
        '<script src="{{ url_for(\'static\', filename=\'js/vulns.js\') }}"></script>',
        '<script>\n' + vulns_js + '\n    </script>'
    )
    # fallback cleanups
    html = html.replace("{{ url_for('static', filename='css/style.css') }}", './css/style.css')
    html = html.replace("{{ url_for('static', filename='js/app.js') }}", './js/app.js')
    html = html.replace("{{ url_for('static', filename='js/assistant.js') }}", './js/assistant.js')
    html = html.replace("{{ url_for('static', filename='js/library.js') }}", './js/library.js')
    html = html.replace("{{ url_for('static', filename='js/vulns.js') }}", './js/vulns.js')
    write('security_agent_dashboard.html', html)

build_static_index()
build_standalone()
print('static/index.html and security_agent_dashboard.html built.')
