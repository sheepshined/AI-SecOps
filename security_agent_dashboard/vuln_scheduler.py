#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""漏洞库自动更新调度器（后台线程 + 配置持久化）。"""
import json
import os
import threading
import time
import traceback
from datetime import datetime, timezone

import vuln_updater

CONFIG_DIR = os.path.join(os.path.dirname(__file__), 'data')
VULN_SCHEDULER_CONFIG_FILE = os.path.join(CONFIG_DIR, 'vuln_scheduler_config.json')

VULN_SCHEDULER_DEFAULT_CONFIG = {
    'enabled': False,
    'interval_seconds': 21600,  # 默认 6 小时
    'selected_sources': [],
}

_state = {
    'running': False,
    'thread': None,
    'updating': False,
    'update_start_at': None,
    'update_sources': None,
    'update_progress': None,
    'update_result': None,
    'update_error': None,
    'last_run_at': None,
    'last_summary': None,
    'last_error': None,
    'next_run_at': None,
}


# 调度器日志，记录到固定文件便于排查
SCHEDULER_LOG_FILE = os.path.join(CONFIG_DIR, 'vuln_scheduler.log')

def _scheduler_log(msg):
    line = f"[{_now_str()}] {msg}"
    print(line)
    try:
        with open(SCHEDULER_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception:
        pass


def _now_str():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def _now_str_from_timestamp(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def _default_sources():
    return [k for k, v in vuln_updater.VULN_SOURCES.items() if v.get('default')]


def load_config():
    if not os.path.isdir(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
    if not os.path.exists(VULN_SCHEDULER_CONFIG_FILE):
        cfg = dict(VULN_SCHEDULER_DEFAULT_CONFIG)
        cfg['selected_sources'] = _default_sources()
        save_config(cfg)
        return cfg
    try:
        with open(VULN_SCHEDULER_CONFIG_FILE, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    merged = dict(VULN_SCHEDULER_DEFAULT_CONFIG)
    merged.update(cfg)
    if not isinstance(merged.get('selected_sources'), list) or not merged['selected_sources']:
        merged['selected_sources'] = _default_sources()
    try:
        merged['interval_seconds'] = int(merged.get('interval_seconds', VULN_SCHEDULER_DEFAULT_CONFIG['interval_seconds']))
    except Exception:
        merged['interval_seconds'] = VULN_SCHEDULER_DEFAULT_CONFIG['interval_seconds']
    if merged['interval_seconds'] < 60:
        merged['interval_seconds'] = 60
    return merged


def save_config(cfg):
    try:
        with open(VULN_SCHEDULER_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _lock_file():
    return os.path.join(os.path.dirname(__file__), '.vuln_scheduler.lock')


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _read_lock_pid():
    try:
        with open(_lock_file(), 'r') as f:
            return int(f.read().strip())
    except Exception:
        return None


def _remove_lock():
    try:
        if os.path.exists(_lock_file()):
            os.unlink(_lock_file())
    except Exception:
        pass


def update_status():
    s = _state
    return {
        'updating': s['updating'],
        'started_at': s['update_start_at'],
        'sources': s['update_sources'],
        'progress': s['update_progress'],
        'result': s['update_result'],
        'error': s['update_error'],
    }


def public_status():
    s = _state
    cfg = load_config()
    thread_alive = bool(s.get('thread') and s.get('thread').is_alive())
    healthy = (cfg.get('enabled') == s['running']) and (not cfg.get('enabled') or thread_alive)
    return {
        'running': s['running'],
        'thread_alive': thread_alive,
        'healthy': healthy,
        'enabled': cfg.get('enabled', False),
        'interval_seconds': cfg.get('interval_seconds', 21600),
        'selected_sources': cfg.get('selected_sources', []),
        'last_run_at': s['last_run_at'],
        'last_error': s['last_error'],
        'next_run_at': s['next_run_at'],
        'updating': s['updating'],
    }


def start_update(sources=None, days=7):
    """启动一次后台漏洞库更新。返回 (ok, info_or_error)。"""
    if _state['updating']:
        return False, '已有更新任务在运行'
    _state['updating'] = True
    _state['update_start_at'] = _now_str()
    _state['update_sources'] = list(sources) if sources else []
    _state['update_progress'] = '初始化...'
    _state['update_result'] = None
    _state['update_error'] = None

    def worker():
        try:
            _state['update_progress'] = '正在拉取漏洞数据...'
            result = vuln_updater.update_vulnerability_library(sources=sources, days=days)
            _state['update_result'] = result
            _state['update_progress'] = '完成'
            _state['last_run_at'] = _now_str()
            _state['last_summary'] = result
            _state['last_error'] = None
        except Exception as e:
            traceback.print_exc()
            err = f'{type(e).__name__}: {e}'
            _state['update_error'] = err
            _state['update_progress'] = '失败'
            _state['last_error'] = err
        finally:
            _state['updating'] = False

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return True, {
        'sources': _state['update_sources'],
        'days': days,
        'started_at': _state['update_start_at'],
    }


def _scheduler_loop():
    cfg = load_config()
    interval = max(60, int(cfg.get('interval_seconds', 21600)))
    next_run_at = time.time() + interval
    _state['next_run_at'] = _now_str_from_timestamp(next_run_at)
    while _state['running']:
        try:
            time.sleep(1)
            if not _state['running']:
                break
            cfg = load_config()
            if not cfg.get('enabled'):
                break
            now = time.time()
            if now >= next_run_at:
                sources = cfg.get('selected_sources') or _default_sources()
                _scheduler_log(f'调度器触发自动更新，源: {sources}')
                start_update(sources=sources, days=2)
                next_run_at = now + max(60, int(cfg.get('interval_seconds', 21600)))
                _scheduler_log(f'下次运行时间: {_now_str_from_timestamp(next_run_at)}')
            _state['next_run_at'] = _now_str_from_timestamp(next_run_at)
        except Exception as e:
            _scheduler_log(f'调度器循环异常: {type(e).__name__}: {e}')
            traceback.print_exc()
            # 继续循环，不要因异常退出
    try:
        _state['running'] = False
        _state['next_run_at'] = None
    except Exception:
        pass
    _scheduler_log('调度器循环已退出')


def _start_scheduler():
    if _state['running']:
        # 如果标记为运行但线程已死，重置后重新启动
        t = _state.get('thread')
        if t and t.is_alive():
            return
        _scheduler_log('调度器线程已死，准备重启')
        _state['running'] = False
        _state['thread'] = None
    lock_pid = _read_lock_pid()
    if lock_pid and lock_pid != os.getpid() and _pid_alive(lock_pid):
        _scheduler_log(f'其他进程 {lock_pid} 已持有调度器锁，跳过启动')
        return
    try:
        with open(_lock_file(), 'w') as f:
            f.write(str(os.getpid()))
    except Exception:
        pass
    _state['running'] = True
    _state['updating'] = False
    _state['thread'] = threading.Thread(target=_scheduler_loop, daemon=True)
    _state['thread'].start()
    _scheduler_log('漏洞库自动更新调度器已启动')


def _stop_scheduler():
    _state['running'] = False
    t = _state.get('thread')
    if t and t.is_alive():
        t.join(timeout=2)
    _state['next_run_at'] = None


def ensure_scheduler_alive():
    """看门狗：如果配置启用但线程不在，自动重启调度器。"""
    cfg = load_config()
    if not cfg.get('enabled'):
        if _state['running']:
            _stop_scheduler()
        return
    t = _state.get('thread')
    if not _state['running'] or not t or not t.is_alive():
        _scheduler_log('看门狗检测到调度器未运行，尝试重启')
        _stop_scheduler()
        _start_scheduler()


def apply_config():
    cfg = load_config()
    if cfg.get('enabled'):
        ensure_scheduler_alive()
    else:
        if _state['running']:
            _stop_scheduler()
