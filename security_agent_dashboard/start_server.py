import subprocess
import os
import sys
import signal
import time

BASE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(BASE, 'dashboard.log')
LOCKS = [os.path.join(BASE, f) for f in ['.xdr_scheduler.lock', '.vuln_scheduler.lock']]

def main():
    # 清理锁文件
    for f in LOCKS:
        try:
            if os.path.exists(f):
                os.remove(f)
                print(f'removed lock: {f}')
        except Exception as e:
            print(f'could not remove {f}: {e}')

    # 启动 Flask 服务，使用新会话脱离终端
    with open(LOG, 'a') as log:
        proc = subprocess.Popen(
            [sys.executable, 'app.py'],
            cwd=BASE,
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    print(f'started app.py as pid {proc.pid}')

if __name__ == '__main__':
    main()
