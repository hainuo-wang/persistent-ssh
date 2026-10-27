"""Launch the broker outside the caller's terminal lifecycle."""
import json
import os
from pathlib import Path
import plistlib
import shlex
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def launch(runtime, config):
    argv = [sys.executable, str(HERE / 'ssh_manager.py'), '--runtime', str(runtime), '_serve']
    if os.name == 'nt':
        powershell = Path(os.environ['WINDIR']) / 'System32' / 'WindowsPowerShell' / 'v1.0' / 'powershell.exe'
        cmd = [str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'RemoteSigned',
               '-File', str(HERE / 'install_task.ps1'), '-Runtime', str(runtime), '-PythonExe', sys.executable]
        backend = 'windows-task-scheduler'
    elif sys.platform == 'darwin':
        label = 'org.persistent-ssh.' + config['namespace']
        plist = runtime / 'daemon.plist'
        plist.write_bytes(plistlib.dumps({'Label': label, 'ProgramArguments': argv,
                                         'WorkingDirectory': str(HERE), 'RunAtLoad': False, 'KeepAlive': False}))
        target = 'gui/' + str(os.getuid())
        existing = subprocess.run(['launchctl', 'print', target + '/' + label], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if existing.returncode:
            subprocess.run(['launchctl', 'bootstrap', target, str(plist)], check=True, capture_output=True)
        cmd = ['launchctl', 'kickstart', target + '/' + label]
        backend = 'launchd'
    else:
        systemd = False
        if shutil.which('systemd-run') and shutil.which('systemctl'):
            try:
                systemd = subprocess.run(['systemctl', '--user', 'show-environment'], stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL, timeout=3).returncode == 0
            except subprocess.TimeoutExpired:
                pass
        if systemd:
            cmd = ['systemd-run', '--user', '--quiet', '--collect', '--unit=persistent-ssh-' + config['namespace'],
                   '--property=RuntimeMaxSec=infinity', '--', *argv]
            backend = 'systemd-user'
        elif shutil.which('tmux'):
            cmd = ['tmux', '-L', 'persistent-ssh-host', 'new-session', '-d', '-s', config['namespace'],
                   '-c', str(HERE), ' '.join(shlex.quote(arg) for arg in argv)]
            backend = 'tmux'
        else:
            raise RuntimeError('A user systemd manager or tmux is required for detached Linux hosting. No unverified nohup fallback is used.')
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if result.returncode:
        raise RuntimeError(backend + ' launch failed: ' + result.stderr.decode(errors='replace')[-2000:])
    return backend


def acquire_unix_lock(runtime, endpoint):
    """Hold this handle for the broker lifetime; only then remove a stale socket."""
    import fcntl
    import stat
    handle = (runtime / 'manager.lock').open('a+b')
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = Path(endpoint)
        if path.exists() or path.is_symlink():
            if not stat.S_ISSOCK(path.lstat().st_mode):
                raise ValueError('Control endpoint exists and is not a socket')
            path.unlink()
        return handle
    except BaseException:
        handle.close()
        raise
