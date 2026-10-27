"""POSIX terminal for SSH authentication plus raw pipes for remote protocol data."""
import errno
import os
from pathlib import Path
import pty
import subprocess
import sys
import threading


def inside_job():
    return False


def job_limits():
    return 0


class Terminal:
    def __init__(self, argv, callback, cwd=None):
        self.callback = callback
        self.error = None
        self.closed = False
        self.lock = threading.Lock()
        self.master, slave = pty.openpty()
        # Keep a slave open until shutdown: the SSH child opens /dev/tty only
        # after exec, and a transient no-slave interval otherwise yields EIO.
        self.slave = slave
        helper = Path(__file__).with_name('posix_child.py')
        try:
            self.process = subprocess.Popen([sys.executable, str(helper), str(slave), *argv],
                                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            cwd=cwd, pass_fds=(slave,), start_new_session=True, close_fds=True)
        except BaseException:
            os.close(self.master)
            os.close(slave)
            raise
        self.pid = self.process.pid
        self.reader = threading.Thread(target=self._read, args=(self.process.stdout.fileno(),), daemon=True)
        self.console_reader = threading.Thread(target=self._read, args=(self.master,), daemon=True)
        self.reader.start()
        self.console_reader.start()

    def _read(self, fd):
        try:
            while True:
                data = os.read(fd, 65536)
                if not data:
                    return
                self.callback(data)
        except OSError as exc:
            if not self.closed and exc.errno not in (errno.EIO, errno.EBADF):
                self.error = str(exc)

    def send(self, data):
        if self.closed or self.poll() is not None:
            raise ConnectionError('SSH process is not running')
        with self.lock:
            self.process.stdin.write(data)
            self.process.stdin.flush()

    def send_console(self, data):
        if self.closed or self.poll() is not None:
            raise ConnectionError('SSH process is not running')
        os.write(self.master, data)

    def poll(self):
        return self.process.poll()

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.process.stdin.close()
        os.close(self.slave)
        os.close(self.master)
        self.reader.join(timeout=1)
        self.console_reader.join(timeout=1)
        self.process.stdout.close()
