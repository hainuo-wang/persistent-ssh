"""Offline Linux end-to-end fixture; never connects to an external SSH host."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import profiles
import ssh_manager as sm


@unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('tmux'), 'Linux and tmux required')
class LinuxIntegration(unittest.TestCase):
    def test_auth_commands_transfer_and_client_exit(self):
        with tempfile.TemporaryDirectory(prefix='pssh-fixture-') as temporary:
            directory = Path(temporary)
            runtime = directory / 'r'
            fixture = directory / 'fixture-ssh'
            fixture.write_bytes((ROOT / 'tests' / 'fixtures' / 'fake_ssh.py').read_bytes())
            fixture.chmod(0o700)
            profiles.initialize(runtime, 'fixture', 'offline-fixture.invalid', {'ssh_executable': str(fixture)})
            manager_started = False
            agent_root = None
            try:
                before = sm.start(runtime)
                manager_started = True
                sm.ipc(runtime, {'action': 'connect'})
                def await_state(expected):
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        status = sm.ipc(runtime, {'action': 'status'})
                        if status['state'] == expected:
                            return status
                        if status['state'] == 'disconnected':
                            self.fail(str(sm.ipc(runtime, {'action': 'diagnose'})))
                        time.sleep(0.05)
                    self.fail(str(sm.ipc(runtime, {'action': 'diagnose'})))
                status = await_state('awaiting_auth')
                self.assertIn('Password:', status['authentication']['prompt'])
                sm.ipc(runtime, {'action': 'respond', 'response': 'fixture-password'})
                status = await_state('awaiting_auth')
                self.assertIn('Verification code:', status['authentication']['prompt'])
                sm.ipc(runtime, {'action': 'respond', 'response': 'fixture-otp'})
                status = await_state('ready')
                ssh_pid = status['ssh_pid']
                agent_root = Path(status['remote']['agent_root'])
                local = directory / 'source.bin'
                local.write_bytes(os.urandom(600000))
                target = directory / 'remote 文件.bin'
                downloaded = directory / 'download 文件.bin'
                sm.upload(runtime, local, str(target))
                sm.download(runtime, str(target), downloaded)
                self.assertEqual(local.read_bytes(), downloaded.read_bytes())
                cli = [sys.executable, str(ROOT / 'scripts' / 'ssh_manager.py'), '--runtime', str(runtime)]
                client = subprocess.Popen(cli + ['exec', '--cwd', temporary, '--command', 'sleep 1; printf completed', '--wait', '25'],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                job = json.loads(client.stderr.readline())['submitted_job_id']
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        if sm.remote(runtime, 'job', job_id=job)['state'] in ('running', 'finished'):
                            break
                    except RuntimeError:
                        pass
                    time.sleep(0.02)
                client.terminate()
                client.wait(timeout=3)
                client.stdout.close()
                client.stderr.close()
                result = sm.read_job(runtime, job, 5)
                self.assertEqual(result['stdout'], 'completed')
                self.assertEqual(result['exit_code'], 0)
                after = sm.ipc(runtime, {'action': 'status'})
                self.assertEqual(before['manager_pid'], after['manager_pid'])
                self.assertEqual(ssh_pid, after['ssh_pid'])
                self.assertIsNone(after['authentication'])
                for path in runtime.rglob('*'):
                    if path.is_file() and path.name != 'auth.key':
                        data = path.read_bytes()
                        self.assertNotIn(b'fixture-password', data)
                        self.assertNotIn(b'fixture-otp', data)
            finally:
                if manager_started:
                    sm.ipc(runtime, {'action': 'shutdown', 'confirm': 'shutdown'})
                    time.sleep(0.5)
                if agent_root:
                    expected = 'persistent-ssh-' + str(os.getuid()) + '-' + profiles.load(runtime)['namespace']
                    if agent_root.parent == Path(tempfile.gettempdir()) and agent_root.name == expected and not agent_root.is_symlink():
                        shutil.rmtree(agent_root)


if __name__ == '__main__':
    unittest.main()
