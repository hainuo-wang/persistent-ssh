import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import profiles
from auth_flow import AuthFlow
import ssh_manager as sm
import remote_agent as ra


class AuthenticationTests(unittest.TestCase):
    def new(self, **changes):
        settings = copy.deepcopy(profiles.DEFAULT_AUTH)
        settings.update(changes)
        return AuthFlow(settings)

    def test_password_and_otp_are_manual(self):
        auth = self.new()
        self.assertEqual(auth.feed('Password: '), 'prompt')
        self.assertEqual(auth.responses_sent, 0)
        auth.respond('example-only-secret')
        self.assertEqual(auth.feed('Verification code: '), 'prompt')
        self.assertEqual(auth.responses_sent, 1)
        self.assertEqual(auth.redact('example-only-secret'), '[REDACTED]')

    def test_confirmation_sequence_requires_explicit_confirmation(self):
        auth = self.new(confirm_empty_prompts=[r'\[EMAIL\] password:', r'\[OTP\] code:'])
        self.assertEqual(auth.feed('https://sso.example.org/qr?id=test\n[EMAIL] password: '), 'confirmation')
        self.assertEqual(auth.responses_sent, 0)
        self.assertIn('https://sso.example.org/qr?id=test', auth.urls)
        auth.confirm()
        self.assertEqual(auth.feed('[OTP] code: '), 'empty')
        self.assertEqual(auth.responses_sent, 2)
        self.assertEqual(auth.feed('user@host:~$ '), 'shell')

    def test_split_prompts_and_custom_prompt(self):
        auth = self.new(prompt_pattern=r'(?i)challenge:\s*$')
        self.assertIsNone(auth.feed('Chall'))
        self.assertEqual(auth.feed('enge: '), 'prompt')

    def test_prompt_ending_angle_bracket_is_not_shell(self):
        auth = self.new()
        self.assertEqual(auth.feed('Enter token> '), 'prompt')

    def test_old_password_banner_does_not_block_shell(self):
        self.assertEqual(self.new().feed('Password authentication is enabled\nuser@host:~$ '), 'shell')

    def test_no_unconfigured_automatic_responses(self):
        auth = self.new()
        with self.assertRaises(ValueError):
            auth.confirm()
        with self.assertRaises(ValueError):
            auth.respond('one\ntwo')

    def test_url_capture_groups_do_not_truncate_url(self):
        auth = self.new(url_pattern=r'https://(sso\.example\.org)/[^\s]+')
        auth.feed('https://sso.example.org/qr/123\nPassword: ')
        self.assertEqual(auth.urls, ['https://sso.example.org/qr/123'])

    def test_secret_does_not_change_prompt_matching(self):
        auth = self.new()
        auth.respond('Verification')
        self.assertEqual(auth.feed('Verification code: '), 'prompt')
        self.assertNotIn('Verification', auth.public()['recent_text'])

    def test_secret_does_not_corrupt_protocol_frames(self):
        manager = sm.Manager.__new__(sm.Manager)
        manager.config = {'auth': copy.deepcopy(profiles.DEFAULT_AUTH), 'transport': 'shell'}
        manager.auth = self.new()
        manager.auth.respond('eyJpZCI6')
        manager.generation = 1
        manager.condition = threading.Condition()
        manager.decoder = __import__('codecs').getincrementaldecoder('utf-8')('replace')
        manager.raw_tail = manager.text = ''
        manager.state = 'authenticating'
        manager.responses = {}
        manager.remote = None
        message = {'id': 'hello', 'ok': True, 'result': {'hostname': 'fixture'}}
        payload = base64.b64encode(json.dumps(message, separators=(',', ':')).encode()).decode()
        manager.consume(('@PSSH1@' + payload + '@END@\r\n').encode(), 1)
        self.assertEqual(manager.state, 'ready')
        self.assertEqual(manager.remote['hostname'], 'fixture')
        self.assertFalse(manager.auth.redactions)


class ProfileTests(unittest.TestCase):
    def test_installed_skill_can_repackage_itself(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / 'installed'
            subprocess.run([sys.executable, str(ROOT / 'scripts' / 'install_skill.py'),
                            '--destination', str(destination)], check=True, capture_output=True)
            archive = Path(temp) / 'installed.zip'
            subprocess.run([sys.executable, str(destination / 'scripts' / 'package_release.py'),
                            '--output', str(archive)], cwd=temp, check=True, capture_output=True)
            with zipfile.ZipFile(archive) as package:
                names = package.namelist()
                self.assertIn('persistent-ssh/SKILL.md', names)
                self.assertIn('persistent-ssh/.gitattributes', names)
                self.assertIn('persistent-ssh/.github/workflows/tests.yml', names)
                self.assertFalse(any('__pycache__' in name or name.endswith('/auth.key') for name in names))

    def test_namespaces_are_separate(self):
        with tempfile.TemporaryDirectory() as temp:
            first, second = Path(temp) / 'one', Path(temp) / 'two'
            profiles.initialize(first, 'one', 'one.invalid')
            profiles.initialize(second, 'two', 'two.invalid')
            a, b = profiles.load(first), profiles.load(second)
            self.assertNotEqual(a['namespace'], b['namespace'])
            self.assertNotEqual(a['endpoint'], b['endpoint'])
            self.assertNotEqual(a['task_name'], b['task_name'])

    def test_secrets_rejected_in_settings(self):
        for data in ({'password': 'test'}, {'auth': {'otp': '123456'}}, {'transport': 'invalid'}):
            with self.assertRaises(ValueError):
                profiles.settings_valid(data)

    def test_profile_path_traversal_rejected(self):
        for value in ('../outside', 'a/b', '-bad', 'a' * 49):
            with self.assertRaises(ValueError):
                profiles.profile_name(value)

    def test_atomic_metadata_writers(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'state.json'
            errors = []
            def writer(index):
                try:
                    profiles.atomic_json(path, {'writer': index})
                except Exception as exc:
                    errors.append(exc)
            threads = [threading.Thread(target=writer, args=(i,)) for i in range(20)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertFalse(errors)
            self.assertIn(json.loads(path.read_text())['writer'], range(20))


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.previous = ra.ROOT
        ra.ROOT = self.root / 'agent'
        (ra.ROOT / 'uploads').mkdir(parents=True)
        (ra.ROOT / 'jobs').mkdir()
        self.patch = mock.patch.object(sm, 'remote', side_effect=lambda runtime, op, **args: ra.handle(dict(op=op, **args)))
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        ra.ROOT = self.previous
        self.temp.cleanup()

    def test_binary_resume_and_unicode_names(self):
        payload = bytes(range(256)) * 1800 + '中文'.encode()
        source, target, downloaded = [self.root / name for name in ('源 文件.bin', '远端 文件.bin', '下载 文件.bin')]
        source.write_bytes(payload)
        info = ra.handle(dict(op='upload_begin', path=str(target), size=len(payload), sha256=hashlib.sha256(payload).hexdigest()))
        first = payload[:sm.CHUNK]
        ra.handle(dict(op='upload_chunk', upload_id=info['upload_id'], offset=0, data=base64.b64encode(first).decode()))
        result = sm.upload(None, source, str(target))
        self.assertEqual(result['resumed_bytes'], sm.CHUNK)
        sm.download(None, str(target), downloaded)
        self.assertEqual(downloaded.read_bytes(), payload)

    def test_download_resume(self):
        source, destination = self.root / 'remote.bin', self.root / 'local.bin'
        source.write_bytes(os.urandom(sm.CHUNK * 2 + 13))
        real = lambda runtime, op, **args: ra.handle(dict(op=op, **args))
        count = 0
        def interrupted(runtime, op, **args):
            nonlocal count
            if op == 'download_chunk':
                count += 1
                if count == 2:
                    raise ConnectionError('simulated transport loss')
            return real(runtime, op, **args)
        with mock.patch.object(sm, 'remote', side_effect=interrupted):
            with self.assertRaises(ConnectionError):
                sm.download(None, str(source), destination)
        self.assertFalse(destination.exists())
        result = sm.download(None, str(source), destination)
        self.assertEqual(result['resumed_bytes'], sm.CHUNK)
        self.assertEqual(destination.read_bytes(), source.read_bytes())

    def test_empty_file(self):
        source = self.root / 'empty'
        source.write_bytes(b'')
        sm.upload(None, source, str(self.root / 'remote'))
        sm.download(None, str(self.root / 'remote'), self.root / 'download')
        self.assertEqual((self.root / 'download').read_bytes(), b'')

    def test_bad_checksum_does_not_replace_destination(self):
        target = self.root / 'target'
        target.write_bytes(b'original')
        info = ra.handle(dict(op='upload_begin', path=str(target), size=4, sha256=hashlib.sha256(b'good').hexdigest(), overwrite=True))
        ra.handle(dict(op='upload_chunk', upload_id=info['upload_id'], offset=0, data=base64.b64encode(b'evil').decode()))
        with self.assertRaises(ValueError):
            ra.handle(dict(op='upload_commit', upload_id=info['upload_id']))
        self.assertEqual(target.read_bytes(), b'original')

    def test_upload_rejects_implicit_overwrite(self):
        source, target = self.root / 'source', self.root / 'target'
        source.write_bytes(b'new')
        target.write_bytes(b'old')
        with self.assertRaises(FileExistsError):
            sm.upload(None, source, str(target))
        self.assertEqual(target.read_bytes(), b'old')

    def test_download_no_clobber_race(self):
        source, target = self.root / 'source', self.root / 'target'
        source.write_bytes(b'data')
        real_link = os.link
        def competitor(part, destination):
            Path(destination).write_bytes(b'other writer')
            return real_link(part, destination)
        with mock.patch.object(sm.os, 'link', side_effect=competitor):
            with self.assertRaises(FileExistsError):
                sm.download(None, str(source), target)
        self.assertEqual(target.read_bytes(), b'other writer')

    def test_remote_change_during_download_rejected(self):
        path = self.root / 'data'
        path.write_bytes(b'first')
        info = ra.handle(dict(op='file_info', path=str(path)))
        path.write_bytes(b'longer replacement')
        with self.assertRaises(RuntimeError):
            ra.handle(dict(op='download_chunk', path=str(path), offset=0, fingerprint=info['fingerprint']))

    def test_log_utf8_boundary(self):
        job = '1' * 32
        directory = ra.ROOT / 'jobs' / job
        directory.mkdir()
        ra.dump(directory / 'status.json', {'id': job, 'state': 'finished', 'exit_code': 0})
        text = 'a' * 8191 + '中文'
        (directory / 'stdout').write_bytes(text.encode())
        (directory / 'stderr').write_bytes(b'')
        first = sm.read_job(None, job, 0)
        second = sm.read_job(None, job, 0, first['stdout_offset'], first['stderr_offset'])
        self.assertEqual(first['stdout'] + second['stdout'], text)


class TerminalTests(unittest.TestCase):
    def test_failed_start_can_be_retried_explicitly(self):
        config = dict(auth=copy.deepcopy(profiles.DEFAULT_AUTH), transport='shell',
                      ssh_alias='fixture.invalid', ssh_executable=sys.executable, profile='fixture')
        with mock.patch.object(profiles, 'load', return_value=config):
            manager = sm.Manager(Path(tempfile.gettempdir()))
        with mock.patch.object(sm, 'Terminal', side_effect=OSError('fixture launch failure')) as launch:
            for _ in range(2):
                with self.assertRaises(OSError):
                    manager.connect()
                self.assertEqual(manager.state, 'disconnected')
                self.assertIn('fixture launch failure', manager.last_error)
            self.assertEqual(launch.call_count, 2)

    def test_hidden_authentication_console(self):
        output = bytearray()
        code = "import getpass; answer=getpass.getpass('Password: '); print('AUTH_OK' if answer=='fixture-password' else 'AUTH_BAD',flush=True)"
        terminal = sm.Terminal([sys.executable, '-u', '-c', code], output.extend)
        try:
            normalized = lambda: sm.ANSI.sub('', output.decode('utf-8', errors='replace'))
            deadline = time.monotonic() + 10
            while 'Password:' not in normalized() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertIn('Password:', normalized())
            terminal.send_console(b'fixture-password\r')
            while b'AUTH_OK' not in output and terminal.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertIn('AUTH_OK', normalized())
            self.assertNotIn('fixture-password', normalized())
        finally:
            terminal.close()

    def test_raw_data_roundtrip(self):
        output = bytearray()
        code = "import sys,base64; print(base64.b64encode(bytes(range(256))*768).decode(),flush=True)"
        terminal = sm.Terminal([sys.executable, '-u', '-c', code], output.extend)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and terminal.poll() is None:
                time.sleep(0.02)
            time.sleep(0.1)
        finally:
            terminal.close()
        # Auth terminal can emit its title; raw stdout remains unmodified.
        text = output.decode('utf-8', errors='replace')
        encoded = base64.b64encode(bytes(range(256)) * 768).decode()
        self.assertIn(encoded, text)


if __name__ == '__main__':
    unittest.main()
