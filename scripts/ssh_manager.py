"""Persistent SSH broker and agent-friendly JSON CLI. Python standard library only."""
import argparse
import base64
import codecs
import getpass
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time
import uuid
import zlib
from multiprocessing.connection import Listener, Client

if os.name == 'nt':
    from conpty import Terminal, inside_job, job_limits
else:
    from posix_terminal import Terminal, inside_job, job_limits
from auth_flow import AuthFlow
import profiles
import host_lifecycle

HERE = Path(__file__).resolve().parent
DEFAULT_RUNTIME = profiles.default_runtime()
CHUNK = 196608
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)')
FRAME = re.compile(r'@PSSH1@([A-Za-z0-9+/=\r\n]+)@END@')


def json_write(path, value):
    profiles.atomic_json(path, value)


def hash_file(path, length=None):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while length is None or length > 0:
            data = f.read(1024 * 1024 if length is None else min(length, 1024 * 1024))
            if not data:
                break
            h.update(data)
            if length is not None:
                length -= len(data)
    return h.hexdigest()


def ipc(runtime, request):
    config = profiles.load(runtime)
    key = (runtime / 'auth.key').read_bytes()
    with Client(config['endpoint'], family=config['family'], authkey=key) as conn:
        conn.send_bytes(json.dumps(request, ensure_ascii=True).encode('ascii'))
        if not conn.poll(request.get('_client_timeout', 180)):
            raise TimeoutError('Manager request timed out; check state before retrying a mutation')
        response = json.loads(conn.recv_bytes(4 * 1024 * 1024))
    if not response.get('ok'):
        raise RuntimeError(response.get('error', 'Manager error'))
    return response['result']


class Manager:
    def __init__(self, runtime):
        self.runtime = runtime
        self.config = profiles.load(runtime)
        self.term = None
        self.state = 'idle'
        self.auth = AuthFlow(self.config['auth'])
        self.local_auth_rejections = 0
        self.last_error = None
        self.text = ''
        self.raw_tail = ''
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')
        self.condition = threading.Condition()
        self.responses = {}
        self.remote = None
        self.rpc_lock = threading.Lock()
        self.control_lock = threading.Lock()
        self.shutdown = threading.Event()
        self.started = time.time()
        self.generation = 0

    def status(self):
        if self.term and self.term.poll() is not None and self.state != 'disconnected':
            self.state = 'disconnected'
            self.last_error = 'SSH process exited with code ' + str(self.term.poll())
        if self.shutdown.is_set():
            self.state = 'stopping'
        return {'manager_pid': os.getpid(), 'manager_started': self.started,
                'manager_inside_job': inside_job(), 'manager_job_limit_flags': hex(job_limits()), 'state': self.state,
                'ssh_pid': self.term.pid if self.term and self.term.poll() is None else None,
                'profile': self.config['profile'], 'ssh_alias': self.config['ssh_alias'],
                'authentication': self.auth.public() if self.state in ('connecting', 'awaiting_auth', 'awaiting_confirmation', 'authenticating') else None,
                'local_auth_rejections': self.local_auth_rejections,
                'remote': self.remote, 'error': self.last_error,
                'runtime': str(self.runtime), 'protocol': 1}

    def consume(self, data, generation):
        with self.condition:
            self._consume_locked(data, generation)

    def _consume_locked(self, data, generation):
        if generation != self.generation:
            return
        chunk = self.decoder.decode(data)
        self.raw_tail += chunk
        # Preserve a split ANSI escape until the following read.
        last_esc = self.raw_tail.rfind('\x1b')
        hold = ''
        if last_esc >= 0 and not ANSI.match(self.raw_tail, last_esc):
            hold = self.raw_tail[last_esc:]
            self.raw_tail = self.raw_tail[:last_esc]
        clean = ANSI.sub('', self.raw_tail)
        self.raw_tail = hold[-1024:]
        with self.condition:
            # Never redact the machine protocol: a legitimate secret can be a
            # substring of arbitrary base64. Redact only human-facing diagnostics.
            self.text += clean
            for match in FRAME.finditer(self.text):
                try:
                    message = json.loads(base64.b64decode(match.group(1)))
                    if message['id'] == 'hello' and message['ok']:
                        self.remote = message['result']
                        self.state = 'ready'
                        self.auth = AuthFlow(self.config['auth'])
                    else:
                        self.responses[message['id']] = message
                    self.condition.notify_all()
                except (ValueError, KeyError):
                    self.last_error = 'Invalid remote frame; no mutation was automatically retried'
            matches = list(FRAME.finditer(self.text))
            if matches:
                self.text = self.text[matches[-1].end():]
            self.text = self.text[-8 * 1024 * 1024:]
            if self.state in ('connecting', 'awaiting_auth', 'awaiting_confirmation', 'authenticating'):
                event = self.auth.feed(clean)
                if event == 'empty':
                    self.term.send_console(b'\r')
                    self.state = 'authenticating'
                elif event == 'confirmation':
                    self.state = 'awaiting_confirmation'
                elif event == 'prompt':
                    self.state = 'awaiting_auth'
                elif event == 'shell' and self.config['transport'] == 'shell':
                    self.state = 'bootstrapping'
                    threading.Thread(target=self.bootstrap, daemon=True).start()
            if 'REMOTE HOST IDENTIFICATION HAS CHANGED' in self.text or 'Host key verification failed' in self.text:
                self.last_error = 'SSH host key verification failed. Verify the host; do not bypass checking.'

    def connect(self):
        with self.control_lock:
            current = self.status()
            if current['state'] not in ('idle', 'disconnected'):
                return current
            if self.term:
                self.term.close()
            self.generation += 1
            generation = self.generation
            self.state, self.last_error = 'connecting', None
            self.text, self.raw_tail = '', ''
            self.remote = None
            self.auth = AuthFlow(self.config['auth'])
            self.decoder = codecs.getincrementaldecoder('utf-8')('replace')
            executable = self.config.get('ssh_executable') or shutil.which('ssh')
            if not executable:
                self.state = 'disconnected'
                self.last_error = 'OpenSSH ssh executable is not on PATH'
                raise FileNotFoundError('OpenSSH ssh executable is not on PATH')
            argv = [executable,
                    '-tt', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=10',
                    '-o', 'TCPKeepAlive=yes', '-o', 'StrictHostKeyChecking=yes',
                    '-o', 'ConnectTimeout=20', '-o', 'ConnectionAttempts=1',
                    '-o', 'NumberOfPasswordPrompts=1']
            if self.config.get('ssh_config'):
                argv.extend(['-F', self.config['ssh_config']])
            argv.append(self.config['ssh_alias'])
            if self.config['transport'] == 'exec':
                argv.append(self.bootstrap_command())
            try:
                self.term = Terminal(argv, lambda data: self.consume(data, generation), str(self.runtime))
            except Exception as exc:
                self.state = 'disconnected'
                self.last_error = 'Unable to start SSH: ' + str(exc)
                raise
            return self.status()

    def confirm(self):
        with self.control_lock:
            if self.status()['state'] != 'awaiting_confirmation':
                raise RuntimeError('No configured confirmation sequence is pending')
            self.auth.confirm()
            self.state = 'authenticating'
            self.term.send_console(b'\r')
            return self.status()

    def respond(self, value):
        with self.control_lock:
            if self.status()['state'] not in ('awaiting_auth', 'awaiting_confirmation', 'connecting', 'authenticating'):
                raise RuntimeError('Not at an authentication prompt')
            if not isinstance(value, str) or len(value) > 4096:
                raise ValueError('Invalid authentication response')
            self.auth.respond(value)
            self.text = ''
            self.state = 'authenticating'
            self.term.send_console(value.encode('utf-8') + b'\r')
            return {'response_submitted': True, 'state': self.state}

    def bootstrap_command(self):
        payload = base64.b64encode(zlib.compress((HERE / 'remote_agent.py').read_bytes(), 9)).decode('ascii')
        namespace = self.config['namespace']
        if not re.fullmatch(r'[a-f0-9]{20}', namespace):
            raise ValueError('Invalid profile namespace')
        installer = ("import os,pathlib,tempfile,base64,zlib,sys\n"
                     "p=pathlib.Path(tempfile.gettempdir())/('persistent-ssh-'+str(os.getuid())+'-" + namespace + "')\n"
                     "p.mkdir(mode=448,exist_ok=True)\n"
                     "if p.is_symlink() or p.stat().st_uid != os.getuid(): raise PermissionError('Unsafe remote runtime')\n"
                     "os.chmod(str(p),448)\n"
                     "f=p/'remote_agent.py'\n"
                     "fd,n=tempfile.mkstemp(prefix='agent-',dir=str(p))\n"
                     "with os.fdopen(fd,'wb') as s: s.write(zlib.decompress(base64.b64decode(" + repr(payload) + ")))\n"
                     "os.replace(n,str(f))\n"
                     "os.execv(sys.executable,[sys.executable,'-u',str(f)])")
        return 'stty raw -echo; exec ' + shlex.quote(self.config['remote_python']) + ' -u -c ' + shlex.quote(installer)

    def bootstrap(self):
        try:
            command = self.bootstrap_command() + '\n'
            for _ in range(100):
                if self.term and self.term.poll() is None:
                    break
                time.sleep(0.01)
            self.term.send(command.encode('utf-8'))
        except Exception as exc:
            self.last_error = str(exc)
            self.state = 'bootstrap_failed'

    def rpc(self, request):
        with self.rpc_lock:
            if self.status()['state'] != 'ready':
                raise ConnectionError('SSH is not ready: ' + self.state)
            request = dict(request)
            request['id'] = uuid.uuid4().hex
            deadline = time.monotonic() + 120
            wire = (json.dumps(request, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii')
            if len(wire) > 400000:
                raise ValueError('Request too large; upload a script and execute it instead')
            self.term.send(wire)
            with self.condition:
                while request['id'] not in self.responses:
                    if self.term.poll() is not None:
                        self.status()
                        raise ConnectionError('SSH disconnected; check the job or transfer ID before retrying')
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Remote reply missing; outcome may be unknown. Check operation state, do not replay commands.')
                    self.condition.wait(timeout=0.5)
                response = self.responses.pop(request['id'])
            if not response['ok']:
                raise RuntimeError(response['error'])
            return response['result']

    def dispatch(self, request):
        action = request['action']
        if action == 'status':
            return self.status()
        if action == 'connect':
            return self.connect()
        if action == 'confirm':
            return self.confirm()
        if action == 'auth_info':
            return self.auth.public()
        if action == 'respond':
            return self.respond(request['response'])
        if action == 'rpc':
            return self.rpc(request['request'])
        if action == 'diagnose':
            text = re.sub(r'https://[^\s]+', '[AUTH URL REDACTED]', self.auth.redact(self.text[-5000:]))
            return {'status': self.status(), 'recent_terminal_text': text}
        if action == 'disconnect':
            if request.get('confirm') != 'disconnect':
                raise ValueError('Explicit confirmation required')
            with self.control_lock:
                if self.term:
                    self.term.close()
                self.state = 'disconnected'
                self.auth = AuthFlow(self.config['auth'])
            return self.status()
        if action == 'shutdown':
            if request.get('confirm') != 'shutdown':
                raise ValueError('Explicit confirmation required')
            self.shutdown.set()
            return {'stopping': True}
        raise ValueError('Unsupported manager action')

    def serve(self):
        key = (self.runtime / 'auth.key').read_bytes()
        self.unix_lock = None
        if os.name != 'nt':
            os.umask(0o077)
            self.unix_lock = host_lifecycle.acquire_unix_lock(self.runtime, self.config['endpoint'])
        listener = Listener(self.config['endpoint'], family=self.config['family'], authkey=key)
        json_write(self.runtime / 'manager.json', {'pid': os.getpid(), 'started': self.started,
                                                  'source': str(HERE), 'inside_job': inside_job()})
        def connection(conn):
            try:
                if not conn.poll(15):
                    return
                request = json.loads(conn.recv_bytes(1024 * 1024))
                result = self.dispatch(request)
                conn.send_bytes(json.dumps({'ok': True, 'result': result}, ensure_ascii=True).encode('ascii'))
            except Exception as exc:
                try:
                    conn.send_bytes(json.dumps({'ok': False, 'error': type(exc).__name__ + ': ' + str(exc)}).encode())
                except (OSError, EOFError):
                    pass
            finally:
                conn.close()
        def accept():
            while not self.shutdown.is_set():
                try:
                    conn = listener.accept()
                    threading.Thread(target=connection, args=(conn,), daemon=True).start()
                except Exception as exc:
                    if self.shutdown.is_set():
                        return
                    self.local_auth_rejections += 1
                    time.sleep(0.1)
        threading.Thread(target=accept, daemon=True).start()
        self.shutdown.wait()
        time.sleep(0.2)
        if self.term:
            self.term.close()
        listener.close()
        if self.unix_lock:
            self.unix_lock.close()


def start(runtime):
    config = profiles.load(runtime)
    if (runtime / 'config.json').exists():
        try:
            status = ipc(runtime, {'action': 'status'})
            if status['state'] != 'stopping':
                return status
            for _ in range(30):
                time.sleep(0.1)
                ipc(runtime, {'action': 'status'})
            raise RuntimeError('Existing manager is still stopping')
        except (OSError, EOFError):
            pass
    backend = host_lifecycle.launch(runtime, config)
    json_write(runtime / 'launcher.json', {'backend': backend, 'started': time.time()})
    for _ in range(60):
        try:
            return ipc(runtime, {'action': 'status'})
        except (OSError, EOFError):
            time.sleep(0.1)
    raise TimeoutError('Background manager did not become ready')


def remote(runtime, op, **args):
    return ipc(runtime, {'action': 'rpc', 'request': dict(op=op, **args)})


def read_job(runtime, job_id, wait, stdout_offset=0, stderr_offset=0):
    deadline = time.monotonic() + min(max(wait, 0), 25)
    outputs = {'stdout': bytearray(), 'stderr': bytearray()}
    offsets = {'stdout_offset': stdout_offset, 'stderr_offset': stderr_offset}
    while True:
        result = remote(runtime, 'job', job_id=job_id, **offsets)
        for stream in outputs:
            outputs[stream].extend(base64.b64decode(result.pop(stream + '_base64')))
            offsets[stream + '_offset'] = result[stream + '_offset']
        drained = all(result.get(s + '_size', 0) <= offsets[s + '_offset'] for s in outputs)
        finished = result['state'] not in ('starting', 'running')
        if (finished and drained) or time.monotonic() >= deadline or sum(map(len, outputs.values())) >= 65536:
            break
        if drained:
            time.sleep(0.25)
    for stream, data in outputs.items():
        decoder = codecs.getincrementaldecoder('utf-8')('replace')
        at_end = finished and result.get(stream + '_size', 0) <= offsets[stream + '_offset']
        result[stream] = decoder.decode(bytes(data), final=at_end)
        pending, _ = decoder.getstate()
        # Re-read an incomplete UTF-8 suffix on the next client call.
        result[stream + '_offset'] -= len(pending)
        if pending:
            drained = False
    result['output_remaining'] = not drained
    return result


def upload(runtime, source, destination, overwrite=False, mkdirs=False):
    source = Path(source).resolve(strict=True)
    before = source.stat()
    sha = hash_file(source)
    info = remote(runtime, 'upload_begin', path=destination, size=before.st_size,
                  sha256=sha, overwrite=overwrite, mkdirs=mkdirs)
    if info['complete']:
        return dict(info, path=destination, reused=True)
    offset = info['offset']
    if hash_file(source, offset) != info['prefix_sha256']:
        raise ValueError('Partial upload does not match the local file; no destination was replaced')
    resumed = offset
    started = time.monotonic()
    with source.open('rb') as f:
        f.seek(offset)
        while True:
            data = f.read(CHUNK)
            if not data:
                break
            answer = remote(runtime, 'upload_chunk', upload_id=info['upload_id'], offset=offset,
                            data=base64.b64encode(data).decode('ascii'))
            offset = answer['offset']
    after = source.stat()
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise ValueError('Local file changed during upload; staging remains uncommitted')
    result = remote(runtime, 'upload_commit', upload_id=info['upload_id'])
    result.update(resumed_bytes=resumed, seconds=round(time.monotonic() - started, 3))
    return result


def download(runtime, source, destination, overwrite=False):
    requested = Path(destination).expanduser().absolute()
    if requested.is_symlink():
        raise ValueError('Local destination must not be a symlink')
    target = requested.parent.resolve() / requested.name
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not overwrite:
        raise FileExistsError('Local destination exists; use --overwrite intentionally')
    info = remote(runtime, 'file_info', path=source)
    suffix = hashlib.sha256((source + info['sha256']).encode()).hexdigest()[:24]
    part = target.with_name('.' + target.name + '.pssh-' + suffix + '.part')
    meta = part.with_suffix(part.suffix + '.json')
    identity = {'remote': source, 'local': str(target), 'size': info['size'], 'sha256': info['sha256']}
    if part.exists():
        if not meta.exists() or json.loads(meta.read_text(encoding='utf-8')) != identity:
            raise ValueError('Unrecognized partial download; refusing to overwrite it')
    else:
        with part.open('xb'):
            pass
        json_write(meta, identity)
    offset = part.stat().st_size
    if offset > info['size']:
        raise ValueError('Partial download exceeds remote file size')
    if offset:
        prefix = remote(runtime, 'file_info', path=source, length=offset)
        if hash_file(part) != prefix['sha256']:
            raise ValueError('Partial download checksum mismatch')
    resumed = offset
    started = time.monotonic()
    with part.open('ab') as f:
        while offset < info['size']:
            result = remote(runtime, 'download_chunk', path=source, offset=offset, fingerprint=info['fingerprint'])
            data = base64.b64decode(result['data'], validate=True)
            if not data or result['offset'] != offset + len(data):
                raise ValueError('Invalid download chunk')
            f.write(data)
            offset += len(data)
        f.flush()
        os.fsync(f.fileno())
    if hash_file(part) != info['sha256']:
        raise ValueError('Download checksum mismatch; destination was not replaced')
    if overwrite:
        os.replace(part, target)
    else:
        os.link(part, target)  # Atomic no-clobber publication on Windows and POSIX.
        part.unlink()
    meta.unlink()
    return {'path': str(target), 'size': info['size'], 'sha256': info['sha256'],
            'resumed_bytes': resumed, 'seconds': round(time.monotonic() - started, 3), 'complete': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version='persistent-ssh 0.1.0')
    parser.add_argument('--profile', default='default', help='Named connection profile')
    parser.add_argument('--runtime', type=Path, help='Override the private profile runtime directory')
    subs = parser.add_subparsers(dest='action', required=True)
    for action in ('start', 'status', 'connect', 'confirm', 'auth-info', 'diagnose', 'jobs', 'ping', '_serve'):
        subs.add_parser(action)
    p = subs.add_parser('init')
    p.add_argument('--host', required=True, help='Existing SSH config alias or user@hostname')
    p.add_argument('--settings', type=Path, help='Non-secret JSON authentication/transport settings')
    p = subs.add_parser('auth', help='Human-only secret entry; no password command-line option')
    p.add_argument('--empty', action='store_true', help='Send one explicitly requested empty response')
    for action in ('disconnect', 'shutdown'):
        p = subs.add_parser(action)
        p.add_argument('--yes', action='store_true', required=True)
    p = subs.add_parser('exec')
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--command')
    group.add_argument('--script', type=Path)
    p.add_argument('--cwd', required=True)
    p.add_argument('--wait', type=float, default=10)
    p.add_argument('--timeout', type=float)
    p.add_argument('--job-id', default=None)
    p.add_argument('--env-json', default='{}')
    p = subs.add_parser('job')
    p.add_argument('job_id')
    p.add_argument('--wait', type=float, default=0)
    p.add_argument('--stdout-offset', type=int, default=0)
    p.add_argument('--stderr-offset', type=int, default=0)
    p = subs.add_parser('cancel')
    p.add_argument('job_id')
    for action in ('upload', 'download'):
        p = subs.add_parser(action)
        p.add_argument('source')
        p.add_argument('destination')
        p.add_argument('--overwrite', action='store_true')
        if action == 'upload':
            p.add_argument('--mkdirs', action='store_true')
    args = parser.parse_args()
    runtime = (args.runtime or profiles.default_runtime(args.profile)).expanduser().absolute()
    action = args.action
    if action == '_serve':
        Manager(runtime).serve()
        return
    if action == 'init':
        settings = json.loads(args.settings.read_text(encoding='utf-8-sig')) if args.settings else {}
        result = profiles.initialize(runtime, args.profile, args.host, settings)
    elif action == 'start':
        result = start(runtime)
    elif action in ('status', 'connect', 'confirm', 'auth-info', 'diagnose'):
        result = ipc(runtime, {'action': action.replace('-', '_')})
    elif action == 'auth':
        info = ipc(runtime, {'action': 'auth_info'})
        if args.empty:
            response = ''
        else:
            if not sys.stdin.isatty():
                raise RuntimeError('Enter passwords/OTP in your own interactive terminal; secrets are never accepted as command arguments')
            print(info['recent_text'], file=sys.stderr)
            response = getpass.getpass('Authentication response (hidden): ')
        result = ipc(runtime, {'action': 'respond', 'response': response})
    elif action in ('disconnect', 'shutdown'):
        result = ipc(runtime, {'action': action, 'confirm': action})
    elif action in ('jobs', 'ping'):
        result = remote(runtime, action)
    elif action == 'exec':
        command = args.script.read_text(encoding='utf-8-sig') if args.script else args.command
        job_id = args.job_id or uuid.uuid4().hex
        if not re.fullmatch(r'[a-f0-9]{32}', job_id):
            raise ValueError('Job ID must contain exactly 32 lowercase hexadecimal characters')
        # Record intent before sending so an ambiguous disconnect cannot lose its ID.
        requests = runtime / 'requests'
        requests.mkdir(exist_ok=True)
        intent_path = requests / (job_id + '.json')
        command_hash = hashlib.sha256(command.encode()).hexdigest()
        if intent_path.exists():
            existing = json.loads(intent_path.read_text(encoding='utf-8'))
            if existing['command_sha256'] != command_hash or existing['cwd'] != args.cwd:
                raise ValueError('Job ID already records another command or directory')
        else:
            json_write(intent_path, {'id': job_id, 'cwd': args.cwd, 'created': time.time(),
                                     'command_sha256': command_hash})
        print(json.dumps({'submitted_job_id': job_id}), file=sys.stderr, flush=True)
        remote(runtime, 'exec', job_id=job_id, command=command, cwd=args.cwd,
               timeout=args.timeout, env=json.loads(args.env_json))
        result = read_job(runtime, job_id, args.wait)
    elif action == 'job':
        result = read_job(runtime, args.job_id, args.wait, args.stdout_offset, args.stderr_offset)
    elif action == 'cancel':
        result = remote(runtime, 'cancel', job_id=args.job_id)
    elif action == 'upload':
        result = upload(runtime, args.source, args.destination, args.overwrite, args.mkdirs)
    elif action == 'download':
        result = download(runtime, args.source, args.destination, args.overwrite)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        if sys.stdout:
            sys.stdout.reconfigure(encoding='utf-8')
        if sys.stderr:
            sys.stderr.reconfigure(encoding='utf-8')
        main()
    except Exception as exc:
        if sys.stderr:
            print(json.dumps({'error': type(exc).__name__ + ': ' + str(exc)}, ensure_ascii=False), file=sys.stderr)
        sys.exit(1)
