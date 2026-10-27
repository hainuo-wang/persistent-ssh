"""Linux-side JSON RPC and persistent jobs; deployed over the authenticated shell."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

CHUNK = 196608
ROOT = Path(__file__).resolve().parent
PREFIX = '@PSSH1@'
TMUX_SOCKET = 'pssh-' + hashlib.sha256(str(ROOT).encode()).hexdigest()[:16]


def dump(path, value):
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=str(path.parent))
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=True)
    os.replace(name, str(path))


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def digest(path, length=None):
    h = hashlib.sha256()
    with open(str(path), 'rb') as stream:
        left = length
        while left is None or left > 0:
            block = stream.read(1024 * 1024 if left is None else min(left, 1024 * 1024))
            if not block:
                break
            h.update(block)
            if left is not None:
                left -= len(block)
    return h.hexdigest()


def absolute(value):
    path = Path(value)
    if not path.is_absolute():
        raise ValueError('Remote paths must be absolute')
    return path


def identifier(value):
    if not re.fullmatch(r'[a-f0-9]{32}', value):
        raise ValueError('Invalid operation ID')
    return value


def proc_start(pid):
    try:
        raw = Path('/proc/{}/stat'.format(pid)).read_text()
        return raw.rsplit(')', 1)[1].split()[19]
    except (FileNotFoundError, ProcessLookupError):
        return None


def fingerprint(path):
    s = path.stat()
    if not stat.S_ISREG(s.st_mode):
        raise ValueError('Only regular files are supported')
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns]


def job_dir(job_id):
    return ROOT / 'jobs' / identifier(job_id)


def job_worker(job_id):
    directory = job_dir(job_id)
    spec = load(directory / 'spec.json')
    env = os.environ.copy()
    env.update(spec.get('env', {}))
    result = {'id': job_id, 'state': 'starting', 'started': time.time()}
    try:
        with open(str(directory / 'stdout'), 'wb') as out, open(str(directory / 'stderr'), 'wb') as err:
            p = subprocess.Popen(['/bin/bash', '-lc', spec['command']], cwd=spec['cwd'],
                                 env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                 start_new_session=True)
            result.update(state='running', pid=p.pid, process_start=proc_start(p.pid))
            dump(directory / 'status.json', result)
            try:
                code = p.wait(timeout=spec.get('timeout'))
                result.update(state='finished', exit_code=code)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGTERM)
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait()
                result.update(state='timed_out', exit_code=p.returncode)
    except BaseException as exc:
        result.update(state='failed', error=str(exc))
    result['finished'] = time.time()
    dump(directory / 'status.json', result)


def handle(req):
    op = req['op']
    if op == 'ping':
        return {'hostname': socket.gethostname(), 'user_id': os.getuid(), 'cwd': os.getcwd(),
                'agent_root': str(ROOT), 'agent_pid': os.getpid(), 'tmux': bool(shutil.which('tmux')),
                'python': sys.version.split()[0], 'chunk_bytes': CHUNK}
    if op == 'exec':
        job_id = identifier(req['job_id'])
        directory = job_dir(job_id)
        spec = {'command': req['command'], 'cwd': str(absolute(req['cwd'])),
                'env': req.get('env', {}), 'timeout': req.get('timeout')}
        if not Path(spec['cwd']).is_dir():
            raise FileNotFoundError('Working directory does not exist: ' + spec['cwd'])
        if directory.exists():
            if load(directory / 'spec.json') != spec:
                raise ValueError('Job ID already belongs to another command')
            return handle({'op': 'job', 'job_id': job_id})
        directory.mkdir(mode=0o700, parents=True)
        dump(directory / 'spec.json', spec)
        dump(directory / 'status.json', {'id': job_id, 'state': 'starting', 'created': time.time()})
        argv = [sys.executable, str(Path(__file__).resolve()), 'job', job_id]
        try:
            if shutil.which('tmux'):
                session = 'cx-' + job_id
                result = subprocess.run(['tmux', '-L', TMUX_SOCKET, 'new-session', '-d', '-s', session,
                                         '-c', spec['cwd'], ' '.join(shlex.quote(a) for a in argv)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                if result.returncode:
                    raise RuntimeError(result.stderr.decode('utf-8', errors='replace'))
            else:
                subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        except BaseException as exc:
            dump(directory / 'status.json', {'id': job_id, 'state': 'failed', 'error': str(exc)})
            raise
        return {'id': job_id, 'state': 'starting'}
    if op == 'job':
        directory = job_dir(req['job_id'])
        result = load(directory / 'status.json')
        if result['state'] == 'running' and proc_start(result['pid']) != result['process_start']:
            # The worker may be between wait() and its final atomic status write.
            time.sleep(0.05)
            result = load(directory / 'status.json')
            if result['state'] == 'running' and proc_start(result['pid']) != result['process_start']:
                result['state'] = 'lost'
        if result['state'] == 'starting' and time.time() - result.get('created', time.time()) > 30:
            result['state'] = 'lost'
        for stream in ('stdout', 'stderr'):
            path = directory / stream
            offset = max(0, int(req.get(stream + '_offset', 0)))
            data = b''
            if path.exists():
                with path.open('rb') as f:
                    f.seek(offset)
                    data = f.read(8192)
                result[stream + '_size'] = path.stat().st_size
            result[stream + '_base64'] = base64.b64encode(data).decode('ascii')
            result[stream + '_offset'] = offset + len(data)
        return result
    if op == 'jobs':
        entries = sorted((ROOT / 'jobs').glob('*/status.json'), key=lambda p: p.stat().st_mtime, reverse=True)
        return [load(p) for p in entries[:30]]
    if op == 'cancel':
        directory = job_dir(req['job_id'])
        info = load(directory / 'status.json')
        if info['state'] == 'running' and proc_start(info['pid']) == info['process_start']:
            os.killpg(info['pid'], signal.SIGTERM)
            return {'id': req['job_id'], 'termination_requested': True}
        return {'id': req['job_id'], 'termination_requested': False, 'state': info['state']}
    if op == 'file_info':
        path = absolute(req['path'])
        before = fingerprint(path)
        sha = digest(path, req.get('length'))
        if fingerprint(path) != before:
            raise RuntimeError('File changed while hashing')
        return {'path': str(path), 'size': before[2], 'sha256': sha, 'fingerprint': before,
                'mode': stat.S_IMODE(path.stat().st_mode)}
    if op == 'download_chunk':
        path = absolute(req['path'])
        if fingerprint(path) != req['fingerprint']:
            raise RuntimeError('Remote file changed; restart download')
        with path.open('rb') as f:
            f.seek(int(req['offset']))
            data = f.read(CHUNK)
        if fingerprint(path) != req['fingerprint']:
            raise RuntimeError('Remote file changed during read')
        return {'data': base64.b64encode(data).decode('ascii'), 'offset': int(req['offset']) + len(data)}
    if op == 'upload_begin':
        path = absolute(req['path'])
        sha = req['sha256']
        size = int(req['size'])
        if not re.fullmatch(r'[a-f0-9]{64}', sha) or size < 0:
            raise ValueError('Invalid size or SHA-256')
        if req.get('mkdirs'):
            path.parent.mkdir(parents=True, exist_ok=True)
        if not path.parent.is_dir() or path.is_symlink():
            raise ValueError('Destination parent missing or destination is a symlink')
        mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
        if path.exists():
            if not path.is_file():
                raise ValueError('Destination must be a regular file')
            if path.stat().st_size == size and digest(path) == sha:
                return {'complete': True, 'size': size, 'sha256': sha}
            if not req.get('overwrite'):
                raise FileExistsError('Destination exists; use --overwrite intentionally')
        uid = hashlib.sha256((str(path) + '\0' + sha).encode()).hexdigest()[:32]
        metadata = ROOT / 'uploads' / (uid + '.json')
        temporary = path.with_name('.' + path.name + '.pssh-' + uid + '.part')
        info = {'path': str(path), 'temporary': str(temporary), 'size': size, 'sha256': sha,
                'mode': mode, 'overwrite': bool(req.get('overwrite'))}
        if metadata.exists():
            if load(metadata) != info:
                raise RuntimeError('Existing upload has different options')
            if not temporary.exists():
                fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
                os.close(fd)
        else:
            fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            os.close(fd)
            metadata.parent.mkdir(mode=0o700, exist_ok=True)
            dump(metadata, info)
        if temporary.is_symlink() or not temporary.is_file():
            raise ValueError('Invalid staging file')
        offset = temporary.stat().st_size
        if offset > size:
            raise ValueError('Staging file exceeds expected size')
        return {'complete': False, 'upload_id': uid, 'offset': offset, 'prefix_sha256': digest(temporary)}
    if op == 'upload_chunk':
        info = load(ROOT / 'uploads' / (identifier(req['upload_id']) + '.json'))
        path = Path(info['temporary'])
        data = base64.b64decode(req['data'], validate=True)
        if len(data) > CHUNK:
            raise ValueError('Chunk too large')
        offset = int(req['offset'])
        if offset < 0 or offset + len(data) > info['size']:
            raise ValueError('Chunk outside expected file size')
        fd = os.open(str(path), os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'r+b') as f:
            current = os.fstat(f.fileno()).st_size
            if offset < current:
                f.seek(offset)
                if f.read(len(data)) != data:
                    raise ValueError('Repeated chunk has different bytes')
                return {'offset': current}
            if offset != current:
                raise ValueError('Upload offset mismatch')
            f.seek(offset)
            f.write(data)
            f.flush()
        return {'offset': offset + len(data)}
    if op == 'upload_commit':
        metadata = ROOT / 'uploads' / (identifier(req['upload_id']) + '.json')
        info = load(metadata)
        temp = Path(info['temporary'])
        target = Path(info['path'])
        if not temp.exists():
            if target.is_file() and target.stat().st_size == info['size'] and digest(target) == info['sha256']:
                return {'path': str(target), 'size': info['size'], 'sha256': info['sha256'], 'complete': True}
            raise FileNotFoundError('Upload staging file is missing')
        if temp.is_symlink() or temp.stat().st_size != info['size'] or digest(temp) != info['sha256']:
            raise ValueError('Upload checksum or size mismatch; destination was not replaced')
        with temp.open('r+b') as f:
            os.fsync(f.fileno())
        os.chmod(str(temp), info['mode'])
        if target.is_symlink():
            raise ValueError('Refusing to replace a symlink')
        if info['overwrite']:
            os.replace(str(temp), str(target))
        else:
            os.link(str(temp), str(target))
            temp.unlink()
        return {'path': str(target), 'size': info['size'], 'sha256': info['sha256'], 'complete': True}
    raise ValueError('Unknown operation: ' + op)


def emit(value):
    raw = json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    # Frames contain no control characters or arbitrary command output.
    frame = PREFIX + base64.b64encode(raw).decode('ascii') + '@END@'
    sys.stdout.write('\r\n' + frame + '\r\n')
    sys.stdout.flush()


def serve():
    os.umask(0o077)
    (ROOT / 'jobs').mkdir(exist_ok=True)
    (ROOT / 'uploads').mkdir(exist_ok=True)
    emit({'id': 'hello', 'ok': True, 'result': handle({'op': 'ping'})})
    for line in sys.stdin.buffer:
        request_id = None
        try:
            req = json.loads(line)
            request_id = req['id']
            emit({'id': request_id, 'ok': True, 'result': handle(req)})
        except BaseException as exc:
            emit({'id': request_id, 'ok': False, 'error': type(exc).__name__ + ': ' + str(exc)})


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'job':
        job_worker(sys.argv[2])
    else:
        serve()
