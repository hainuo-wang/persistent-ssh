"""Public, non-secret profile settings and private local runtime state."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time

DEFAULT_AUTH = {
    'prompt_pattern': r'(?im)(?:(?:password|passphrase|verification code|otp|token|response|choice)[^\r\n]{0,160}[:?>][ \t]*$|press enter[^\r\n]{0,160}$)',
    'url_pattern': r'https://[^\s<>"\x27]+',
    'shell_prompt_pattern': r'(?:^|[\r\n])[^\r\n]{0,220}[#$>] ?$',
    'confirm_empty_prompts': [],
}


def profile_name(value):
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,47}', value):
        raise ValueError('Profile must start with a lowercase letter and use at most 48 letters, digits or hyphens')
    return value


def default_root():
    if os.name == 'nt':
        return Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local')) / 'PersistentSSH'
    return Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local' / 'state')) / 'persistent-ssh'


def default_runtime(name='default'):
    return default_root() / profile_name(name)


def atomic_json(path, value):
    # Unique staging names prevent concurrent CLI clients sharing a .new file.
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
        for attempt in range(8):
            try:
                os.replace(temporary, path)
                break
            except PermissionError as exc:
                # Windows can temporarily deny replacement while another writer
                # or scanner holds the destination. Retry the same metadata only.
                if os.name != 'nt' or getattr(exc, 'winerror', None) not in (5, 32) or attempt == 7:
                    raise
                time.sleep(0.01 * (attempt + 1))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def settings_valid(settings):
    allowed = {'auth', 'transport', 'remote_python', 'ssh_executable', 'ssh_config'}
    if set(settings) - allowed:
        raise ValueError('Unknown settings: ' + ', '.join(sorted(set(settings) - allowed)))
    auth = dict(DEFAULT_AUTH)
    supplied = settings.get('auth', {})
    if not isinstance(supplied, dict) or set(supplied) - set(auth):
        raise ValueError('Unknown authentication settings; passwords and OTPs must not be stored')
    auth.update(supplied)
    for key in ('prompt_pattern', 'url_pattern', 'shell_prompt_pattern'):
        if not isinstance(auth[key], str) or len(auth[key]) > 1024:
            raise ValueError('Invalid authentication pattern')
        re.compile(auth[key])
    rules = auth['confirm_empty_prompts']
    if not isinstance(rules, list) or len(rules) > 6:
        raise ValueError('At most six explicit empty-response prompt patterns are supported')
    for rule in rules:
        if not isinstance(rule, str) or not rule or len(rule) > 512:
            raise ValueError('Invalid empty-response prompt pattern')
        re.compile(rule)
    transport = settings.get('transport', 'shell')
    if transport not in ('shell', 'exec'):
        raise ValueError('transport must be shell or exec')
    remote_python = settings.get('remote_python', 'python3')
    if not isinstance(remote_python, str) or not remote_python or any(c in remote_python for c in '\x00\r\n'):
        raise ValueError('remote_python must be a single executable path/name')
    result = dict(settings, auth=auth, transport=transport, remote_python=remote_python)
    for key in ('ssh_executable', 'ssh_config'):
        if key in result:
            path = Path(result[key]).expanduser().resolve(strict=True)
            if not path.is_file():
                raise ValueError(key + ' must name a file')
            result[key] = str(path)
    return result


def initialize(runtime, name, host, settings=None):
    name = profile_name(name)
    if not host or host.startswith('-') or len(host) > 512 or re.search(r'[\s\x00]', host):
        raise ValueError('Use one SSH config alias or user@hostname, without options or whitespace')
    settings = settings_valid(settings or {})
    if runtime.is_symlink():
        raise ValueError('Runtime must not be a symlink')
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (runtime / 'config.json').exists():
        raise FileExistsError('Profile already exists; reuse it or choose another profile name')
    if os.name == 'nt':
        identity = subprocess.check_output(['whoami', '/user', '/fo', 'csv', '/nh']).decode(errors='replace')
        sid = re.search(r'S-1-[0-9-]+', identity).group(0)
        subprocess.run(['icacls', str(runtime), '/inheritance:r', '/grant:r', '*' + sid + ':(OI)(CI)F'],
                       check=True, stdout=subprocess.DEVNULL)
        owner = sid
    else:
        if runtime.stat().st_uid != os.getuid():
            raise PermissionError('Runtime belongs to another user')
        os.chmod(runtime, 0o700)
        owner = str(os.getuid())
    namespace = hashlib.sha256((owner + str(runtime.resolve())).encode()).hexdigest()[:20]
    endpoint = (r'\\.\pipe\persistent-ssh-' + namespace) if os.name == 'nt' else str(runtime / 'control.sock')
    if os.name != 'nt' and len(os.fsencode(endpoint)) >= 100:
        raise ValueError('Runtime path too long for a Unix socket; use --runtime with a shorter private directory')
    key = runtime / 'auth.key'
    if key.is_symlink():
        raise ValueError('Control key must not be a symlink')
    with key.open('xb') as stream:
        stream.write(secrets.token_bytes(32))
    if os.name != 'nt':
        os.chmod(key, 0o600)
    config = dict(settings, protocol=1, profile=name, namespace=namespace, ssh_alias=host,
                  endpoint=endpoint, family='AF_PIPE' if os.name == 'nt' else 'AF_UNIX',
                  task_name='PersistentSSH-' + namespace)
    atomic_json(runtime / 'config.json', config)
    return {'profile': name, 'ssh_alias': host, 'runtime': str(runtime), 'initialized': True}


def load(runtime):
    if runtime.is_symlink() or (runtime / 'auth.key').is_symlink():
        raise ValueError('Runtime and control key must not be symlinks')
    if os.name != 'nt':
        if runtime.stat().st_uid != os.getuid() or runtime.stat().st_mode & 0o077:
            raise PermissionError('Runtime must be owned by you with mode 0700')
    config = json.loads((runtime / 'config.json').read_text(encoding='utf-8'))
    if config.get('protocol') != 1:
        raise ValueError('Unsupported profile format')
    return config
