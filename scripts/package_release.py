"""Build a source/skill archive from an explicit public-file allowlist."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=root.parent / 'persistent-ssh.zip')
    args = parser.parse_args()
    names = ['SKILL.md', 'README.md', 'README.zh-CN.md', 'LICENSE', 'SECURITY.md', 'CONTRIBUTING.md', '.gitignore', '.gitattributes']
    files = [root / name for name in names]
    for section in ('scripts', 'agents', 'docs', 'examples', 'tests', '.github'):
        for path in (root / section).rglob('*'):
            if path.is_file() and not path.is_symlink() and '__pycache__' not in path.parts:
                if path.suffix in ('.py', '.ps1', '.md', '.json', '.yaml', '.yml'):
                    files.append(path)
    files = sorted(set(files))
    for path in files:
        if not path.is_file() or path.is_symlink():
            raise ValueError('Missing or unsafe public file: ' + str(path))
        data = path.read_bytes()
        markers = [b'-----BEGIN ' + kind + b' PRIVATE KEY-----' for kind in (b'OPENSSH', b'RSA')]
        if any(marker in data for marker in markers):
            raise ValueError('Private key material found')
    target = args.output.resolve()
    if target in (path.resolve() for path in files):
        raise ValueError('Archive must not replace a source file')
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, 'persistent-ssh/' + path.relative_to(root).as_posix())
    print(json.dumps({'archive': str(target), 'files': len(files),
                      'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}, indent=2))


if __name__ == '__main__':
    main()
