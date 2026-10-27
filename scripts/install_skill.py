"""Install the complete skill without credentials or starting any service."""
import argparse
import os
from pathlib import Path
import shutil


def main():
    source = Path(__file__).resolve().parents[1]
    default = Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')) / 'skills' / 'persistent-ssh'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, default=default)
    parser.add_argument('--replace', action='store_true', help='Replace package files in an existing installation; first coordinate any active brokers')
    args = parser.parse_args()
    target = args.destination.expanduser().absolute()
    if target.is_symlink():
        raise SystemExit('Refusing to install through a destination symlink')
    target = target.resolve()
    if target == source:
        print('This directory is already the skill source.')
        return
    if target.is_relative_to(source):
        raise SystemExit('Destination must not be inside the source package')
    if target.exists() and not args.replace:
        raise SystemExit('Destination exists. Review active brokers before using --replace.')
    target.mkdir(parents=True, exist_ok=True)
    files = [source / name for name in ('SKILL.md', 'README.md', 'README.zh-CN.md', 'LICENSE', 'SECURITY.md', 'CONTRIBUTING.md', '.gitignore', '.gitattributes')]
    for directory in ('scripts', 'agents', 'docs', 'examples', 'tests', '.github'):
        files.extend(path for path in (source / directory).rglob('*')
                     if path.is_file() and '__pycache__' not in path.parts and not path.is_symlink())
    for path in files:
        destination = target / path.relative_to(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink():
            raise SystemExit('Refusing to overwrite a symlink: ' + str(destination))
        shutil.copy2(path, destination)
    print('Installed persistent-ssh into ' + str(target))
    print('No profile, credential, background service or SSH connection was created.')


if __name__ == '__main__':
    main()
