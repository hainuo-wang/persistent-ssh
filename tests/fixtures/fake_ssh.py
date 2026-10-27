#!/usr/bin/env python3
"""Offline SSH-shaped fixture: synthetic password/OTP, then a real local helper."""
import getpass
import os
import shlex
import sys

password = getpass.getpass('Password: ', stream=sys.stdout)
if password != 'fixture-password':
    sys.exit(2)
code = getpass.getpass('Verification code: ', stream=sys.stdout)
if code != 'fixture-otp':
    sys.exit(3)
sys.stdout.write('fixture@localhost:~$ ')
sys.stdout.flush()
command = ''
for line in sys.stdin:
    command += line
    try:
        shlex.split(command)
    except ValueError:
        continue
    break
if not command.startswith('stty raw -echo; exec '):
    sys.exit(4)
# The fixture's standard input is already a raw pipe, unlike a remote SSH PTY.
command = command[len('stty raw -echo; '):]
os.execl('/bin/sh', 'sh', '-c', command)
