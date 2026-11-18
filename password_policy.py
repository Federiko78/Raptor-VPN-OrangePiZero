#!/usr/bin/env python3
"""Common password policy for the Orange Pi Factory installer and Web UI.

This file never writes, displays, or logs a cleartext password. The Linux root
password is only changed when the operator explicitly requests it over a TTY.
"""
import getpass
import os
import re
import shutil
import subprocess
import sys


MIN_LENGTH = 12
MAX_LENGTH = 128

POLICY_DESCRIPTION = ('From %d to %d characters, with at least one uppercase letter, '
                      'one lowercase letter and one number. Symbols are optional.' % (MIN_LENGTH, MAX_LENGTH))


def password_error(password):
    """Return Italian rejection message, or None when acceptable.

    The policy applies only when a password is set or changed: an existing
    shorter password keeps working until it is changed.
    """
    if not isinstance(password, str) or len(password) < MIN_LENGTH or len(password) > MAX_LENGTH:
        return 'The password must contain from %d to %d characters.' % (MIN_LENGTH, MAX_LENGTH)
    if len(password.encode('utf-8')) > 256:
        return 'The password exceeds the 256-byte UTF-8 limit.'
    if password != password.strip() or any(ord(c) < 32 or ord(c) == 127 for c in password):
        return 'The password cannot start or end with spaces or contain control characters.'
    if not re.search('[A-Z]', password):
        return 'The password must contain at least one uppercase letter (A-Z).'
    if not re.search('[a-z]', password):
        return 'The password must contain at least one lowercase letter (a-z).'
    if not re.search('[0-9]', password):
        return 'The password must contain at least one number (0-9).'
    return None


def change_linux_root_password():
    """Interactively change root via chpasswd stdin, never command-line args."""
    if os.geteuid() != 0 or not os.isatty(0):
        sys.exit('ERROR: change the root password only from an interactive SSH session as root.')
    executable = shutil.which('chpasswd')
    if not executable:
        sys.exit('ERROR: chpasswd not available; Linux password unchanged.')
    print('Linux password rules: ' + POLICY_DESCRIPTION)
    print('The password will not be displayed and is not shared with the Web UI.')
    for _ in range(3):
        try:
            first = getpass.getpass('New Linux root password: ')
            second = getpass.getpass('Confirm Linux root password: ')
        except (EOFError, KeyboardInterrupt):
            sys.exit('\nCancelled: Linux password unchanged.')
        if first != second:
            print('The passwords do not match. Try again.')
            continue
        error = password_error(first)
        if error:
            print(error)
            continue
        try:
            result = subprocess.run([executable], input=('root:' + first + '\n').encode('utf-8'),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                    timeout=20, check=False)
        except (OSError, subprocess.TimeoutExpired):
            sys.exit('ERROR: unable to apply the Linux password. Check the system.')
        if result.returncode != 0:
            sys.exit('ERROR: chpasswd refused the Linux password change. Check PAM.')
        print('Password Linux root aggiornata correttamente.')
        return
    sys.exit('Too many attempts: Linux password unchanged.')


if __name__ == '__main__':
    if sys.argv[1:] == ['--set-linux-root']:
        change_linux_root_password()
    else:
        sys.exit('Uso: python3 password_policy.py --set-linux-root')
