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


POLICY_DESCRIPTION = ('Da 8 a 128 caratteri, con almeno una lettera maiuscola, '
                      'una minuscola e un numero. I simboli sono facoltativi.')


def password_error(password):
    """Return Italian rejection message, or None when acceptable."""
    if not isinstance(password, str) or len(password) < 8 or len(password) > 128:
        return 'La password deve contenere da 8 a 128 caratteri.'
    if len(password.encode('utf-8')) > 256:
        return 'La password supera il limite di 256 byte UTF-8.'
    if password != password.strip() or any(ord(c) < 32 or ord(c) == 127 for c in password):
        return 'La password non può iniziare o finire con spazi né contenere caratteri di controllo.'
    if not re.search('[A-Z]', password):
        return 'La password deve contenere almeno una lettera maiuscola (A-Z).'
    if not re.search('[a-z]', password):
        return 'La password deve contenere almeno una lettera minuscola (a-z).'
    if not re.search('[0-9]', password):
        return 'La password deve contenere almeno un numero (0-9).'
    return None


def change_linux_root_password():
    """Interactively change root via chpasswd stdin, never command-line args."""
    if os.geteuid() != 0 or not os.isatty(0):
        sys.exit('ERRORE: cambiare root soltanto da una sessione SSH interattiva come root.')
    executable = shutil.which('chpasswd')
    if not executable:
        sys.exit('ERRORE: chpasswd non disponibile; password Linux non modificata.')
    print('Regole password Linux: ' + POLICY_DESCRIPTION)
    print('La password non verrà mostrata e non sarà condivisa con la Web UI.')
    for _ in range(3):
        try:
            first = getpass.getpass('Nuova password Linux root: ')
            second = getpass.getpass('Conferma password Linux root: ')
        except (EOFError, KeyboardInterrupt):
            sys.exit('\nAnnullato: password Linux non modificata.')
        if first != second:
            print('Le password non corrispondono. Riprova.')
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
            sys.exit('ERRORE: impossibile applicare la password Linux. Verificare il sistema.')
        if result.returncode != 0:
            sys.exit('ERRORE: chpasswd ha rifiutato il cambio della password Linux. Verificare PAM.')
        print('Password Linux root aggiornata correttamente.')
        return
    sys.exit('Troppi tentativi: password Linux non modificata.')


if __name__ == '__main__':
    if sys.argv[1:] == ['--set-linux-root']:
        change_linux_root_password()
    else:
        sys.exit('Uso: python3 password_policy.py --set-linux-root')
