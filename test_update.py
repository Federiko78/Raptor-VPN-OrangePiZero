#!/usr/bin/env python3
"""Test di update.sh con un "origin" locale e installer finti (copia superficiale, ramo senza upstream)."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

DIR = pathlib.Path(__file__).resolve().parent
ENV = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@t')
STUBS = ('install_tailscale_panel.sh', 'install_eventlog.sh', 'install_access.sh', 'check_installation.sh')


def sh(*args, cwd, check=True):
    return subprocess.run(args, cwd=cwd, env=ENV, check=check, capture_output=True, text=True)


@unittest.skipUnless(os.geteuid() == 0, 'update.sh richiede root')
class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.origin = self.root / 'origin.git'
        sh('git', 'init', '-q', '--bare', str(self.origin), cwd=self.root)
        self.work = self.root / 'work'
        sh('git', 'clone', '-q', str(self.origin), str(self.work), cwd=self.root)
        text = (DIR / 'update.sh').read_text()
        # percorso dell'helper di rete: file finto dentro la prova
        (self.work / 'netstub').write_text('')
        os.chmod(self.work / 'netstub', 0o755)
        (self.work / 'update.sh').write_text(text.replace('/usr/local/libexec/tailscale-panel-net-helper', str(self.root / 'pi' / 'netstub')))
        for name in STUBS:
            (self.work / name).write_text('echo "[%s eseguito]"\n' % name)
        self.release('v1', 'main')
        sh('git', 'clone', '-q', '--depth', '1', '--branch', 'main', 'file://' + str(self.origin), str(self.root / 'pi'), cwd=self.root)
        self.pi = self.root / 'pi'

    def release(self, version, branch):
        (self.work / 'VERSION').write_text(version + '\n')
        files = ['VERSION', 'update.sh', 'netstub'] + list(STUBS)
        sums = sh('sha256sum', *files, cwd=self.work).stdout
        (self.work / 'SHA256SUMS').write_text(sums)
        if sh('git', 'rev-parse', '--verify', '-q', branch, cwd=self.work, check=False).returncode:
            sh('git', 'checkout', '-q', '-b', branch, cwd=self.work)
        else:
            sh('git', 'checkout', '-q', branch, cwd=self.work)
        sh('git', 'add', '-A', cwd=self.work)
        sh('git', 'commit', '-q', '-m', version, cwd=self.work)
        sh('git', 'push', '-q', 'origin', branch, cwd=self.work)

    def update(self):
        return sh('sh', './update.sh', cwd=self.pi, check=False)

    def test_branch_made_with_checkout_fetch_head_has_no_upstream_and_still_updates(self):
        self.release('v2', 'grafica')
        sh('git', 'fetch', '-q', '--depth', '1', 'origin', 'grafica', cwd=self.pi)
        sh('git', 'checkout', '-q', '-B', 'grafica', 'FETCH_HEAD', cwd=self.pi)
        self.release('v3', 'grafica')
        done = self.update()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual((self.pi / 'VERSION').read_text().strip(), 'v3')
        self.assertIn('[install_tailscale_panel.sh eseguito]', done.stdout)
        self.assertIn('[install_eventlog.sh eseguito]', done.stdout)

    def test_final_check_is_not_the_fresh_board_one(self):
        # --fresh pretende la policy iniziale (LAN spenta, zero host): su una scheda in servizio e' un falso errore.
        (self.work / 'check_installation.sh').write_text('echo "VERIFICA args=[$*]"\n')
        self.release('v2', 'main')
        done = self.update()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('VERIFICA args=[]', done.stdout)

    def test_normal_shallow_clone_updates(self):
        self.release('v2', 'main')
        self.assertEqual(self.update().returncode, 0)
        self.assertEqual((self.pi / 'VERSION').read_text().strip(), 'v2')

    def test_hand_edited_files_are_refused_and_untouched(self):
        self.release('v2', 'main')
        (self.pi / 'VERSION').write_text('manomesso\n')
        done = self.update()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('modificati a mano', done.stdout + done.stderr)
        self.assertEqual((self.pi / 'VERSION').read_text().strip(), 'manomesso')
        self.assertNotIn('eseguito', done.stdout)

    def test_missing_remote_branch_stops_before_installing(self):
        sh('git', 'checkout', '-q', '-b', 'fantasma', cwd=self.pi)
        done = self.update()
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn('eseguito', done.stdout)

    def test_damaged_checksum_stops_before_installing(self):
        (self.work / 'VERSION').write_text('v2\n')
        sh('git', 'add', '-A', cwd=self.work)       # VERSION cambia, SHA256SUMS no
        sh('git', 'commit', '-q', '-m', 'sums vecchi', cwd=self.work)
        sh('git', 'push', '-q', 'origin', 'main', cwd=self.work)
        done = self.update()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('SHA256', done.stdout + done.stderr)
        self.assertNotIn('eseguito', done.stdout)


if __name__ == '__main__':
    unittest.main()
