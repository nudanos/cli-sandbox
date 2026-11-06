# SPDX-License-Identifier: GPL-2.0-only

import os
from pathlib import Path
import pwd
import runpy
import sys
import sysconfig
import tempfile
import types
import unittest
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[1]


class TestNspawnSettings(unittest.TestCase):
    def test_bind_password_module_only_for_older_roots(self):
        vyatta = types.ModuleType('vyatta')
        vyatta.__path__ = [str(REPO / 'lib')]
        with patch.dict(sys.modules, {'vyatta': vyatta}):
            sandbox_class = runpy.run_path(str(REPO / 'scripts/cli-sandbox'))['UserSandBox']

        multiarch = sysconfig.get_config_var('MULTIARCH') or ''
        module = Path('/usr/lib') / multiarch / 'security/pam_vyatta_passwd.so'
        with tempfile.TemporaryDirectory() as work:
            workspace = Path(work)
            root = workspace / 'root'
            sandbox_class.conf.update({
                'DISTDIR': str(root),
                'RUNDIR': str(workspace),
                'NSPAWN_TEMPLATE': str(REPO / 'conf/cli_sandbox.nspawn'),
                'SETTINGS_DIR': str(workspace / 'nspawn'),
                'MOVED_MOUNTS': [],
            })
            sandbox = sandbox_class(pwd.getpwuid(os.getuid()).pw_name)
            settings = Path(sandbox.settings)
            sandbox.edit_nspawn_template()
            self.assertIn(f'BindReadOnly={module}\n', settings.read_text())

            installed_module = root / str(module).lstrip('/')
            installed_module.parent.mkdir(parents=True)
            installed_module.touch()
            sandbox.edit_nspawn_template()
            self.assertNotIn('pam_vyatta_passwd.so', settings.read_text())
