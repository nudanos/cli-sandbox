# Copyright (c) 2026, NuDanOS contributors.
#
# SPDX-License-Identifier: LGPL-2.1-only

import os
import tempfile
import unittest

from shared_storage import SharedStorage


class TestLoad(unittest.TestCase):
    def make(self):
        ss = SharedStorage()
        ss.add_mount('/shared/data', 'rw', '/var/lib/shared/data.img', 100,
                     False)
        ss.add_dir('/var/log/user', 'r')
        return ss

    def test_write_then_load(self):
        """What write() stores, load() reads back (yaml.load without a
        Loader is a TypeError in PyYAML 6)"""
        with tempfile.TemporaryDirectory() as tmp:
            conf = os.path.join(tmp, 'shared_storage.conf')
            self.make().write(conf)
            loaded = SharedStorage()
            loaded.load(conf_file=conf)
        self.assertEqual(loaded.mounts, self.make().mounts)
        self.assertEqual(loaded.dirs, self.make().dirs)

    def test_load_stream(self):
        loaded = SharedStorage()
        loaded.load(stream=self.make().dump())
        self.assertEqual(loaded.dirs, {'/var/log/user': {'perm': 'r'}})

    def test_load_missing_file(self):
        loaded = SharedStorage()
        loaded.load(conf_file='/nonexistent/shared_storage.conf')
        self.assertEqual((loaded.mounts, loaded.dirs), ({}, {}))


if __name__ == '__main__':
    unittest.main()
