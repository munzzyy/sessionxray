"""Transcript paths are POSIX no matter what OS sessionxray runs on. This guards
against sliding back to os.path, which on Windows rewrites /etc/hosts to
\\etc\\hosts and quietly breaks every sensitive-path and dev-null check."""

from __future__ import annotations

import unittest

from sessionxray.rules.filesystem import _DEV_NOISE, _is_sensitive, _is_under, _normalize


class PosixPaths(unittest.TestCase):
    def test_normalize_never_emits_a_backslash(self):
        for raw in ("/etc/hosts", "/dev/null", "~/.ssh/id_rsa", "sub/dir/file"):
            out = _normalize(raw, "/home/u/app")
            self.assertNotIn("\\", out or "", raw)
            self.assertTrue((out or "").startswith("/"), raw)

    def test_sensitive_absolute_path_recognized(self):
        self.assertTrue(_is_sensitive(_normalize("/etc/hosts", "/home/u/app")))

    def test_ssh_suffix_recognized_after_home_expansion(self):
        out = _normalize("~/.ssh/id_rsa", "/home/u/app")
        self.assertIn("/.ssh", out)
        self.assertTrue(_is_sensitive(out))

    def test_dev_null_is_noise(self):
        self.assertIn(_normalize("/dev/null", "/home/u/app"), _DEV_NOISE)

    def test_under_root_uses_forward_slash(self):
        self.assertTrue(_is_under("/home/u/app/src/x.py", "/home/u/app"))
        self.assertFalse(_is_under("/home/u/app-other/x.py", "/home/u/app"))
