"""Transcript paths are POSIX no matter what OS sessionxray runs on. This guards
against sliding back to os.path, which on Windows rewrites /etc/hosts to
\\etc\\hosts and quietly breaks every sensitive-path and dev-null check."""

from __future__ import annotations

import unittest

from sessionxray.discovery import NO_HOME
from sessionxray.rules._util import is_under, normalize_path
from sessionxray.rules.filesystem import _DEV_NOISE, _is_sensitive


class PosixPaths(unittest.TestCase):
    def test_normalize_never_emits_a_backslash(self):
        for raw in ("/etc/hosts", "/dev/null", "~/.ssh/id_rsa", "sub/dir/file"):
            out = normalize_path(raw, "/home/u/app", "/home/u")
            self.assertNotIn("\\", out or "", raw)
            self.assertTrue((out or "").startswith("/"), raw)

    def test_sensitive_absolute_path_recognized(self):
        self.assertTrue(_is_sensitive(normalize_path("/etc/hosts", "/home/u/app", "/home/u")))

    def test_sensitive_prefix_needs_a_whole_component(self):
        # "/etc" must not swallow "/etcetera", and "/root" must not swallow
        # "/rootkit-scanner" -- a plain startswith() matched both.
        self.assertFalse(_is_sensitive("/etcetera/notes.md"))
        self.assertFalse(_is_sensitive("/rootkit-scanner/log.txt"))
        self.assertTrue(_is_sensitive("/root/notes.md"))

    def test_ssh_suffix_recognized_after_home_expansion(self):
        out = normalize_path("~/.ssh/id_rsa", "/home/u/app", "/home/u")
        self.assertIn("/.ssh", out)
        self.assertTrue(_is_sensitive(out))

    def test_unknown_home_is_not_a_sensitive_directory(self):
        # When the transcript never says where home was, `~/notes.md` has to
        # land somewhere harmless. The old fallback was /root, which made every
        # home-relative read on a Windows analyst machine look sensitive.
        out = normalize_path("~/notes.md", "/home/u/app", NO_HOME)
        self.assertFalse(_is_sensitive(out), out)

    def test_dev_null_is_noise(self):
        self.assertIn(normalize_path("/dev/null", "/home/u/app", "/home/u"), _DEV_NOISE)

    def test_under_root_uses_forward_slash(self):
        self.assertTrue(is_under("/home/u/app/src/x.py", "/home/u/app"))
        self.assertFalse(is_under("/home/u/app-other/x.py", "/home/u/app"))
