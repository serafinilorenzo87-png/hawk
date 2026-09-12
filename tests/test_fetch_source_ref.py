r"""FETCH SOURCE path extraction (_extract_source_ref).

The Info-dialog "FETCH SOURCE" button fetches a web source referenced by
a finding.  Its extractor matched any path ending in a web-ish extension
(.js/.json/.txt/...), so a finding whose "Next steps" quoted a local
command example — e.g. `hydra -P /usr/share/wordlists/rockyou.txt` —
handed FETCH SOURCE a Kali filesystem path.  It then built
http://target/usr/share/wordlists/rockyou.txt and 404'd.

The extractor now skips local-filesystem / instructional path prefixes
(/usr, /etc, /var, ...) while still returning genuine web sources.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class _DummyCtk:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, _n):
        return _DummyCtk

    def __call__(self, *a, **k):
        return _DummyCtk()


def _install_customtkinter_stub():
    module = types.ModuleType("customtkinter")
    for name in (
        "CTkFrame", "CTkFont", "CTkButton", "CTkLabel", "CTkEntry",
        "CTkTextbox", "CTkToplevel", "CTkScrollableFrame", "CTkOptionMenu",
        "CTkCheckBox", "CTkRadioButton", "CTkProgressBar", "CTkTabview",
        "CTkSwitch", "StringVar", "BooleanVar", "IntVar",
    ):
        setattr(module, name, _DummyCtk)
    sys.modules["customtkinter"] = module


class ExtractSourceRefTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        from gui.widgets.target_intel_render import TargetIntelRenderMixin

        class _R(TargetIntelRenderMixin):
            pass

        self.r = _R()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_local_wordlist_path_is_not_a_source(self):
        # The exact RPCCLIENT "Next steps" line that caused the 404.
        blob = ("Next steps:\n"
                "  $ hydra -L users.txt -P "
                "/usr/share/wordlists/rockyou.txt ssh://192.168.176.177")
        self.assertIsNone(self.r._extract_source_ref(blob))

    def test_other_local_prefixes_are_skipped(self):
        for p in ("/etc/passwd.txt", "/var/log/app.txt",
                  "/opt/tool/data.json", "/home/kali/notes.txt"):
            self.assertIsNone(self.r._extract_source_ref(f"see {p}"), p)

    def test_real_web_source_with_line_is_extracted(self):
        blob = "JS secret hit — Found in: /assets/app.min.js:562"
        self.assertEqual(("/assets/app.min.js", 562),
                         self.r._extract_source_ref(blob))

    def test_bare_web_txt_still_extracted(self):
        # A genuine web file (robots.txt) is NOT a local prefix.
        self.assertEqual(("/robots.txt", None),
                         self.r._extract_source_ref("exposed /robots.txt"))


if __name__ == "__main__":
    unittest.main()
