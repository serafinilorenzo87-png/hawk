"""_sha256_file powers the DOWNLOAD button's integrity line (E-01 / CWE-494).

The Potato picker's DOWNLOAD button curls three prebuilt .exe
(JuicyPotato / PrintSpoofer / GodPotato) off GitHub.  Those binaries run
target-side (Windows privesc, same profile as PEAS/pspy), so per E-01 the
integrity check scales with the place of execution: the download worker
shows the file's SHA-256 as informational transparency, never a
fail-closed gate.  The hashing is factored into the pure, GUI-free
_sha256_file() so it is verifiable headless here.

ctk-stubbed so this RUNS without a display / real customtkinter -- the
gui import only pulls customtkinter in, no widget is built.
"""

import hashlib
import os
import sys
import tempfile
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


class Sha256FileHelperTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        from gui import dialogs_privesc as dp   # import after stub install
        self._dp = dp

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def _write(self, data):
        fd, path = tempfile.mkstemp(prefix="hawk_sha_")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        except Exception:
            os.close(fd)
            raise
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_known_vector_abc(self):
        path = self._write(b"abc")
        self.assertEqual(
            self._dp._sha256_file(path),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_known_vector_empty(self):
        path = self._write(b"")
        self.assertEqual(
            self._dp._sha256_file(path),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_spans_multiple_read_chunks(self):
        # Larger than the 65536-byte chunk so the iter(read, b"") loop runs
        # several times; the chunked digest must still match a one-shot hash.
        data = b"HAWK-potato-" * 20000     # 240000 bytes, > 3 chunks
        path = self._write(data)
        self.assertEqual(
            self._dp._sha256_file(path),
            hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    unittest.main()
