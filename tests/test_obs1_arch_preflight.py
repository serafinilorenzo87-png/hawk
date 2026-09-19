"""OBS-1 regression: winPEAS Smart Preflight must consume the known arch.

Before the fix, OSFingerprint had no ``arch`` field, so
``_recommend_winpeas_exe_variant`` always fell through to the "any"
variant even when the SMB banner in Target Intel contained "x64".

These tests lock three things:
  * ``from_nmap_output`` extracts arch from SMB banners / NSE OS lines;
  * the fingerprint merge propagates arch;
  * ``_recommend_winpeas_exe_variant`` selects the correct x64/x86 build.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from modules.exploit_suggester import OSFingerprint  # noqa: E402

# Lazy import — dialogs_privesc pulls customtkinter at module level.
_recommend = None

def _get_recommend():
    global _recommend
    if _recommend is None:
        import importlib
        # Stub customtkinter before importing the dialog module.
        import types
        ctk = types.ModuleType("customtkinter")
        ctk.CTkToplevel = type("CTkToplevel", (), {})
        ctk.CTkFrame = type("CTkFrame", (), {})
        ctk.CTkLabel = type("CTkLabel", (), {})
        ctk.CTkButton = type("CTkButton", (), {})
        ctk.CTkScrollableFrame = type("CTkScrollableFrame", (), {})
        ctk.CTkTextbox = type("CTkTextbox", (), {})
        ctk.CTkImage = type("CTkImage", (), {})
        ctk.CTkFont = lambda *a, **kw: None
        sys.modules.setdefault("customtkinter", ctk)
        mod = importlib.import_module("gui.dialogs_privesc")
        _recommend = mod._recommend_winpeas_exe_variant
    return _recommend


# ── Synthetic nmap outputs ─────────────────────────────────────────

_NMAP_SMB_X64 = """\
445/tcp  open  microsoft-ds  Windows Server 2019 Standard 17763 x64
| smb-os-discovery:
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 6.3)
|   Computer name: DC01
"""

_NMAP_SMB_X86 = """\
445/tcp  open  microsoft-ds  Windows XP SP3 x86
| smb-os-discovery:
|   OS: Windows 5.1
"""

_NMAP_NO_ARCH = """\
445/tcp  open  microsoft-ds
| smb-os-discovery:
|   OS: Windows Server 2019 Standard 17763
"""

_NMAP_BANNER_64BIT = """\
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   OS: Windows Server 2016 64-bit
"""


class ArchExtractionTests(unittest.TestCase):
    def test_x64_from_smb_banner(self):
        fp = OSFingerprint.from_nmap_output(_NMAP_SMB_X64.splitlines())
        self.assertEqual(fp.arch, "x64")

    def test_x86_from_smb_banner(self):
        fp = OSFingerprint.from_nmap_output(_NMAP_SMB_X86.splitlines())
        self.assertEqual(fp.arch, "x86")

    def test_no_arch_stays_empty(self):
        fp = OSFingerprint.from_nmap_output(_NMAP_NO_ARCH.splitlines())
        self.assertEqual(fp.arch, "")

    def test_64bit_keyword_from_rdp_banner(self):
        fp = OSFingerprint.from_nmap_output(_NMAP_BANNER_64BIT.splitlines())
        self.assertEqual(fp.arch, "x64")

    def test_arch_field_exists_on_fresh_fingerprint(self):
        fp = OSFingerprint()
        self.assertEqual(fp.arch, "")


class PreflightVariantSelectionTests(unittest.TestCase):
    def test_x64_arch_selects_x64_variant(self):
        fp = OSFingerprint()
        fp.platform = "windows"
        fp.version = "2019"
        fp.os_raw = "Windows Server 2019 Standard 17763"
        fp.arch = "x64"
        rec = _get_recommend()
        variant_id, reason, redirect = rec(fp, [])
        self.assertFalse(redirect)
        self.assertIn("x64", variant_id)

    def test_empty_arch_falls_to_any(self):
        fp = OSFingerprint()
        fp.platform = "windows"
        fp.version = "2019"
        fp.os_raw = "Windows Server 2019 Standard 17763"
        fp.arch = ""
        rec = _get_recommend()
        variant_id, reason, redirect = rec(fp, [])
        self.assertFalse(redirect)
        self.assertIn("any", variant_id)

    def test_legacy_os_still_redirects_to_bat(self):
        fp = OSFingerprint()
        fp.platform = "windows"
        fp.version = "2008 R2"
        fp.os_raw = "Windows Server 2008 R2 Standard 7601"
        fp.arch = "x64"
        rec = _get_recommend()
        variant_id, reason, redirect = rec(fp, [])
        self.assertTrue(redirect,
                        "legacy OS must redirect to .bat regardless of arch")


if __name__ == "__main__":
    unittest.main()
