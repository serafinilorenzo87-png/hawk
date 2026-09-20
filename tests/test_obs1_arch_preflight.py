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

# No explicit arch token AND a genuinely ambiguous edition — Windows 10 client
# shipped in both x86 and x64, so neither the token scan nor the x64-only-Server
# inference may fire.  (A Server 2019 banner here would now correctly infer x64,
# so it can no longer stand for "no arch signal".)
_NMAP_NO_ARCH = """\
445/tcp  open  microsoft-ds
| smb-os-discovery:
|   OS: Windows 10 Pro 19041 (Windows 10 Pro 10.0)
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


# ── x64-only Windows Server inference (OBS-1 live) ─────────────────
# nmap never prints an arch token for native Windows, so on a real 2008 R2
# DC arch stayed '' and the preflight showed <unknown>.  Server 2008 R2 and
# every later Server are x64-only, so infer x64 from the edition — but keep
# plain 2008 / Windows 7 (which shipped x86 too) unknown.  These samples carry
# NO explicit x64/x86 token: the inference is the only thing that can set arch.

_NMAP_2008R2 = """\
445/tcp  open  microsoft-ds  Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds
| smb-os-discovery:
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   Computer name: VAGRANT-2008R2
"""

_NMAP_2008_PLAIN = """\
445/tcp  open  microsoft-ds  Windows Server 2008 Standard 6002 Service Pack 2 microsoft-ds
| smb-os-discovery:
|   OS: Windows Server 2008 Standard 6002 Service Pack 2 (Windows Server 2008 Standard 6.0)
|   Computer name: SRV2008
"""

_NMAP_WIN7 = """\
445/tcp  open  microsoft-ds  Windows 7 Professional 7601 Service Pack 1 microsoft-ds
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   Computer name: WS01
"""

_NMAP_2016 = """\
445/tcp  open  microsoft-ds  Windows Server 2016 Standard 14393 microsoft-ds
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 10.0)
|   Computer name: DC16
"""

_NMAP_2019 = """\
445/tcp  open  microsoft-ds  Windows Server 2019 Standard 17763 microsoft-ds
| smb-os-discovery:
|   OS: Windows Server 2019 Standard 17763 (Windows Server 2019 Standard 10.0)
|   Computer name: DC19
"""

_NMAP_2022 = """\
445/tcp  open  microsoft-ds  Windows Server 2022 Standard 20348 microsoft-ds
| smb-os-discovery:
|   OS: Windows Server 2022 Standard 20348 (Windows Server 2022 Standard 10.0)
|   Computer name: DC22
"""


class ArchInferenceX64OnlyServerTests(unittest.TestCase):
    """Infer x64 from x64-only Windows Server editions when nmap gave no
    explicit arch token (the real 2008 R2 DC case that <unknown>ed OBS-1)."""

    def _arch(self, nmap):
        return OSFingerprint.from_nmap_output(nmap.splitlines()).arch

    def test_2008r2_infers_x64(self):
        self.assertEqual(self._arch(_NMAP_2008R2), "x64")

    def test_plain_2008_stays_unknown(self):
        # Server 2008 (non-R2) shipped in x86 too — must NOT be inferred.
        self.assertEqual(self._arch(_NMAP_2008_PLAIN), "")

    def test_win7_client_stays_unknown(self):
        # Client Windows 7 shipped x86 and x64 — genuinely ambiguous.
        self.assertEqual(self._arch(_NMAP_WIN7), "")

    def test_2016_infers_x64(self):
        self.assertEqual(self._arch(_NMAP_2016), "x64")

    def test_2019_infers_x64(self):
        self.assertEqual(self._arch(_NMAP_2019), "x64")

    def test_2022_infers_x64(self):
        self.assertEqual(self._arch(_NMAP_2022), "x64")

    def test_explicit_token_takes_precedence_over_inference(self):
        # An explicit x86 token wins over the server inference (the guard is
        # `if not fp.arch`), so a hypothetical x86 build is not mislabeled x64.
        nmap = ("445/tcp open microsoft-ds Windows Server 2016 Standard "
                "14393 x86 microsoft-ds\n"
                "| smb-os-discovery:\n"
                "|   OS: Windows Server 2016 Standard 14393 x86\n")
        self.assertEqual(self._arch(nmap), "x86")


class ArchRoundTripPersistenceTests(unittest.TestCase):
    """arch must survive a session save/reload (to_dict → from_dict) like every
    other fingerprint field — otherwise the preflight reverts to <unknown> on
    reload until the user re-scans (OBS-1 persistence gap found live)."""

    def test_to_dict_includes_arch(self):
        fp = OSFingerprint()
        fp.arch = "x86"
        self.assertEqual(fp.to_dict().get("arch"), "x86")

    def test_x64_survives_round_trip(self):
        fp = OSFingerprint()
        fp.platform = "windows"
        fp.version = "2008 R2 SP1"
        fp.arch = "x64"
        fp2 = OSFingerprint.from_dict(fp.to_dict())
        self.assertEqual(fp2.arch, "x64")

    def test_legacy_session_without_arch_key_loads_empty(self):
        # A session saved before OBS-1 has no 'arch' key: load as '' (not crash).
        fp = OSFingerprint.from_dict({"platform": "windows",
                                      "version": "2008 R2 SP1"})
        self.assertEqual(fp.arch, "")


if __name__ == "__main__":
    unittest.main()
