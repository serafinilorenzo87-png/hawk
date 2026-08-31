r"""METASPLOIT card review fixes (MS2, live pass 2026-08-30).

Covered here (the picker OS/service-aware fix and the msf_index keyword
cache land in their own follow-up):

  * msfdb auto-start — the base METASPLOIT card only printed DB *hints*;
    it now ensures the database is up before launching msfconsole
    (starts it only when postgres isn't already running, so no needless
    sudo prompt).
  * bg-capture orphan-safety — the read-only msfconsole mirror was a bare
    Popen read via for-line-in-stdout with no process group / timeout and
    a kill() that signals nothing, so a wedged msfconsole orphaned. Now it
    runs in its own setsid group with a watchdog that killpg's it.
  * RC filename — used a second-granularity int timestamp, so two launches
    in the same second collided (one xterm's `rm -f` could delete the
    other's script). Now a unique mkstemp path.
  * payload category — an android fingerprint was mapped to the "Linux
    x86" payload category (which lists no android payloads).

These live on runner/dialog/widget modules that can't import headless, so
they are static source-shape checks.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _method(src, name):
    i = src.index(f"def {name}")
    j = len(src)
    for pat in ("\n    def ", "\nclass "):
        k = src.find(pat, i + 1)
        if k != -1:
            j = min(j, k)
    return src[i:j]


class MsfdbAutostartTests(unittest.TestCase):
    def test_launcher_starts_db_only_if_not_running(self):
        body = _method(_src("gui/widgets/card_routes_scan.py"),
                       "_route_metasploit_launcher")
        self.assertIn("pgrep -x postgres", body)   # cheap up-check, no sudo
        self.assertIn("msfdb start", body)          # start it when down
        self.assertIn("msfconsole", body)


class BgCaptureOrphanSafetyTests(unittest.TestCase):
    def test_bg_capture_has_group_and_watchdog(self):
        body = _method(_src("utils/runner.py"), "_bg_capture")
        # own process group + a watchdog that kills the whole group.
        self.assertIn("preexec_fn=os.setsid", body)
        self.assertIn("threading.Timer", body)
        self.assertIn("killpg", body)


class RcFilenameUniqueTests(unittest.TestCase):
    def test_rc_uses_mkstemp_not_second_timestamp(self):
        src = _src("utils/runner.py")
        self.assertIn("mkstemp(", src)
        self.assertIn('prefix="hawk_msf_"', src)
        # the colliding int-second filename is gone.
        self.assertNotIn('f"hawk_msf_{ts}.rc"', src)


class PayloadCategoryTests(unittest.TestCase):
    def test_android_not_mapped_to_linux_x86(self):
        body = _method(_src("gui/payload_dialog.py"), "_guess_category")
        self.assertIn("android", body)
        # no code path RETURNS the (android-less) Linux x86 category
        # anymore — a comment may still name it.
        self.assertNotIn('return "Linux x86"', body)


class ModuleRankingTests(unittest.TestCase):
    """OS/service-aware ranking (pure function rank_modules_for_target in
    utils.msf_index): on a Linux target the Windows EternalBlue must NOT
    lead over the Samba/multi module, and off-service modules sink by
    port."""

    def setUp(self):
        from utils.msf_index import rank_modules_for_target
        self.rank = rank_modules_for_target

    def test_windows_module_sinks_below_multi_on_linux(self):
        ranked = self.rank([
            ("exploit/windows/smb/ms17_010_eternalblue", "EternalBlue"),
            ("exploit/multi/samba/usermap_script", "Samba usermap"),
        ], platform="linux", port=445)
        self.assertEqual(ranked[0][0],
                         "exploit/multi/samba/usermap_script")

    def test_nix_module_sinks_below_win_on_windows(self):
        ranked = self.rank([
            ("exploit/unix/misc/distcc_exec", "distcc"),
            ("exploit/windows/smb/ms17_010_eternalblue", "EternalBlue"),
        ], platform="windows", port=445)
        self.assertEqual(ranked[0][0],
                         "exploit/windows/smb/ms17_010_eternalblue")

    def test_off_service_module_demoted_by_port(self):
        # HTTP:80 finding — distcc (3632) ranks below an http module.
        ranked = self.rank([
            ("exploit/unix/misc/distcc_exec", "DistCC"),
            ("exploit/multi/http/php_cgi_arg_injection", "php-cgi"),
        ], platform="linux", port=80)
        self.assertEqual(ranked[0][0],
                         "exploit/multi/http/php_cgi_arg_injection")

    def test_exploit_ranks_above_scanner(self):
        ranked = self.rank([
            ("auxiliary/scanner/smb/smb_version", "scanner"),
            ("exploit/multi/samba/usermap_script", "usermap"),
        ], platform="linux", port=445)
        self.assertEqual(ranked[0][0],
                         "exploit/multi/samba/usermap_script")

    def test_service_text_boost_breaks_tie_without_port(self):
        # ENUM4LINUX SMB finding, NO port: samba (named in the text via the
        # smb<->samba alias) leads over tomcat (not named), both multi/*.
        ranked = self.rank([
            ("exploit/multi/http/tomcat_mgr_upload", "Tomcat"),
            ("exploit/multi/samba/usermap_script", "Samba usermap"),
        ], platform="linux", port=None,
            finding_text="ENUM4LINUX on METASPLOITABLE - null session, "
                         "SMB1, no signing")
        self.assertEqual(ranked[0][0],
                         "exploit/multi/samba/usermap_script")

    def test_service_boost_never_rescues_platform_mismatch(self):
        # The SMB finding names smb and EternalBlue's path has "smb", but a
        # Windows exploit on a Linux target must still sink to the bottom.
        ranked = self.rank([
            ("exploit/windows/smb/ms17_010_eternalblue", "EternalBlue"),
            ("exploit/multi/samba/usermap_script", "Samba"),
        ], platform="linux", port=None, finding_text="SMB1 samba enum")
        self.assertEqual(ranked[-1][0],
                         "exploit/windows/smb/ms17_010_eternalblue")

    def test_unknown_platform_preserves_order(self):
        mods = [
            ("exploit/windows/smb/ms17_010_eternalblue", "EB"),
            ("exploit/multi/samba/usermap_script", "Samba"),
        ]
        ranked = self.rank(list(mods), platform="", port=None)
        self.assertEqual([m[0] for m in ranked], [m[0] for m in mods])

    def test_single_module_returned_as_is(self):
        one = [("exploit/windows/smb/ms17_010_eternalblue", "EB")]
        self.assertEqual(
            self.rank(list(one), platform="linux", port=445), one)


class RankingDelegationTests(unittest.TestCase):
    def test_mixin_delegates_to_pure_ranker(self):
        # The widget wrapper pulls platform+port off self and calls the
        # pure ranker; it must not re-implement the scoring.
        src = _src("gui/widgets/target_intel_msf.py")
        self.assertIn("rank_modules_for_target", src)
        self.assertIn("_extract_port_from_finding", src)


class MsfIndexCacheTests(unittest.TestCase):
    def test_schema_bumped_for_hay_field(self):
        import utils.msf_index as mi
        self.assertGreaterEqual(mi._SCHEMA_VERSION, 4)

    def test_search_reads_precomputed_haystack(self):
        src = _src("utils/msf_index.py")
        self.assertIn('"_hay"', src)            # built into the by_path entry
        self.assertIn('meta.get("_hay")', src)   # read in search_by_keywords


class AuxPayloadFreeTests(unittest.TestCase):
    def test_generic_auxiliary_payload_free_in_fallback(self):
        # index-not-ready fallback covers ANY auxiliary/post module, not
        # just scanner/dos, so it never emits `set PAYLOAD` for them.
        src = _src("gui/widgets/target_intel_msf.py")
        self.assertIn('startswith(("auxiliary/", "post/"))', src)


class RankingWiredTests(unittest.TestCase):
    def test_both_msf_callers_rank_suggestions(self):
        src = _src("gui/widgets/target_intel_render.py")
        self.assertEqual(src.count("_rank_modules_for_target"), 2)


if __name__ == "__main__":
    unittest.main()
