r"""SUID nmap → POST-RCE RECON finding → PRIVESC CHEAT SHEET match.

Bug (found live on MS2): the recon analyzer's SUID_GTFO list was full-paths
and did NOT include nmap, so /usr/bin/nmap — the single most famous SUID
privesc on Metasploitable — was never flagged, and the cheat sheet's
suid_gtfobins pattern (which keys on the "Exploitable SUID binaries…"
finding) had nothing to match.

Fix: SUID_GTFO is matched by BASENAME and now includes nmap + the common
gtfobins SUID binaries.

Both modules are pure (no GUI), so this is a real end-to-end functional
test of the recon-analyze -> cheat-sheet-match chain.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from utils import post_rce_recon as pr           # noqa: E402
from utils import privesc_patterns as pp          # noqa: E402


def _blob(*suid_lines):
    body = "\n".join(suid_lines)
    return (
        "___HAWK_BEGIN___\n"
        "<<<SECTION:WHOAMI>>>\nuid=1000(msfadmin) gid=1000(msfadmin)\n"
        "msfadmin\nmetasploitable\n<<<END:WHOAMI>>>\n"
        f"<<<SECTION:SUID>>>\n{body}\n<<<END:SUID>>>\n"
        "___HAWK_END___\n"
    )


class SuidGtfobinsChainTests(unittest.TestCase):
    def test_nmap_is_flagged_regardless_of_path(self):
        res = pr.analyze_output(_blob(
            "/bin/su", "/usr/bin/passwd", "/usr/bin/nmap"))
        titles = [f["title"].lower() for f in res.get("findings", [])]
        self.assertTrue(any("exploitable suid" in t for t in titles),
                        "nmap SUID should raise an Exploitable-SUID finding")

    def test_non_exploitable_suid_not_flagged(self):
        # su/passwd/ping are legit SUIDs, not gtfobins shell escapes.
        res = pr.analyze_output(_blob(
            "/bin/su", "/usr/bin/passwd", "/bin/ping"))
        titles = [f["title"].lower() for f in res.get("findings", [])]
        self.assertFalse(any("exploitable suid" in t for t in titles))

    def test_chain_to_cheat_sheet(self):
        res = pr.analyze_output(_blob("/usr/bin/nmap", "/usr/bin/find"))
        findings = [{"title": f["title"], "description": f["description"]}
                    for f in res.get("findings", [])]
        matches = pp.match(findings)
        self.assertTrue(any(m["id"] == "suid_gtfobins" for m in matches),
                        "cheat sheet should match the Exploitable-SUID finding")


if __name__ == "__main__":
    unittest.main()
