r"""The ARGUS "coming soon" teaser must not promise a release NUMBER.

HAWK's SemVer plan reserves 2.0.0 for a real breaking change; roadmap
features ship as minor bumps and their marketing lives in release *names*,
not version numbers.  The teaser dialog used to hardcode "v2.0.0", which
both violates that plan and re-ages the moment the number is picked.

These are static source-shape checks (target_bar subclasses customtkinter
and cannot import headless): the visible teaser strings must use neutral
"coming soon / upcoming release" wording, with no semver-shaped number.
"""

import os
import re
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


class ArgusTeaserVersionTests(unittest.TestCase):
    def test_teaser_dialog_has_no_release_number(self):
        body = _method(_src("gui/widgets/target_bar.py"),
                       "_show_coming_soon_dialog")
        self.assertNotIn("2.0.0", body)
        # No semver-shaped release number at all — guards re-introduction
        # without pinning this test to a specific future version.
        self.assertIsNone(
            re.search(r"\bv?\d+\.\d+\.\d+\b", body),
            "teaser dialog must not name a release number")

    def test_teaser_uses_neutral_wording(self):
        body = _method(_src("gui/widgets/target_bar.py"),
                       "_show_coming_soon_dialog")
        low = body.lower()
        self.assertTrue("coming soon" in low or "upcoming" in low,
                        "teaser should use neutral coming-soon wording")


if __name__ == "__main__":
    unittest.main()
