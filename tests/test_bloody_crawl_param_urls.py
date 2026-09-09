r"""Bloody Crawl must feed the SQLMap picker with parameterised URLs.

The SQLMap target picker (_collect_sqlmap_candidates) does NOT read
AssaultState or discovered_web_paths — it text-scans Target Intel
finding descriptions for ``https?://host:port/...?name=...`` URLs whose
host matches its own base_url (which always carries an explicit port).

Bloody Crawl now reconstructs ``base?param=value`` URLs from the GET
query parameters it harvested and prints them in a PARAMETERISED URLS
block, in exactly the shape the picker extracts.  The cross-check below
runs the real collector against a synthesised finding to prove the
picker actually returns them (a wrong format would fail silently).
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


def _oracle():
    from gui.widgets.card_routes_oracle import CardOracleRoutesMixin
    return CardOracleRoutesMixin


def _param(url, name, method="GET", where="query", sample=""):
    from utils.assault_state import Param
    return Param(url=url, name=name, method=method, where=where,
                 sample=sample)


class BuildParamUrlTests(unittest.TestCase):
    def setUp(self):
        self._old = sys.modules.get("customtkinter")
        _install_customtkinter_stub()
        self.build = _oracle()._build_param_urls

    def tearDown(self):
        if self._old is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old

    def test_reconstructs_url_with_canonical_host_port(self):
        # start_url has no explicit port -> default 80 is added, because the
        # SQLMap collector's host always carries ":port".
        urls = self.build("http://192.168.177.134/",
                          [_param("http://192.168.177.134/view.php",
                                  "id", sample="7")])
        self.assertEqual(urls, ["http://192.168.177.134:80/view.php?id=7"])

    def test_https_default_port_is_443(self):
        urls = self.build("https://target/",
                          [_param("https://target/x", "a", sample="1")])
        self.assertEqual(urls, ["https://target:443/x?a=1"])

    def test_explicit_port_is_preserved(self):
        urls = self.build("http://t:8080/",
                          [_param("http://t:8080/x", "a", sample="1")])
        self.assertEqual(urls, ["http://t:8080/x?a=1"])

    def test_empty_sample_becomes_representative_value(self):
        urls = self.build("http://t/",
                          [_param("http://t/x", "a", sample="")])
        self.assertEqual(urls, ["http://t:80/x?a=1"])

    def test_sample_is_sanitised_of_url_breaking_chars(self):
        urls = self.build("http://t/",
                          [_param("http://t/x", "a", sample='a "b" (c)')])
        # spaces/quotes/parens stripped so the picker regex cannot truncate.
        self.assertEqual(urls, ["http://t:80/x?a=abc"])

    def test_post_body_params_are_excluded(self):
        urls = self.build("http://t/", [
            _param("http://t/login", "pw", method="POST", where="body"),
        ])
        self.assertEqual(urls, [])

    def test_dedup_by_base_and_param_set(self):
        urls = self.build("http://t/", [
            _param("http://t/v", "id", sample="1"),
            _param("http://t/v", "id", sample="2"),   # same base+name
        ])
        self.assertEqual(urls, ["http://t:80/v?id=1"])

    def test_multiple_params_on_one_base_are_one_url(self):
        urls = self.build("http://t/", [
            _param("http://t/v", "id", sample="1"),
            _param("http://t/v", "cat", sample="books"),
        ])
        self.assertEqual(len(urls), 1)
        self.assertIn("id=1", urls[0])
        self.assertIn("cat=books", urls[0])

    def test_good_paths_drops_params_on_dead_links(self):
        # /view/... is a 404 TWiki placeholder (not in good_paths) and must
        # be dropped; the reachable /mutillidae/index.php survives.
        params = [
            _param("http://192.168.177.134/mutillidae/index.php",
                   "page", sample="home.php"),
            _param("http://192.168.177.134/view/TWiki/TWikiHistory",
                   "rev", sample="1.7"),
        ]
        good = {"/mutillidae/index.php"}
        urls = self.build("http://192.168.177.134/", params, good)
        self.assertEqual(
            urls, ["http://192.168.177.134:80/mutillidae/index.php?page=home.php"])

    def test_good_paths_none_keeps_everything(self):
        params = [_param("http://t/a", "x", sample="1"),
                  _param("http://t/b", "y", sample="2")]
        self.assertEqual(len(self.build("http://t/", params)), 2)


class SqlmapPickerCrossCheckTests(unittest.TestCase):
    """The emitted block must be readable by the REAL collector."""

    def setUp(self):
        self._old = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old

    def test_collector_returns_the_block_urls(self):
        from gui.widgets.card_routes_web import CardWebRoutesMixin
        CardOracleRoutesMixin = _oracle()

        params = [
            _param("http://192.168.177.134/view.php", "id", sample="7"),
            _param("http://192.168.177.134/search.php", "q", sample="test"),
        ]
        urls = CardOracleRoutesMixin._build_param_urls(
            "http://192.168.177.134/", params)
        self.assertEqual(len(urls), 2)

        # Synthesise the finding description exactly as the worker prints it.
        desc = ("Bloody Crawl summary ...\n"
                "──────────────\n"
                f"PARAMETERISED URLS ({len(urls)}):\n"
                "  URLs with query parameters — SQLmap injection targets:\n"
                + "\n".join(f"    {u}" for u in urls))

        class Host:
            def __init__(self):
                self.app = types.SimpleNamespace(
                    target_intel=types.SimpleNamespace(
                        _auto_findings=[{
                            "description": desc,
                            "title": "Bloody Crawl on "
                                     "http://192.168.177.134/"}]))

        # base_url as _route_sqlmap builds it: scheme://host:port
        got = CardWebRoutesMixin._collect_sqlmap_candidates(
            Host(), "http://192.168.177.134:80")
        for u in urls:
            self.assertIn(u, got, f"collector missed {u}")

    def test_collector_ignores_paths_without_parameters(self):
        from gui.widgets.card_routes_web import CardWebRoutesMixin
        desc = ("PARAMETERISED URLS (0):\n"
                "  content page: http://192.168.177.134:80/about.php\n")

        class Host:
            def __init__(self):
                self.app = types.SimpleNamespace(
                    target_intel=types.SimpleNamespace(
                        _auto_findings=[{"description": desc, "title": ""}]))

        got = CardWebRoutesMixin._collect_sqlmap_candidates(
            Host(), "http://192.168.177.134:80")
        self.assertEqual(got, [])


if __name__ == "__main__":
    unittest.main()
