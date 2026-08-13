"""The gobuster pickers must default to a non-aggressive thread count.

gobuster's own default is `-t 10`.  HAWK's web dir/dns pickers shipped
`-t 20`, which on fragile lab / HTB virtual networks (VMware NAT, an old
Metasploitable stack) saturates the L3 path — the target starts answering
"no route to host" mid-scan and the operator's connection drops.  Both
web gobuster routes must hand the picker default_threads="10"; the
operator can still raise it in the dialog when the network can take it.
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


def _capture_picker_kwargs(route_name, tool_id, tool_name, *route_args):
    """Drive a gobuster route with the wordlist picker stubbed out and
    return the kwargs the route handed it.  The route's _on_run/extra
    closures never fire (the picker is stubbed), so no Tk is needed."""
    from gui.widgets.card_routes_web import CardWebRoutesMixin

    captured = {}

    class Host(CardWebRoutesMixin):
        def __init__(self):
            self.app = types.SimpleNamespace(
                session_manager=types.SimpleNamespace(current=None))

        def _show_wordlist_picker(self, tool, wl_options, **kwargs):
            captured.update(kwargs)

    host = Host()
    tool = types.SimpleNamespace(id=tool_id, name=tool_name)
    getattr(host, route_name)(tool, *route_args)
    return captured


class GobusterThreadDefaultTests(unittest.TestCase):
    def setUp(self):
        self._old_ctk = sys.modules.get("customtkinter")
        _install_customtkinter_stub()

    def tearDown(self):
        if self._old_ctk is None:
            sys.modules.pop("customtkinter", None)
        else:
            sys.modules["customtkinter"] = self._old_ctk

    def test_gobuster_dir_defaults_to_10_threads(self):
        kw = _capture_picker_kwargs(
            "_route_gobuster_dir", "gobuster_dir", "GOBUSTER Dir",
            "http://192.168.177.134:80")
        self.assertEqual(kw.get("default_threads"), "10")

    def test_gobuster_dns_defaults_to_10_threads(self):
        kw = _capture_picker_kwargs(
            "_route_gobuster_dns", "gobuster_dns", "GOBUSTER DNS")
        self.assertEqual(kw.get("default_threads"), "10")


if __name__ == "__main__":
    unittest.main()
