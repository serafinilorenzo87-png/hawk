#!/usr/bin/env python3
# HAWK — Hostile Assessment War-Kit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0
#
# Attribution "Created by Lorenzo Serafini" must be preserved in all
# redistributed and Derivative Works — see NOTICE for details.

"""HAWK - Hostile Assessment War-Kit"""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils.config import APP_VERSION

def _check_deps():
    # tkinter is a SYSTEM package (python3-tk), not a pip one, and customtkinter
    # imports it at import time — so a missing tkinter surfaces as an ImportError
    # on `import customtkinter`. Check tkinter first, otherwise the message blames
    # customtkinter (a pip install that won't fix anything) for a missing apt pkg.
    try:
        import tkinter  # noqa: F401
    except Exception:
        print("\n[!] tkinter (Tk runtime) is missing — install the SYSTEM "
              "package:\n    sudo apt install python3-tk\n"
              "    (tkinter is NOT a pip package; customtkinter needs it.)\n")
        sys.exit(1)
    try:
        import customtkinter  # noqa: F401
    except ImportError:
        print("\n[!] customtkinter not installed. Run:\n"
              "    python3 -m pip install -r requirements.txt   "
              "(ideally inside a venv)\n")
        sys.exit(1)
_check_deps()
import customtkinter as ctk

def _parse_args():
    p = argparse.ArgumentParser(description="HAWK")
    p.add_argument("--nosplash",      action="store_true")
    p.add_argument("--no-api-dialog", action="store_true")
    p.add_argument("--version",       action="store_true")
    return p.parse_args()

def main():
    args = _parse_args()
    if args.version:
        print(f"HAWK v{APP_VERSION} - Created by Lorenzo Serafini"); sys.exit(0)
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("green")
    from gui.app import HawkApp
    app = HawkApp()

    def _start():
        if args.nosplash:
            app.show(); app.mainloop()
        else:
            app.withdraw()
            from gui.splash import SplashScreen
            SplashScreen(app, on_done=lambda: [app.show(), app.mainloop()])
            app.mainloop()

    if args.no_api_dialog:
        from utils.cve_lookup import _load_stored_key, get_client
        stored = _load_stored_key()
        if stored: get_client().set_api_key(stored)
        _start()
    else:
        from utils.cve_lookup import _load_stored_key
        stored = _load_stored_key()
        from gui.api_key_dialog import ApiKeyDialog
        app.withdraw()

        def _api_dialog():
            ApiKeyDialog(app, on_done=lambda k: _start(), existing_key=stored)

        # First launch only: offer the one-time nmap/masscan caps setup
        # before the API key dialog. On every later launch this is a no-op
        # and startup is unchanged.
        from gui.first_run_dialog import is_first_run, FirstRunDialog
        if is_first_run():
            app.after(100, lambda: FirstRunDialog(app, on_done=_api_dialog))
        else:
            app.after(100, _api_dialog)
        app.mainloop()

if __name__ == "__main__":
    main()
