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
    try: import customtkinter
    except ImportError:
        print("\n[!] customtkinter not installed. Run: pip install customtkinter\n")
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
        app.after(100, lambda: ApiKeyDialog(
            app, on_done=lambda k: _start(), existing_key=stored))
        app.mainloop()

if __name__ == "__main__":
    main()
