# HAWK — Hostile Assessment WorKit
# Copyright 2026 Lorenzo Serafini
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is provided in the LICENSE file at the root
# of this distribution, or at http://www.apache.org/licenses/LICENSE-2.0
#
# Attribution "Created by Lorenzo Serafini" must be preserved in all
# redistributed and Derivative Works — see NOTICE for details.

"""
HAWK - Clipboard utility v1.0
Uses xclip as backend for reliable copy/paste on Linux/X11.
Fallback to tkinter clipboard if xclip not available.
"""

import subprocess
import shutil
import customtkinter as ctk
import tkinter as tk


def _xclip_available() -> bool:
    return shutil.which("xclip") is not None


def clipboard_copy(text: str) -> bool:
    """Copy text to system clipboard via xclip."""
    if not text:
        return False
    try:
        subprocess.run(
            ["xclip", "-selection", "clipboard"],
            input=text.encode("utf-8"),
            check=True, timeout=3)
        return True
    except Exception:
        return False


def clipboard_paste() -> str:
    """Paste text from system clipboard via xclip."""
    try:
        result = subprocess.run(
            ["xclip", "-selection", "clipboard", "-o"],
            capture_output=True, timeout=3)
        return result.stdout.decode("utf-8", errors="replace")
    except Exception:
        return ""


def get_selected_text(widget) -> str:
    """Get selected text from a CTkEntry or CTkTextbox."""
    try:
        if isinstance(widget, ctk.CTkEntry):
            inner = widget._entry
            if inner.selection_present():
                return inner.selection_get()
        elif isinstance(widget, ctk.CTkTextbox):
            inner = widget._textbox
            try:
                return inner.get("sel.first", "sel.last")
            except tk.TclError:
                pass
    except Exception:
        pass
    return ""


def insert_text(widget, text: str):
    """Insert text at cursor position in a CTkEntry or CTkTextbox."""
    try:
        state = str(widget.cget("state"))
        if state == "disabled":
            return
    except Exception:
        pass
    try:
        if isinstance(widget, ctk.CTkEntry):
            inner = widget._entry
            # Delete selection if any
            try:
                inner.delete("sel.first", "sel.last")
            except tk.TclError:
                pass
            inner.insert("insert", text)
        elif isinstance(widget, ctk.CTkTextbox):
            inner = widget._textbox
            try:
                inner.delete("sel.first", "sel.last")
            except tk.TclError:
                pass
            inner.insert("insert", text)
    except Exception:
        pass


def delete_selected(widget):
    """Delete selected text."""
    try:
        state = str(widget.cget("state"))
        if state == "disabled":
            return
    except Exception:
        pass
    try:
        if isinstance(widget, ctk.CTkEntry):
            widget._entry.delete("sel.first", "sel.last")
        elif isinstance(widget, ctk.CTkTextbox):
            widget._textbox.delete("sel.first", "sel.last")
    except Exception:
        pass


def select_all(widget):
    """Select all text in widget."""
    try:
        if isinstance(widget, ctk.CTkEntry):
            widget._entry.select_range(0, "end")
            widget._entry.icursor("end")
        elif isinstance(widget, ctk.CTkTextbox):
            widget._textbox.tag_add("sel", "1.0", "end")
    except Exception:
        pass


def add_context_menu(widget):
    """
    Add right-click Copy/Paste/Cut/SelectAll to any CTkEntry or CTkTextbox.
    Uses xclip for reliable clipboard access on Linux/X11.
    """
    try:
        state = str(widget.cget("state"))
        readonly = (state == "disabled")
    except Exception:
        readonly = False

    use_xclip = _xclip_available()

    menu = tk.Menu(widget, tearoff=0,
                   bg="#1a1a2e", fg="#d0d8e0",
                   activebackground="#00C8C8",
                   activeforeground="#0B0F14",
                   relief="flat", bd=0,
                   font=("Courier New", 12))

    def _copy():
        text = get_selected_text(widget)
        if not text:
            # If nothing selected, copy all
            try:
                if isinstance(widget, ctk.CTkEntry):
                    text = widget._entry.get()
                elif isinstance(widget, ctk.CTkTextbox):
                    text = widget._textbox.get("1.0", "end-1c")
            except Exception:
                return
        if use_xclip:
            clipboard_copy(text)
        else:
            try:
                widget.clipboard_clear()
                widget.clipboard_append(text)
            except Exception:
                pass

    def _paste():
        if readonly:
            return
        if use_xclip:
            text = clipboard_paste()
        else:
            try:
                text = widget.clipboard_get()
            except Exception:
                text = ""
        if text:
            insert_text(widget, text)

    def _cut():
        if readonly:
            return
        text = get_selected_text(widget)
        if text:
            if use_xclip:
                clipboard_copy(text)
            else:
                try:
                    widget.clipboard_clear()
                    widget.clipboard_append(text)
                except Exception:
                    pass
            delete_selected(widget)

    def _select_all():
        select_all(widget)

    if not readonly:
        menu.add_command(label="  Cut        Ctrl+X", command=_cut)
    menu.add_command(label="  Copy       Ctrl+C", command=_copy)
    if not readonly:
        menu.add_command(label="  Paste      Ctrl+V", command=_paste)
    menu.add_separator()
    menu.add_command(label="  Select All  Ctrl+A", command=_select_all)

    def _show(event):
        try:
            widget.focus_set()
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    # Bind on the INNER tk widget, not the CTk wrapper:
    #   - Button-3 on a CTkEntry is consumed by the inner tk.Entry and never
    #     reaches the frame, so widget.bind() would do nothing.
    #   - Control-v on the wrapper fires AFTER the inner tk.Entry's class
    #     binding has already pasted once — hence the double paste.  Binding
    #     directly on the inner widget + returning "break" suppresses the
    #     Tk-default class handler so paste happens exactly once.
    if isinstance(widget, ctk.CTkEntry):
        inner = widget._entry
    elif isinstance(widget, ctk.CTkTextbox):
        inner = widget._textbox
    else:
        inner = widget

    inner.bind("<Button-3>", _show)
    inner.bind("<Button-2>", _show)

    # Shortcut handlers — return "break" to stop Tk's default paste/copy/cut
    # handlers from running in addition to ours (otherwise Ctrl+V pastes twice).
    if not readonly:
        inner.bind("<Control-c>", lambda e: (_copy(), "break")[1])
        inner.bind("<Control-v>", lambda e: (_paste(), "break")[1])
        inner.bind("<Control-x>", lambda e: (_cut(), "break")[1])
    inner.bind("<Control-a>", lambda e: (_select_all(), "break")[1])


def apply_context_menus_recursive(parent):
    """Recursively apply context menu to all CTkEntry and CTkTextbox."""
    try:
        for widget in parent.winfo_children():
            if isinstance(widget, (ctk.CTkEntry, ctk.CTkTextbox)):
                add_context_menu(widget)
            apply_context_menus_recursive(widget)
    except Exception:
        pass
