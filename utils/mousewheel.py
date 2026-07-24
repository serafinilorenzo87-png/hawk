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
HAWK — Global mouse-wheel scrolling.

customtkinter's CTkScrollableFrame only scrolls when the pointer is over its
scrollbar, not when it's over a child widget. This module installs a global
handler so that wheel events anywhere in the app are routed to whichever
scrollable container the pointer is currently hovering — exactly the
behaviour users expect from any modern desktop app.

Usage
=====
    from utils.mousewheel import install_global_mousewheel
    install_global_mousewheel(root)

Call once on the top-level Tk/CTk root after the UI is built.
"""

from __future__ import annotations

import tkinter as tk


# Stdlib widgets that actually scroll line-by-line on wheel. We scroll
# these ourselves because bind_all consumed the event.
#
# NOTE: tk.Canvas is deliberately NOT in this list. customtkinter uses
# an internal tk.Canvas inside CTkButton / CTkFrame / CTkLabel to paint
# rounded corners, and those canvases have no scrollregion. If we claim
# the event for them, the scroll is swallowed — which is exactly the
# "wheel only works on the scrollbar" bug users reported.
_NATIVE_WHEEL_CLASSES = (tk.Text, tk.Listbox, tk.Spinbox)

# How many tk "units" to scroll per wheel notch.
# - For tk.Text / tk.Listbox, 1 unit == 1 line. 3 lines/notch feels natural.
# - For the tk.Canvas inside CTkScrollableFrame, 1 unit is tiny (yScrollIncrement
#   is 0 by default → ~1 pixel). We need a larger multiplier to match OS-wide
#   scroll behaviour.
_TEXT_UNITS_PER_NOTCH   = 2
_CANVAS_UNITS_PER_NOTCH = 4


def _find_scrollable_canvas(widget):
    """Walk up the widget tree looking for a CTkScrollableFrame's internal
    canvas that still has overflow content. Returns the canvas to scroll,
    or None.

    We intentionally only match customtkinter's CTkScrollableFrame (detected
    via its `_parent_canvas` attribute). Raw tk.Canvas widgets are ignored
    to avoid claiming the event for buttons/labels whose "canvas" is just
    a rendering surface with no scrollregion.
    """
    w = widget
    while w is not None:
        canvas = getattr(w, "_parent_canvas", None)
        if isinstance(canvas, tk.Canvas):
            # Scroll only if there's actually overflow to scroll into.
            try:
                first, last = canvas.yview()
                if last - first < 1.0:
                    return canvas
            except Exception:
                return canvas
            # If yview says "all visible", keep walking — maybe an outer
            # scrollable frame does have overflow.
        w = getattr(w, "master", None)
    return None


def _has_bubble_flag(widget) -> bool:
    """Return True when the widget (or any ancestor) opts out of
    capturing wheel events via the ``_hawk_bubble_wheel`` attribute.

    Callers set this flag on a CTkTextbox / tk.Text that should NOT
    eat wheel events — most commonly read-only preview boxes embedded
    inside a scrollable container, where the user expects the wheel to
    scroll the OUTER container, not the tiny inner textbox.

    Example — Target Intel auto-finding descriptions:
        desc_box = ctk.CTkTextbox(...)
        desc_box._hawk_bubble_wheel = True
        desc_box._textbox._hawk_bubble_wheel = True   # inner tk.Text
    """
    w = widget
    while w is not None:
        if getattr(w, "_hawk_bubble_wheel", False):
            return True
        w = getattr(w, "master", None)
    return False


def _on_wheel(event):
    """Global wheel handler — dispatch to the container under the pointer."""
    # event.delta: Windows/macOS.  On Windows 1 notch = 120 (or -120).
    # On macOS it can be 1/-1 already. Treat any positive as up-scroll.
    # On Linux X11 the event arrives as Button-4 / Button-5 (handled below).
    if getattr(event, "num", 0) == 4:
        direction = -1           # wheel up → scroll up
    elif getattr(event, "num", 0) == 5:
        direction = 1            # wheel down → scroll down
    else:
        delta = getattr(event, "delta", 0)
        if delta == 0:
            return
        direction = -1 if delta > 0 else 1

    # Find the widget under the actual pointer position. We can't rely on
    # event.widget because bind_all delivers events based on focus, not
    # pointer. winfo_containing() is the right call.
    try:
        root = event.widget.winfo_toplevel()
        hovered = root.winfo_containing(event.x_root, event.y_root)
    except Exception:
        hovered = None

    if hovered is None:
        return

    # 1. tk.Text / tk.Listbox scroll themselves line-by-line — UNLESS
    # the widget is flagged `_hawk_bubble_wheel`, in which case we fall
    # through to the outer-canvas walk so the wheel scrolls whatever
    # scrollable frame the textbox is embedded inside.  This matches the
    # user expectation that short read-only previews don't trap the
    # mouse wheel away from the surrounding panel.
    if isinstance(hovered, _NATIVE_WHEEL_CLASSES) \
            and not _has_bubble_flag(hovered):
        try:
            hovered.yview_scroll(direction * _TEXT_UNITS_PER_NOTCH, "units")
        except Exception:
            return
        return "break"

    # 2. Walk up to the nearest CTkScrollableFrame and scroll its canvas.
    target = _find_scrollable_canvas(hovered)
    if target is None:
        return
    try:
        target.yview_scroll(direction * _CANVAS_UNITS_PER_NOTCH, "units")
    except Exception:
        pass
    return "break"


def install_global_mousewheel(root: tk.Misc) -> None:
    """Install global wheel bindings on `root`. Safe to call once per app."""
    # Windows / macOS: <MouseWheel> with event.delta.
    root.bind_all("<MouseWheel>", _on_wheel, add="+")
    # Linux / X11: Button-4 (up) and Button-5 (down).
    root.bind_all("<Button-4>", _on_wheel, add="+")
    root.bind_all("<Button-5>", _on_wheel, add="+")
    # Shift+wheel → horizontal, where a frame supports it. We bind the
    # same handler; yview_scroll will be wrong for horizontal but most
    # CTkScrollableFrame use vertical-only scrollbars so this is a no-op
    # in practice.  Left unbound intentionally to avoid surprises.
