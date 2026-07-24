"""
Build the HAWK v1.0.0 presentation PDF (5 pages).
Run once: `python build_presentation_pdf.py`
Output: HAWK-Presentation-v1.0.0.pdf in repo root.
"""
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor, white, black
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


# ─── Register a monospace TTF that covers Unicode box-drawing chars ──────────
# ReportLab's built-in Courier is ISO-8859-1 only — the ██╗╔═║╚╝ glyphs used
# by HAWK's FIGlet banner would render as empty boxes. We try a few common
# system fonts (Consolas/DejaVu) and fall back to Courier-Bold if none found.
_MONO_FONT = "Courier-Bold"   # fallback
_FONT_CANDIDATES = [
    ("MonoBlock", r"C:\Windows\Fonts\consola.ttf"),
    ("MonoBlock", r"C:\Windows\Fonts\cour.ttf"),
    ("MonoBlock", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
    ("MonoBlock", "/usr/share/fonts/TTF/DejaVuSansMono.ttf"),
]
for name, path in _FONT_CANDIDATES:
    if os.path.isfile(path):
        try:
            pdfmetrics.registerFont(TTFont(name, path))
            _MONO_FONT = name
            break
        except Exception:
            continue

# ─── Palette (mirrors HAWK's in-app theme) ───────────────────────────────────
BG          = HexColor("#0A0E12")   # near-black
PANEL       = HexColor("#0F1620")   # card background
ACCENT      = HexColor("#00C8C8")   # cyan — banner / titles
GREEN       = HexColor("#4AFFB0")   # primary green — body highlights
DIM_GREEN   = HexColor("#2A7A52")   # borders
TEXT        = HexColor("#D8E0E8")   # body text on dark
MUTED       = HexColor("#7A8694")   # captions
YELLOW      = HexColor("#FFD060")   # warnings / labels
RED         = HexColor("#FF6060")   # critical
RULE        = HexColor("#1E2A38")   # subtle separators

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm

OUT_PATH = "HAWK-Presentation-v1.0.0.pdf"


# ─── Helpers ─────────────────────────────────────────────────────────────────

def fill_bg(c):
    c.setFillColor(BG)
    c.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)


def header_strip(c, page_no, total):
    """Slim top strip: HAWK · v1.0.0 ·  page x/y"""
    c.setFillColor(ACCENT)
    c.rect(0, PAGE_H - 4 * mm, PAGE_W, 1, fill=1, stroke=0)
    c.setFont("Courier-Bold", 8)
    c.setFillColor(MUTED)
    c.drawString(MARGIN, PAGE_H - 9 * mm,
                 "HAWK  ·  HOSTILE ASSESSMENT WORKIT  ·  v1.0.0")
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 9 * mm,
                      f"Page {page_no} / {total}")


def footer_strip(c):
    c.setFillColor(RULE)
    c.rect(MARGIN, 14 * mm, PAGE_W - 2 * MARGIN, 0.4, fill=1, stroke=0)
    c.setFont("Courier", 7)
    c.setFillColor(MUTED)
    c.drawString(MARGIN, 9 * mm,
                 "Created by Lorenzo Serafini  ·  Apache 2.0  ·  "
                 "Authorized use only")
    c.drawRightString(PAGE_W - MARGIN, 9 * mm, "github: tba")


def section_title(c, y, text, color=ACCENT):
    c.setFont("Courier-Bold", 16)
    c.setFillColor(color)
    c.drawString(MARGIN, y, text)
    c.setStrokeColor(color)
    c.setLineWidth(1)
    c.line(MARGIN, y - 2 * mm, MARGIN + 28 * mm, y - 2 * mm)
    return y - 9 * mm


def body(c, x, y, lines, font="Helvetica", size=10, leading=14, color=TEXT):
    c.setFont(font, size)
    c.setFillColor(color)
    for ln in lines:
        c.drawString(x, y, ln)
        y -= leading
    return y


def bullet(c, x, y, items, bullet_char="▸",
           bcolor=GREEN, tcolor=TEXT, size=10, leading=14, indent=5 * mm):
    for it in items:
        c.setFont("Courier-Bold", size)
        c.setFillColor(bcolor)
        c.drawString(x, y, bullet_char)
        c.setFont("Helvetica", size)
        c.setFillColor(tcolor)
        c.drawString(x + indent, y, it)
        y -= leading
    return y


def panel(c, x, y, w, h, title=None, accent=DIM_GREEN, fill=PANEL):
    c.setFillColor(fill)
    c.setStrokeColor(accent)
    c.setLineWidth(1)
    c.roundRect(x, y - h, w, h, 4, fill=1, stroke=1)
    if title:
        c.setFont("Courier-Bold", 9)
        c.setFillColor(accent)
        c.drawString(x + 4 * mm, y - 5 * mm, title.upper())
    return x + 4 * mm, y - 9 * mm   # cursor inside panel


# ─── Page 1 — Cover ──────────────────────────────────────────────────────────

def page_cover(c):
    fill_bg(c)
    # Top accent bar
    c.setFillColor(ACCENT)
    c.rect(0, PAGE_H - 6 * mm, PAGE_W, 2, fill=1, stroke=0)
    c.setFillColor(GREEN)
    c.rect(0, PAGE_H - 9 * mm, PAGE_W, 1, fill=1, stroke=0)

    # ASCII logo — same FIGlet banner the live app shows, so the cover
    # matches what users see at launch. Drawn with one fixed X anchor for
    # the whole block (monospace + per-line centering would desync columns
    # whenever line lengths differ by one glyph).
    logo_lines = [
        "██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗",
        "██║  ██║██╔══██╗██║    ██║██║ ██╔╝",
        "███████║███████║██║ █╗ ██║█████╔╝ ",
        "██╔══██║██╔══██║██║███╗██║██╔═██╗ ",
        "██║  ██║██║  ██║╚███╔███╔╝██║  ██╗",
        "╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝",
    ]
    logo_font   = _MONO_FONT
    logo_size   = 22
    # Measure the first line once and anchor the whole block on that X.
    c.setFont(logo_font, logo_size)
    line_width  = c.stringWidth(logo_lines[0], logo_font, logo_size)
    anchor_x    = (PAGE_W - line_width) / 2
    c.setFillColor(ACCENT)
    y = PAGE_H - 48 * mm
    for ln in logo_lines:
        c.drawString(anchor_x, y, ln)
        y -= 8 * mm

    # Tagline
    c.setFont("Courier-Bold", 13)
    c.setFillColor(GREEN)
    c.drawCentredString(PAGE_W / 2, y - 5 * mm,
                        "HOSTILE  ASSESSMENT  WORKIT")

    c.setFont("Helvetica", 11)
    c.setFillColor(TEXT)
    c.drawCentredString(PAGE_W / 2, y - 13 * mm,
                        "An open-source pentest control panel for Kali Linux.")
    c.drawCentredString(PAGE_W / 2, y - 19 * mm,
                        "One window. Eight kill-chain phases. Every tool you "
                        "already use.")

    # Big version pill
    pill_w, pill_h = 70 * mm, 22 * mm
    px = (PAGE_W - pill_w) / 2
    py = 90 * mm
    c.setFillColor(PANEL)
    c.setStrokeColor(ACCENT)
    c.setLineWidth(1.5)
    c.roundRect(px, py, pill_w, pill_h, 6, fill=1, stroke=1)
    c.setFont("Courier-Bold", 22)
    c.setFillColor(ACCENT)
    c.drawCentredString(PAGE_W / 2, py + 12 * mm, "VERSION  1.0.0")
    c.setFont("Helvetica-Oblique", 9)
    c.setFillColor(MUTED)
    c.drawCentredString(PAGE_W / 2, py + 5 * mm,
                        "first public release  ·  more to come")

    # Author block
    c.setFont("Courier-Bold", 11)
    c.setFillColor(GREEN)
    c.drawCentredString(PAGE_W / 2, 70 * mm, "CREATED BY")
    c.setFont("Helvetica-Bold", 16)
    c.setFillColor(TEXT)
    c.drawCentredString(PAGE_W / 2, 62 * mm, "Lorenzo Serafini")
    c.setFont("Helvetica", 9)
    c.setFillColor(MUTED)
    c.drawCentredString(PAGE_W / 2, 56 * mm,
                        "Security engineer  ·  Italy  ·  2026")

    # Footer disclaimer
    c.setFont("Courier", 8)
    c.setFillColor(YELLOW)
    c.drawCentredString(PAGE_W / 2, 30 * mm,
                        "AUTHORIZED USE ONLY")
    c.setFont("Helvetica", 8)
    c.setFillColor(MUTED)
    c.drawCentredString(PAGE_W / 2, 24 * mm,
                        "HAWK is a tool for licensed penetration testers, "
                        "CTF players, and red-teamers.")
    c.drawCentredString(PAGE_W / 2, 19 * mm,
                        "Never run it against systems you don't own or have "
                        "explicit written permission to test.")

    c.setFont("Courier", 7)
    c.setFillColor(DIM_GREEN)
    c.drawCentredString(PAGE_W / 2, 12 * mm,
                        "Apache 2.0  ·  Open source  ·  Attribution required")
    c.showPage()


# ─── Page 2 — What is HAWK ───────────────────────────────────────────────────

def page_what(c):
    fill_bg(c)
    header_strip(c, 2, 5)
    y = PAGE_H - 25 * mm

    y = section_title(c, y, "WHAT IS HAWK?")

    intro = [
        "HAWK is a desktop GUI that wraps the standard Kali Linux pentesting toolkit",
        "into a single coherent workflow. Instead of juggling a dozen terminal tabs,",
        "you click through eight kill-chain phases and HAWK runs the right tool with",
        "the right arguments — then captures the results into structured findings.",
    ]
    y = body(c, MARGIN, y, intro, leading=14)
    y -= 4 * mm

    # The kill chain panel
    y = section_title(c, y, "EIGHT  PHASES")
    phases = [
        ("RECON",         "passive footprinting — whois, dnsrecon, theHarvester, subfinder"),
        ("SCANNING",      "port discovery — nmap, masscan, rustscan"),
        ("ENUMERATION",   "service drill-down — gobuster, ffuf, enum4linux, kerbrute, ldapsearch"),
        ("VULN SCAN",     "find weak spots — nikto, nuclei, wpscan, sqlmap, searchsploit"),
        ("EXPLOITATION",  "land a shell — metasploit, hydra, responder, impacket, certipy"),
        ("POST-EXPLOIT",  "live off the land — find SUID, sudo -l, scheduled tasks"),
        ("LATERAL",       "pivot through — chisel, ligolo, proxychains, ssh tunnels"),
        ("REPORTING",     "what you actually found, exportable"),
    ]
    for name, desc in phases:
        c.setFont("Courier-Bold", 10)
        c.setFillColor(ACCENT)
        c.drawString(MARGIN, y, f"{name:<14}")
        c.setFont("Helvetica", 10)
        c.setFillColor(TEXT)
        c.drawString(MARGIN + 38 * mm, y, desc)
        y -= 6.5 * mm

    y -= 2 * mm

    # Big idea panel
    inner_x, inner_y = panel(c, MARGIN, y, PAGE_W - 2 * MARGIN, 35 * mm,
                              title="THE BIG IDEA", accent=ACCENT)
    body(c, inner_x, inner_y,
         ["HAWK does not replace your tools. It orchestrates them.",
          "Every command is visible, every flag is editable, every result is logged.",
          "When you outgrow the GUI, the underlying CLI workflow is right there —",
          "no proprietary lock-in, no hidden magic."],
         leading=13)

    footer_strip(c)
    c.showPage()


# ─── Page 3 — Why & Design philosophy ────────────────────────────────────────

def page_why(c):
    fill_bg(c)
    header_strip(c, 3, 5)
    y = PAGE_H - 25 * mm

    y = section_title(c, y, "WHY  HAWK  EXISTS")

    why = [
        "Every CTF player and junior pentester hits the same wall: too many tools,",
        "too many flags, too much context-switching. The senior on the team has",
        "muscle memory; the junior has 12 browser tabs of cheat sheets.",
        "",
        "HAWK was built to flatten that learning curve without dumbing anything down.",
        "It's the assistant that whispers \"try gobuster first\", \"this port is SMB,",
        "use enum4linux\", \"that hash looks like NTLMv2\" — without taking the",
        "wheel away from you.",
    ]
    y = body(c, MARGIN, y, why, leading=14)
    y -= 3 * mm

    y = section_title(c, y, "WHY  IT  FEELS  EASY", color=GREEN)

    pillars = [
        ("Guided dialogs",    "Every tool with non-obvious args (sqlmap, nuclei, "
                              "certipy, hydra) opens a dialog that explains modes,"),
        ("",                  "suggests parameters, and shows the live command preview before launch."),
        ("Credential Store",  "Cracked passwords, NTLM hashes, Kerberos tickets — all in one place."),
        ("",                  "Other tools auto-pull from it: no copy-paste between terminals."),
        ("Target Intel",      "As scans complete, results are parsed into structured findings —"),
        ("",                  "open ports, services, versions, CVEs — searchable and exportable."),
        ("Background jobs",   "Long-running scans (hydra, nuclei, nmap full) keep going while"),
        ("",                  "you work on other phases. Each shows elapsed + estimated time."),
        ("Smart errors",      "Tool crashed? HAWK explains why (missing dep, port conflict,"),
        ("",                  "wrong wordlist) and offers a one-click fix."),
    ]
    for label, text in pillars:
        if label:
            c.setFont("Courier-Bold", 10)
            c.setFillColor(GREEN)
            c.drawString(MARGIN, y, label)
            c.setFont("Helvetica", 10)
            c.setFillColor(TEXT)
            c.drawString(MARGIN + 38 * mm, y, text)
        else:
            c.setFont("Helvetica", 10)
            c.setFillColor(TEXT)
            c.drawString(MARGIN + 38 * mm, y, text)
        y -= 5.5 * mm

    y -= 3 * mm

    # Quote / philosophy box
    inner_x, inner_y = panel(c, MARGIN, y, PAGE_W - 2 * MARGIN, 24 * mm,
                              title="DESIGN  PRINCIPLE", accent=ACCENT)
    c.setFont("Helvetica-Oblique", 10)
    c.setFillColor(TEXT)
    c.drawString(inner_x, inner_y,
                 "\"A junior pentester should land their first shell with HAWK")
    c.drawString(inner_x, inner_y - 13,
                 " and learn the underlying tools by reading what HAWK runs.\"")

    footer_strip(c)
    c.showPage()


# ─── Page 4 — What's inside (technical) ──────────────────────────────────────

def page_inside(c):
    fill_bg(c)
    header_strip(c, 4, 5)
    y = PAGE_H - 25 * mm

    y = section_title(c, y, "WHAT'S  INSIDE")

    intro = [
        "HAWK is ~15 000 lines of Python 3.11+ on top of customtkinter. It",
        "ships as source — clone, install deps, run. No daemon, no database.",
    ]
    y = body(c, MARGIN, y, intro, leading=14)
    y -= 3 * mm

    # Two-column architecture overview
    col_w = (PAGE_W - 2 * MARGIN - 6 * mm) / 2
    top_y = y

    # Left column: stack
    inner_x, inner_y = panel(c, MARGIN, y, col_w, 70 * mm,
                              title="STACK", accent=ACCENT)
    stack = [
        "Language    Python 3.11+",
        "GUI         customtkinter (tk-based)",
        "Runner      subprocess + threading",
        "Sessions    JSON on disk",
        "Reports     HTML + Markdown export",
        "Platforms   Kali Linux (primary)",
        "            Parrot, Ubuntu (tested)",
        "License     Apache 2.0",
    ]
    c.setFont("Courier", 9)
    c.setFillColor(TEXT)
    cy = inner_y
    for ln in stack:
        c.drawString(inner_x, cy, ln)
        cy -= 12

    # Right column: integrated tools
    inner_x2, inner_y2 = panel(c, MARGIN + col_w + 6 * mm, top_y,
                                col_w, 70 * mm,
                                title="INTEGRATED  TOOLS", accent=ACCENT)
    tools = [
        "Recon       whois  dig  dnsrecon  theHarvester",
        "            subfinder  amass  whatweb  wafw00f",
        "Scanning    nmap  masscan  rustscan",
        "Enum        gobuster  ffuf  enum4linux  netexec",
        "            kerbrute  ldapsearch  smbclient",
        "Vuln        nikto  nuclei  wpscan  sqlmap",
        "            searchsploit  CVE/NVD lookup",
        "Exploit     metasploit  hydra  responder",
        "            impacket-*  certipy-ad",
        "Lateral     chisel  ligolo  proxychains",
        "Misc        john  hashcat  evil-winrm",
    ]
    c.setFont("Courier", 8)
    c.setFillColor(TEXT)
    cy2 = inner_y2
    for ln in tools:
        c.drawString(inner_x2, cy2, ln)
        cy2 -= 11

    y = top_y - 75 * mm

    # Notable engineering features
    y = section_title(c, y, "ENGINEERING  HIGHLIGHTS", color=GREEN)
    features = [
        "Cross-distro tool detection — finds binaries even when not on $PATH",
        "Auto-fix dialog for Python 3.12+ distutils crashes (apt impacket)",
        "Live command preview in every dialog before you hit RUN",
        "Background job bar with CPU-load warning when too many run at once",
        "Autosave every 5 min — no lost sessions on crashes",
        "Right-click context menus, global mouse-wheel scrolling, dark theme",
        "ANSI banner stripping — only real findings reach the Intel panel",
    ]
    bullet(c, MARGIN, y, features, size=9, leading=12.5)

    footer_strip(c)
    c.showPage()


# ─── Page 5 — Roadmap & call to action ───────────────────────────────────────

def page_roadmap(c):
    fill_bg(c)
    header_strip(c, 5, 5)
    y = PAGE_H - 25 * mm

    y = section_title(c, y, "THIS  IS  v1.0.0")

    intro = [
        "First public release. The backend is solid — battle-tested across HTB,",
        "THM, and live engagements. What's listed below is what ships today;",
        "what comes next will be shaped by you, the people actually using HAWK.",
    ]
    y = body(c, MARGIN, y, intro, leading=14)
    y -= 4 * mm

    # Single wide panel listing what's in v1.0
    ph = 70 * mm
    inner_x, inner_y = panel(c, MARGIN, y, PAGE_W - 2 * MARGIN, ph,
                              title="v1.0.0  —  WHAT  SHIPS  TODAY",
                              accent=ACCENT)
    # Two inner columns so 8 items fit compactly without stretching the page.
    items_left = [
        "8-phase kill-chain GUI",
        "30+ integrated Kali tools",
        "Guided dialogs for every non-trivial tool",
        "Credential Store with auto-propagation",
    ]
    items_right = [
        "Target Intel — structured finding parser",
        "Background jobs + CPU-load warnings",
        "Session save / load / 5-min autosave",
        "Smart error dialogs with one-click fixes",
    ]
    col2_x = inner_x + (PAGE_W - 2 * MARGIN) / 2 - 4 * mm
    cy_l = inner_y
    cy_r = inner_y
    for it in items_left:
        c.setFont("Courier-Bold", 10)
        c.setFillColor(GREEN)
        c.drawString(inner_x, cy_l, "▸")
        c.setFont("Helvetica", 10)
        c.setFillColor(TEXT)
        c.drawString(inner_x + 5 * mm, cy_l, it)
        cy_l -= 14
    for it in items_right:
        c.setFont("Courier-Bold", 10)
        c.setFillColor(GREEN)
        c.drawString(col2_x, cy_r, "▸")
        c.setFont("Helvetica", 10)
        c.setFillColor(TEXT)
        c.drawString(col2_x + 5 * mm, cy_r, it)
        cy_r -= 14

    # Apache license footnote inside the panel
    c.setFont("Courier", 8)
    c.setFillColor(MUTED)
    c.drawString(inner_x, min(cy_l, cy_r) - 2,
                 "Apache 2.0  ·  attribution required  ·  "
                 "Kali Linux primary target")

    y = y - ph - 6 * mm

    # Whats-next, deliberately open-ended
    y = section_title(c, y, "WHAT  COMES  NEXT", color=GREEN)
    next_lines = [
        "The roadmap is intentionally blank. HAWK v1.0.0 is a complete tool on",
        "its own — it does what it says on the cover. Where it goes from here",
        "will be driven by real feedback from real engagements.",
        "",
        "Use it. Break it. File an issue. Open a PR. That's the roadmap.",
    ]
    y = body(c, MARGIN, y, next_lines, leading=14)
    y -= 4 * mm

    # Final author block
    inner_x, inner_y = panel(c, MARGIN, y, PAGE_W - 2 * MARGIN, 28 * mm,
                              title="CREATED  BY", accent=ACCENT)
    c.setFont("Helvetica-Bold", 14)
    c.setFillColor(GREEN)
    c.drawString(inner_x, inner_y, "Lorenzo Serafini")
    c.setFont("Helvetica", 9)
    c.setFillColor(TEXT)
    c.drawString(inner_x, inner_y - 14,
                 "Security engineer  ·  Italy  ·  2026")
    c.setFont("Courier", 8)
    c.setFillColor(MUTED)
    c.drawString(inner_x, inner_y - 24,
                 "GitHub: to be announced  ·  License: Apache 2.0  ·  "
                 "Contact: via repo issues")

    footer_strip(c)
    c.showPage()


# ─── Build it ────────────────────────────────────────────────────────────────

def build():
    c = canvas.Canvas(OUT_PATH, pagesize=A4)
    c.setTitle("HAWK v1.0.0 — Hostile Assessment WorKit")
    c.setAuthor("Lorenzo Serafini")
    c.setSubject("HAWK v1.0.0 presentation")
    c.setKeywords(("HAWK", "pentest", "Kali", "open-source", "Lorenzo Serafini"))

    page_cover(c)
    page_what(c)
    page_why(c)
    page_inside(c)
    page_roadmap(c)

    c.save()
    print(f"Wrote {OUT_PATH}")


if __name__ == "__main__":
    build()
