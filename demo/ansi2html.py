#!/usr/bin/env python3
"""Tiny ANSI (SGR) -> HTML converter used to render demo screenshots. stdin -> stdout."""
import html, re, sys

PALETTE = {30: "#1d1f21", 31: "#ff5f56", 32: "#5af78e", 33: "#f3f99d", 34: "#57c7ff",
           35: "#ff6ac1", 36: "#9aedfe", 37: "#f1f1f0", 90: "#686868", 91: "#ff5f56",
           92: "#5af78e", 93: "#f3f99d", 94: "#57c7ff", 95: "#ff6ac1", 96: "#9aedfe", 97: "#ffffff"}

def convert(text):
    out, st = [], {}
    def span(chunk):
        if not chunk:
            return
        css = []
        fg, bg = st.get("fg"), st.get("bg")
        if st.get("rev"):
            fg, bg = bg or "#1d1f21", fg or "#f1f1f0"
        if fg: css.append(f"color:{fg}")
        if bg: css.append(f"background:{bg}")
        if st.get("bold"): css.append("font-weight:bold")
        if st.get("dim"): css.append("opacity:.6")
        if st.get("ital"): css.append("font-style:italic")
        if st.get("ul"): css.append("text-decoration:underline")
        e = html.escape(chunk)
        out.append(f'<span style="{";".join(css)}">{e}</span>' if css else e)
    pos = 0
    for m in re.finditer(r"\x1b\[([0-9;]*)m", text):
        span(text[pos:m.start()]); pos = m.end()
        codes = [int(c) for c in m.group(1).split(";") if c] or [0]
        for c in codes:
            if c == 0: st = {}
            elif c == 1: st["bold"] = True
            elif c == 2: st["dim"] = True
            elif c == 3: st["ital"] = True
            elif c == 4: st["ul"] = True
            elif c == 7: st["rev"] = True
            elif c == 22: st.pop("bold", None); st.pop("dim", None)
            elif c == 39: st.pop("fg", None)
            elif c == 49: st.pop("bg", None)
            elif c in PALETTE: st["fg"] = PALETTE[c]
            elif 40 <= c <= 47 or 100 <= c <= 107: st["bg"] = PALETTE[c - 10]
    span(text[pos:])
    return "".join(out)

body = convert(sys.stdin.read())
print(f"""<!doctype html><meta charset="utf-8"><style>
body{{margin:0;background:#0f1115}}
.term{{margin:18px;padding:18px 22px;background:#1a1c22;border-radius:10px;
box-shadow:0 8px 30px #0008;color:#e6e6e6;font:15px/1.38 'DejaVu Sans Mono','Menlo',monospace;
white-space:pre;display:inline-block}}
.bar{{margin-bottom:12px}}.bar i{{display:inline-block;width:12px;height:12px;border-radius:6px;margin-right:7px}}
</style><div class="term"><div class="bar"><i style="background:#ff5f56"></i><i style="background:#ffbd2e"></i><i style="background:#27c93f"></i></div>{body}</div>""")
