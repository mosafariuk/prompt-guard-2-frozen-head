#!/usr/bin/env python3
"""Render the Phase-5 result as a dependency-free SVG: OOD recall vs. false-positive
rate, with the 1% ship-gate ceiling and the SUCCESS zone. No matplotlib/numpy needed.

Output: results/phase5a/recall_vs_fpr.svg
"""
from pathlib import Path

# (label, fpr%, fpr_lo, fpr_hi, recall%, rec_lo, rec_hi, kind)
RUNS = [
    ("PG2 native head",  0.25, 0.25, 0.25, 22.8, 20.0, 25.8, "base"),
    ("Phase 5a",         2.20, 1.60, 3.00, 99.7, 98.9, 99.9, "null"),
    ("Phase 5a-bis",     1.20, 0.80, 1.70, 99.9, 99.3, 100.0, "null"),
    ("Phase 5a-ter",     0.70, 0.40, 1.20, 99.9, 99.3, 100.0, "success"),
]
COL = {"base": "#6b7280", "null": "#d97706", "success": "#059669"}
INK, MUTE, FAINT = "#111827", "#6b7280", "#9ca3af"

W, H = 900, 520
L, R, T, B = 82, 846, 96, 424          # plot box
XMAX, YMAX = 2.6, 100.0

def px(fpr): return L + (fpr / XMAX) * (R - L)
def py(rec): return B - (rec / YMAX) * (B - T)

s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
     'font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif">']
s.append(f'<rect width="{W}" height="{H}" fill="#ffffff"/>')

# titles
s.append(f'<text x="{L}" y="36" font-size="21" font-weight="700" fill="{INK}">'
         'Frozen Prompt Guard&#8201;2 + linear head: 22.8%&#8202;&#8594;&#8202;99.9% OOD recall</text>')
s.append(f'<text x="{L}" y="60" font-size="13.5" fill="{MUTE}">'
         'Recall vs. false-positive rate on fresh out-of-distribution injections &#183; '
         'Wilson 95% CI &#183; pre-registered</text>')

# SUCCESS zone: FPR in [0,1], recall in [50,100]
s.append(f'<rect x="{px(0):.1f}" y="{py(100):.1f}" width="{px(1.0)-px(0):.1f}" height="{py(50)-py(100):.1f}" '
         'fill="#059669" fill-opacity="0.08"/>')
s.append(f'<text x="{px(0.5):.1f}" y="{py(64):.1f}" font-size="12" font-weight="600" fill="#059669" '
         'text-anchor="middle">SHIP-GATE / SUCCESS zone</text>')
s.append(f'<text x="{px(0.5):.1f}" y="{py(64)+15:.1f}" font-size="10.5" fill="#059669" text-anchor="middle">'
         'recall &#8805; 50%, FPR &#8804; 1%</text>')

# gridlines + axes
for r in range(0, 101, 20):
    y = py(r)
    s.append(f'<line x1="{L}" y1="{y:.1f}" x2="{R}" y2="{y:.1f}" stroke="#eef0f2" stroke-width="1"/>')
    s.append(f'<text x="{L-9}" y="{y+4:.1f}" font-size="12" fill="{MUTE}" text-anchor="end">{r}</text>')
s.append(f'<line x1="{L}" y1="{B}" x2="{R}" y2="{B}" stroke="#374151" stroke-width="1.4"/>')
s.append(f'<line x1="{L}" y1="{T}" x2="{L}" y2="{B}" stroke="#374151" stroke-width="1.4"/>')
for v in [0.0, 0.5, 1.0, 1.5, 2.0, 2.5]:
    x = px(v)
    s.append(f'<line x1="{x:.1f}" y1="{B}" x2="{x:.1f}" y2="{B+5}" stroke="#374151" stroke-width="1"/>')
    s.append(f'<text x="{x:.1f}" y="{B+20}" font-size="12" fill="{MUTE}" text-anchor="middle">{v:g}</text>')
s.append(f'<text x="{(L+R)/2:.1f}" y="{B+42}" font-size="13.5" fill="#374151" text-anchor="middle">'
         'False-positive rate (%)</text>')
s.append(f'<text transform="translate(28,{(T+B)/2:.1f}) rotate(-90)" font-size="13.5" fill="#374151" '
         'text-anchor="middle">OOD recall (%)</text>')

# 1% FPR ceiling
xc = px(1.0)
s.append(f'<line x1="{xc:.1f}" y1="{T}" x2="{xc:.1f}" y2="{B}" stroke="#dc2626" stroke-width="1.6" '
         'stroke-dasharray="6 4"/>')
s.append(f'<text x="{xc-7:.1f}" y="{B-8:.1f}" font-size="12" font-weight="600" fill="#dc2626" '
         'text-anchor="end">1% FPR ceiling</text>')

# points with CI error bars
def cap(x, y, horiz):
    d = 4
    if horiz:
        return f'<line x1="{x:.1f}" y1="{y-d:.1f}" x2="{x:.1f}" y2="{y+d:.1f}" stroke-width="1.2"/>'
    return f'<line x1="{x-d:.1f}" y1="{y:.1f}" x2="{x+d:.1f}" y2="{y:.1f}" stroke-width="1.2"/>'

for label, f, flo, fhi, rec, rlo, rhi, kind in RUNS:
    c = COL[kind]; x, y = px(f), py(rec)
    s.append(f'<g stroke="{c}" opacity="0.75">')
    s.append(f'<line x1="{px(flo):.1f}" y1="{y:.1f}" x2="{px(fhi):.1f}" y2="{y:.1f}" stroke-width="1.4"/>')
    s.append(cap(px(flo), y, True)); s.append(cap(px(fhi), y, True))
    s.append(f'<line x1="{x:.1f}" y1="{py(rlo):.1f}" x2="{x:.1f}" y2="{py(rhi):.1f}" stroke-width="1.4"/>')
    s.append(cap(x, py(rlo), False)); s.append(cap(x, py(rhi), False))
    s.append('</g>')
    if kind == "success":
        s.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="13" fill="none" stroke="{c}" stroke-width="1.6" opacity="0.45"/>')
        s.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="8.5" fill="{c}"/>')
    else:
        s.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6.5" fill="{c}"/>')

def block(x, y, lines, anchor="start"):
    for i, (txt, sz, col, w) in enumerate(lines):
        s.append(f'<text x="{x:.1f}" y="{y+i*15:.1f}" font-size="{sz}" font-weight="{w}" fill="{col}" '
                 f'text-anchor="{anchor}">{txt}</text>')

# native — lower-left, beside its point
block(px(0.25)+14, py(22.8)+1, [("PG2 native head", 12.5, "#374151", "600"),
                                ("22.8% recall @ 0.25% FPR", 11.5, MUTE, "400")])
# 5a-ter — inside success zone, well below its point (leader line up to the point)
s.append(f'<line x1="{px(0.55):.1f}" y1="{py(88):.1f}" x2="{px(0.69):.1f}" y2="{py(99):.1f}" '
         f'stroke="{COL["success"]}" stroke-width="1" opacity="0.5"/>')
block(px(0.08), py(84), [("Phase 5a-ter — SUCCESS", 13, COL["success"], "700"),
                         ("99.9% [99.3, 100] @ 0.7% FPR", 11.5, MUTE, "400"),
                         ("AUC 0.999 · fresh disjoint data", 11, FAINT, "400")])
# 5a-bis — just right of ceiling, below its point
block(px(1.27), py(86), [("Phase 5a-bis — NULL", 12.5, COL["null"], "600"),
                         ("99.9% @ 1.2% [0.8, 1.7]", 11.5, MUTE, "400"),
                         ("CI included 1% — held NULL", 11, FAINT, "400")])
# 5a — top right, extending left from near the edge
block(px(2.58), py(88), [("Phase 5a — NULL", 12.5, COL["null"], "600"),
                         ("99.7% @ 2.2% FPR", 11.5, MUTE, "400")], anchor="end")

s.append('</svg>')

out = Path(__file__).resolve().parent / "results" / "phase5a" / "recall_vs_fpr.svg"
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("\n".join(s))
print("wrote", out)
