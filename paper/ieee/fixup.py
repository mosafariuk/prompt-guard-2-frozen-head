#!/usr/bin/env python3
"""Post-process pandoc's LaTeX (body.tex) for two-column IEEEtran compilation.
Idempotent-ish transforms: escaped-star in proofs, longtable->full-width table*,
box-drawing + prose math glyphs, and shrink-to-fit wrapping of wide display equations."""
import sys, re

p = sys.argv[1]
t = open(p).read()

# 1. Markdown-escaped asterisks in crypto superscripts (m^\* -> m^*).
t = t.replace('\\*', '*')

# 2. pandoc longtable -> full-width (table*) shrink-to-fit float (longtable can't
#    span IEEEtran two-column mode).
def conv(m):
    cols, inner = m.group(1), m.group(2)
    inner = re.sub(r'\\endhead|\\endfirsthead|\\endlastfoot|\\endfoot', '', inner)
    inner = inner.replace('\\noalign{}', '').replace('\\bottomrule', '').strip()
    inner = re.sub(r'^\\toprule\s*', '', inner)
    return ('\\begin{table*}[!t]\\centering\\scriptsize\n\\resizebox{\\textwidth}{!}{%\n'
            '\\begin{tabular}{' + cols + '}\n\\toprule\n' + inner +
            '\n\\bottomrule\n\\end{tabular}}\n\\end{table*}')
t = re.sub(r'\\begin\{longtable\}\[\]\{([^\n]*)\}\n(.*?)\\end\{longtable\}', conv, t, flags=re.S)

# 3. Unicode glyphs -> LaTeX. Arrows/box-drawing/prose-math must be converted BEFORE
#    the strip step below (which drops any remaining non-Latin-1 pictographs).
glyph = {
    '┌': '+', '┐': '+', '└': '+', '┘': '+', '├': '+', '┤': '+', '┬': '+', '┴': '+',
    '┼': '+', '─': '-', '│': '|', '┃': '|', '━': '-', '▼': 'v', '▲': '^', '▶': '>', '◀': '<',
    '→': r'$\to$', '⇒': r'$\Rightarrow$', '↦': r'$\mapsto$',
    '≈': r'$\approx$', '≥': r'$\ge$', '≤': r'$\le$', '×': r'$\times$', '≠': r'$\ne$',
    '∅': r'$\emptyset$', '∈': r'$\in$', '∪': r'$\cup$', '∩': r'$\cap$', '⊂': r'$\subset$',
    '⊕': r'$\oplus$', '∥': r'$\|$', '‖': r'$\|$', '·': r'$\cdot$', '±': r'$\pm$',
    '✓': r'\checkmark', '✗': r'$\times$', '⭐': '', '†': r'$\dagger$', '≡': r'$\equiv$',
}
for k, v in glyph.items():
    t = t.replace(k, v)

# 4. Drop any remaining emoji/pictographs (keep Latin-1 + core math block 0x2200-0x22FF).
t = ''.join(ch for ch in t if ord(ch) < 0x2190 or (0x2200 <= ord(ch) < 0x2300))

# 5. Shrink-to-fit any UNTAGGED display equation so wide ones cannot overflow a column.
#    Tagged equations (Eq. 1, 2) are narrow and left intact (\tag only valid outside \fiteq).
def wrap(m):
    c = m.group(1)
    return m.group(0) if '\\tag' in c else '\\fiteq{' + c + '}'
t = re.sub(r'\\\[(.*?)\\\]', wrap, t, flags=re.S)

open(p, 'w').write(t)
print("fixup applied")
