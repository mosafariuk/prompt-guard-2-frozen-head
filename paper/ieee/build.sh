#!/usr/bin/env bash
# Reproducible build: markdown sections -> pandoc -> fixup -> two-column IEEEtran PDF.
# Requires: pandoc, tectonic (brew install pandoc tectonic).
set -euo pipefail
cd "$(dirname "$0")/.."   # -> paper/

# 1. Assemble the body (sections I..X + appendices + references); strip provenance blockquotes.
cat 01_introduction.md 02_threat_model.md 03_edge_isolate_architecture.md \
    04_cryptographic_tenant_isolation.md 05_nlp_heuristics.md 06_async_threat_logging.md \
    07_evaluation.md 08_related_work_limitations_conclusion.md 09_appendices.md 10_references.md \
  | grep -vE '^> (Evidence status|Citation keys|Reviewer|Evidence caveat|Evidence status for)' \
  > ieee/body.md

# 2. Convert to a LaTeX fragment (\input{body} in main.tex).
pandoc ieee/body.md --from gfm+tex_math_dollars --to latex \
  --top-level-division=section --listings -o ieee/body.tex

# 3. Two-column post-processing (tables, glyphs, wide-equation shrink-to-fit).
python3 ieee/fixup.py ieee/body.tex

# 4. Compile (tectonic auto-fetches IEEEtran + packages).
cd ieee && tectonic main.tex
echo "built: $(pwd)/main.pdf"
