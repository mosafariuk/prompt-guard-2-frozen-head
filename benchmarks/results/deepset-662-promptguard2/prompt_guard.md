# Full-System Detection — Edge + Llama Prompt Guard 2 86M (independent, multilingual)

Model: `meta-llama/Llama-Prompt-Guard-2-86M` (CPU)  |  Corpus: deepset/prompt-injections, N=662 (malicious=263, benign=399; DE+EN)  |  skipped/errored=0
Composition: full-system positive = edge hard-reject OR Prompt Guard 2 == malicious.

| Configuration | Recall (Mitigation) | FPR | Precision |
|---------------|---------------------|-----|-----------|
| Edge only | 2.28% [1.05%, 4.89%] | 0.00% [0.00%, 0.95%] | 100.00% |
| Prompt Guard 2 only | 22.81% [18.15%, 28.26%] | 0.25% [0.04%, 1.41%] | 98.36% |
| **Full System (Edge + Prompt Guard 2 86M)** | **22.81% [18.15%, 28.26%]** | **0.25% [0.04%, 1.41%]** | 98.36% |

All figures are independently measured on the bilingual deepset corpus (NOT vendor
self-reported). Confidence intervals are Wilson score at 95%.
