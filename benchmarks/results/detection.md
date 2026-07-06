# Detection Efficacy (Section VII-D) — local-screening

Corpus: deepset/prompt-injections (Hugging Face), Apache 2.0. Fetched via datasets-server. train=546, test=116, total=662. label: 1=injection, 0=legit.
N=662  (malicious=263, benign=399)

## Confusion matrix
|          | pred + | pred - |
|----------|--------|--------|
| actual + | 6 (TP) | 257 (FN) |
| actual - | 0 (FP) | 399 (TN) |

## Rates (Wilson 95% CI)
| metric | value [95% CI] |
|--------|----------------|
| Mitigation (Recall) | 2.28% [1.05%, 4.89%] |
| Precision | 100.00% [60.97%, 100.00%] |
| FPR | 0.00% [0.00%, 0.95%] |
| FNR | 97.72% [95.11%, 98.95%] |

> ">99% mitigation" is credited only if the Recall **lower** bound exceeds 99%.
> Lower bound here: 1.05% (N may be too small for a 0.99 lower bound — report honestly).

## Per-family recall (malicious only)
| family | recall | tp/total |
|--------|--------|----------|
| direct_override | 11.32% | 6/53 |
| other | 0.00% | 0/204 |
| roleplay | 0.00% | 0/6 |
