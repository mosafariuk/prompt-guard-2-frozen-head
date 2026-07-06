# Full-System Detection (Section VII / IX) — edge + Tier-3a

Model: `protectai/deberta-v3-base-prompt-injection-v2`  |  N=662 (malicious=263, benign=399)
Composition: full-system positive = edge hard-reject OR classifier malicious.

| Layer | Recall (mitigation) | FPR | Precision |
|-------|---------------------|-----|-----------|
| Edge only | 2.28% [1.05%, 4.89%] | 0.00% [0.00%, 0.95%] | 100.00% |
| Classifier only | 41.44% [35.66%, 47.48%] | 1.00% [0.39%, 2.55%] | 96.46% |
| **Full system** | **41.44% [35.66%, 47.48%]** | **1.00% [0.39%, 2.55%]** | 96.46% |

Edge-only recall was the 2.28% baseline (Section VII, Table III). The lift to the
full-system recall is the measured value of the escalation tier.
