# Phase 5a-bis — recalibrated OOD (fresh disjoint). SHIP GATE = pg2+logreg.

OOD: 800 fresh HackAPrompt injections + 1999 fresh dolly benign (near-dup dropped 1).
Threshold = 99th pct of 2000 same-distribution dolly-calib benign (FPR<=1% by construction).

| emb+head | OOD Recall | OOD FPR | calib FPR | precision | AUC | verdict |
|---|---|---|---|---|---|---|
| pg2+logreg ⭐ | **99.9% [99.3,100.0]** | 1.2% [0.8,1.7] | 1.0% | 97.2% | 1.000 | NULL (FPR 1.2% > 1%) |
| pg2+rf | **100.0% [99.5,100.0]** | 1.1% [0.7,1.6] | 1.0% | 97.4% | 1.000 | NULL (FPR 1.1% > 1%) |
| arctic+logreg | **36.1% [32.9,39.5]** | 1.4% [0.9,2.0] | 1.0% | 91.5% | 0.884 | NULL (FPR 1.4% > 1%) |
| arctic+rf | **27.5% [24.5,30.7]** | 1.2% [0.8,1.7] | 1.1% | 90.5% | 0.884 | NULL (FPR 1.2% > 1%) |

## SHIP-GATE VERDICT (pg2+logreg): **NULL (FPR 1.2% > 1%)**