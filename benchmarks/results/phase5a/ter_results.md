# Phase 5a-ter — 99.5th-pct calibration, FRESH disjoint. SHIP GATE = pg2+logreg.

OOD: 800 fresh HackAPrompt injections + 2000 fresh dolly benign (near-dup dropped 0).
Threshold = 99.5th pct of 2000 same-dist calib benign (target ~0.5% FPR).

| emb+head | OOD Recall | OOD FPR | calib FPR | precision | AUC | verdict |
|---|---|---|---|---|---|---|
| pg2+logreg ⭐ | **99.9% [99.3,100.0]** | 0.7% [0.4,1.2] | 0.50% | 98.3% | 0.999 | SUCCESS |
| pg2+rf | **99.9% [99.3,100.0]** | 0.5% [0.3,0.9] | 0.50% | 98.8% | 1.000 | SUCCESS |
| arctic+logreg | **29.9% [26.8,33.1]** | 0.4% [0.2,0.9] | 0.50% | 96.4% | 0.887 | NULL |
| arctic+rf | **17.0% [14.6,19.8]** | 0.5% [0.3,0.9] | 0.50% | 93.2% | 0.887 | NULL |

## SHIP-GATE VERDICT (pg2+logreg): **SUCCESS**