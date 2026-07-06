# Phase 5a — Head Results (frozen embeddings). SHIP GATE = pg2+logreg.

Baseline (PG2 native): 22.81% recall @ 0.25% FPR (upper CI 28.3%).
Threshold picked on VALIDATION only (FPR<=1%); OOD touched once.

| emb+head | ID recall | ID FPR | **OOD recall** | OOD FPR | OOD prec | OOD AUC | verdict |
|---|---|---|---|---|---|---|---|
| pg2+logreg ⭐ | 59.6% [46.7,71.4] | 0.0% [0.0,7.9] | **99.7% [98.5,100.0]** | 2.2% [1.2,3.9] | 97.1% | 1.000 | NULL (FPR > 1%) |
| pg2+rf | 71.9% [59.2,81.9] | 0.0% [0.0,7.9] | **100.0% [99.0,100.0]** | 5.0% [3.4,7.3] | 93.6% | 1.000 | NULL (FPR > 1%) |
| arctic+logreg | 61.4% [48.4,72.9] | 0.0% [0.0,7.9] | **52.6% [47.5,57.7]** | 4.8% [3.3,7.1] | 88.8% | 0.901 | NULL (FPR > 1%) |
| arctic+rf | 57.9% [45.0,69.8] | 0.0% [0.0,7.9] | **40.2% [35.3,45.3]** | 5.8% [4.1,8.2] | 83.4% | 0.890 | NULL (FPR > 1%) |

## SHIP-GATE VERDICT (pg2+logreg): **NULL (FPR > 1%)**
OOD injections=363, benign=499