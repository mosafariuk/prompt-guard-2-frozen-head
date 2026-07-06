"""Phase 5a Step 3 — train a lightweight head on frozen embeddings; measure OOD ONCE.

Pre-registered protocol (docs/phase5a_finetune_scoping.md):
  - Fit head on TRAIN embeddings only.
  - Select the operating threshold on VALIDATION only, for FPR <= 1%.
  - Apply that exact threshold to the OOD test set EXACTLY ONCE.
  - Ship gate = PG2 embeddings + Logistic Regression. Other rows (arctic, RF) are
    disclosed secondary comparisons, reported for completeness, NOT the gate.
  SUCCESS = OOD recall >= 50% @ FPR <= 1% with Wilson lower bound > baseline upper
            (baseline PG2 22.81% [18.15, 28.26] -> upper 0.2826).
  PARTIAL = OOD recall in [30%, 50%) @ FPR <= 1%.  NULL = otherwise.
"""
from __future__ import annotations
import json, math
from pathlib import Path
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score

HERE = Path(__file__).resolve().parent
C = HERE / "corpus5a"
Z = 1.959963985
BASELINE_UPPER = 0.2826   # PG2 recall Wilson upper bound (§VII Table IV)


def wilson(k, n):
    if n == 0: return (float("nan"),) * 3
    p = k / n; z2 = Z * Z; d = 1 + z2 / n
    c = (p + z2 / (2 * n)) / d
    h = (Z / d) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return p, max(0.0, c - h), min(1.0, c + h)


def labels(split):
    return np.array([json.loads(l)["label"] for l in (C / f"{split}.jsonl").read_text().splitlines()])


def pick_threshold(scores, y, max_fpr=0.01):
    """Smallest threshold with validation FPR <= max_fpr (recall-maximizing at the cap)."""
    benign = np.sort(scores[y == 0])[::-1]
    allowed = int(np.floor(max_fpr * len(benign)))
    if allowed == 0:
        return np.nextafter(benign.max(), np.inf) if len(benign) else 0.5
    return benign[allowed - 1]  # just above the allowed-th highest benign score


def metrics_at(scores, y, t):
    pred = scores >= t
    tp = int(((pred == 1) & (y == 1)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    return {"recall": wilson(tp, tp + fn), "fpr": wilson(fp, fp + tn),
            "precision": tp / (tp + fp) if (tp + fp) else float("nan"),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def run(emb_name, head_name):
    Xtr = np.load(C / f"train.{emb_name}.npy"); ytr = labels("train")
    Xva = np.load(C / f"val.{emb_name}.npy"); yva = labels("val")
    Xod = np.load(C / f"ood_test.{emb_name}.npy"); yod = labels("ood_test")
    clf = (LogisticRegression(max_iter=2000, class_weight="balanced", C=1.0)
           if head_name == "logreg" else
           RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0, n_jobs=-1))
    clf.fit(Xtr, ytr)
    sva = clf.predict_proba(Xva)[:, 1]; sod = clf.predict_proba(Xod)[:, 1]
    t = pick_threshold(sva, yva, 0.01)                 # VALIDATION ONLY
    val_m = metrics_at(sva, yva, t)                    # in-distribution at t
    ood_m = metrics_at(sod, yod, t)                    # OOD touched ONCE at t
    ood_m["auc"] = float(roc_auc_score(yod, sod)) if len(set(yod)) > 1 else float("nan")
    return {"emb": emb_name, "head": head_name, "threshold": float(t), "val": val_m, "ood": ood_m}


def verdict(ood):
    r, rlo = ood["recall"][0], ood["recall"][1]; fpr = ood["fpr"][0]
    if fpr > 0.01: return "NULL (FPR > 1%)"
    if r >= 0.50 and rlo > BASELINE_UPPER: return "SUCCESS"
    if 0.30 <= r < 0.50: return "PARTIAL"
    if r >= 0.50 and rlo <= BASELINE_UPPER: return "PARTIAL (point >=50% but CI overlaps baseline)"
    return "NULL"


def main():
    configs = [("pg2", "logreg"), ("pg2", "rf"), ("arctic", "logreg"), ("arctic", "rf")]
    results = [run(e, h) for e, h in configs]
    (C / "head_results.json").write_text(json.dumps(results, indent=2, default=list))

    def pc(w): return f"{w[0]*100:.1f}% [{w[1]*100:.1f},{w[2]*100:.1f}]"
    lines = ["# Phase 5a — Head Results (frozen embeddings). SHIP GATE = pg2+logreg.",
             f"\nBaseline (PG2 native): 22.81% recall @ 0.25% FPR (upper CI {BASELINE_UPPER*100:.1f}%).",
             "Threshold picked on VALIDATION only (FPR<=1%); OOD touched once.\n",
             "| emb+head | ID recall | ID FPR | **OOD recall** | OOD FPR | OOD prec | OOD AUC | verdict |",
             "|---|---|---|---|---|---|---|---|"]
    for r in results:
        gate = " ⭐" if (r["emb"], r["head"]) == ("pg2", "logreg") else ""
        v = verdict(r["ood"])
        lines.append(f"| {r['emb']}+{r['head']}{gate} | {pc(r['val']['recall'])} | {pc(r['val']['fpr'])} | "
                     f"**{pc(r['ood']['recall'])}** | {pc(r['ood']['fpr'])} | {r['ood']['precision']*100:.1f}% | "
                     f"{r['ood']['auc']:.3f} | {v} |")
    gate_row = next(r for r in results if (r["emb"], r["head"]) == ("pg2", "logreg"))
    lines.append(f"\n## SHIP-GATE VERDICT (pg2+logreg): **{verdict(gate_row['ood'])}**")
    lines.append(f"OOD injections={gate_row['ood']['tp']+gate_row['ood']['fn']}, "
                 f"benign={gate_row['ood']['fp']+gate_row['ood']['tn']}")
    (C / "head_results.md").write_text("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
