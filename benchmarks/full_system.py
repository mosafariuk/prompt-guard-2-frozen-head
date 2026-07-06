"""Full-system detection benchmark: edge (deterministic) + Tier-3a (ML classifier).

Composes the two layers the way the deployed system does:
  full-system predicted-positive  =  edge hard-reject  OR  classifier == malicious
i.e. the edge cheaply blocks known signatures at 0% FPR, and the on-prem ML tier
provides recall on everything the edge did not hard-reject. Reports the recall LIFT
over edge-only, with Wilson 95% CIs — the measured, honest answer to "does the
layered architecture close the gap?" (paper Sections V-A, VII, IX).

Usage:
  # 1) produce edge decisions:  (in benchmarks/)  npm run detection
  # 2) run this with a chosen classifier:
  MODEL_ID=protectai/deberta-v3-base-prompt-injection-v2 python full_system.py
  # (Prompt Guard 2 is gated; set HF token + MODEL_ID=meta-llama/Llama-Prompt-Guard-2-86M)
"""
from __future__ import annotations
import json
import math
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "escalation-tier"))


def load_classifier():
    """Prefer the production torch/transformers path; fall back to ONNX runtime
    when torch is unavailable (e.g. x86_64/Rosetta Python with no torch wheel)."""
    try:
        from classifier import InjectionClassifier  # torch path
        return InjectionClassifier()
    except Exception as e:  # noqa: BLE001
        print(f"[torch path unavailable: {e}] -> using onnxruntime path", flush=True)
        from onnx_classifier import OnnxInjectionClassifier
        return OnnxInjectionClassifier()

Z = 1.959963985  # 95%


def wilson(k: int, n: int) -> tuple[float, float, float]:
    if n == 0:
        return (float("nan"),) * 3
    phat = k / n
    z2 = Z * Z
    denom = 1 + z2 / n
    center = (phat + z2 / (2 * n)) / denom
    half = (Z / denom) * math.sqrt(phat * (1 - phat) / n + z2 / (4 * n * n))
    return phat, max(0.0, center - half), min(1.0, center + half)


def confusion(preds: list[bool], labels: list[int]) -> dict:
    tp = sum(1 for p, y in zip(preds, labels) if p and y == 1)
    fp = sum(1 for p, y in zip(preds, labels) if p and y == 0)
    fn = sum(1 for p, y in zip(preds, labels) if not p and y == 1)
    tn = sum(1 for p, y in zip(preds, labels) if not p and y == 0)
    rec = wilson(tp, tp + fn)
    fpr = wilson(fp, fp + tn)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": rec, "fpr": fpr,
            "precision": (tp / (tp + fp)) if (tp + fp) else float("nan")}


def load_json(p: Path):
    return json.loads(p.read_text())


def main() -> None:
    corpus = None
    for f in ["corpus/payloads.json", "corpus/sample_payloads.json"]:
        p = HERE / f
        if p.exists():
            corpus = load_json(p)
            break
    if corpus is None:
        sys.exit("no corpus; run `npm run corpus`")
    rows = corpus["rows"]

    edge = load_json(HERE / "results" / "edge_decisions.json")["decisions"]
    if len(edge) != len(rows):
        sys.exit(f"edge_decisions ({len(edge)}) != corpus ({len(rows)}); re-run detection")

    print(f"Loading classifier MODEL_ID={os.environ.get('MODEL_ID', '(default)')} ...", flush=True)
    clf = load_classifier()
    print(f"Model: {clf.model_id}; scoring {len(rows)} payloads ...", flush=True)

    labels = [r["label"] for r in rows]
    edge_reject = [d["decision"] == "reject" for d in edge]
    edge_positive = [d["decision"] != "forward" for d in edge]  # reject or escalate

    clf_pos, scores = [], []
    for i, r in enumerate(rows):
        res = clf.classify(r["text"])
        clf_pos.append(res["score"] >= 0.5)
        scores.append(res["score"])
        if (i + 1) % 100 == 0:
            print(f"  {i + 1}/{len(rows)}", flush=True)

    full_positive = [er or cp for er, cp in zip(edge_reject, clf_pos)]

    out = {
        "model": clf.model_id,
        "n": len(rows),
        "malicious": sum(1 for y in labels if y == 1),
        "benign": sum(1 for y in labels if y == 0),
        "edge_only": confusion(edge_positive, labels),
        "classifier_only": confusion(clf_pos, labels),
        "full_system": confusion(full_positive, labels),
        "note": "full-system positive = edge hard-reject OR classifier malicious",
    }
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "full_system.json").write_text(json.dumps(out, indent=2))

    def pct(w):
        return f"{w[0]*100:.2f}% [{w[1]*100:.2f}%, {w[2]*100:.2f}%]"

    md = f"""# Full-System Detection (Section VII / IX) — edge + Tier-3a

Model: `{clf.model_id}`  |  N={out['n']} (malicious={out['malicious']}, benign={out['benign']})
Composition: full-system positive = edge hard-reject OR classifier malicious.

| Layer | Recall (mitigation) | FPR | Precision |
|-------|---------------------|-----|-----------|
| Edge only | {pct(out['edge_only']['recall'])} | {pct(out['edge_only']['fpr'])} | {out['edge_only']['precision']*100:.2f}% |
| Classifier only | {pct(out['classifier_only']['recall'])} | {pct(out['classifier_only']['fpr'])} | {out['classifier_only']['precision']*100:.2f}% |
| **Full system** | **{pct(out['full_system']['recall'])}** | **{pct(out['full_system']['fpr'])}** | {out['full_system']['precision']*100:.2f}% |

Edge-only recall was the 2.28% baseline (Section VII, Table III). The lift to the
full-system recall is the measured value of the escalation tier.
"""
    (HERE / "results" / "full_system.md").write_text(md)
    print(md)


if __name__ == "__main__":
    main()
