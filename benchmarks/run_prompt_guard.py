"""Step 1 — Independent multilingual benchmark of Llama Prompt Guard 2 86M.

Loads meta-llama/Llama-Prompt-Guard-2-86M (gated; needs HF_TOKEN in the env),
streams the 662-row bilingual (DE+EN) deepset corpus through it on CPU, and reports
the real, independent Confusion Matrix / Recall / FPR with Wilson 95% intervals,
composing with the edge layer for a full-system table for Section VII.

SECURITY: the HF token is read ONLY from the HF_TOKEN environment variable and is
never written to disk or logged. Do not pass it as a literal.

Run:
  HF_TOKEN=hf_xxx MODEL_ID=meta-llama/Llama-Prompt-Guard-2-86M \
    <arm64-python> benchmarks/run_prompt_guard.py
"""
from __future__ import annotations
import json
import math
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODEL_ID = os.environ.get("MODEL_ID", "meta-llama/Llama-Prompt-Guard-2-86M")
MAX_TOKENS = int(os.environ.get("MAX_TOKENS", "512"))
Z = 1.959963985  # 95%
# Label strings (lowercased) that denote a positive (malicious/attack) prediction.
POSITIVE = {"malicious", "injection", "jailbreak", "label_1", "1", "unsafe", "inj"}


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
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": wilson(tp, tp + fn),
        "fpr": wilson(fp, fp + tn),
        "precision": (tp / (tp + fp)) if (tp + fp) else float("nan"),
    }


def load_json(p: Path):
    return json.loads(p.read_text())


def main() -> None:
    token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")
    if not token:
        sys.exit("HF_TOKEN not set in environment (required for the gated Prompt Guard 2).")

    # Import here so a missing torch fails with a clear, actionable message.
    try:
        import torch
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
    except Exception as e:  # noqa: BLE001
        sys.exit(f"transformers/torch unavailable: {e}\n"
                 "Prompt Guard 2 ships only safetensors (no ONNX), so torch is required. "
                 "Use an arm64/linux Python where a torch wheel exists.")

    corpus = None
    for f in ["corpus/payloads.json", "corpus/sample_payloads.json"]:
        p = HERE / f
        if p.exists():
            corpus = load_json(p)
            break
    if corpus is None:
        sys.exit("no corpus; run `npm run corpus` first.")
    rows = corpus["rows"]

    edge_path = HERE / "results" / "edge_decisions.json"
    if not edge_path.exists():
        sys.exit("results/edge_decisions.json missing; run `npm run detection` first.")
    edge = load_json(edge_path)["decisions"]
    if len(edge) != len(rows):
        sys.exit(f"edge_decisions ({len(edge)}) != corpus ({len(rows)}); re-run detection.")

    print(f"Loading {MODEL_ID} on CPU ...", flush=True)
    tok = AutoTokenizer.from_pretrained(MODEL_ID, token=token)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID, token=token)
    model.eval()

    # Dynamically resolve the malicious class index from the model's own mapping.
    id2label = model.config.id2label
    positive_ids = [i for i, name in id2label.items() if str(name).strip().lower() in POSITIVE]
    if not positive_ids:
        positive_ids = [max(id2label.keys())]  # binary fallback: last index = positive
    print(f"id2label={id2label} -> positive class ids={positive_ids}", flush=True)

    labels = [r["label"] for r in rows]
    clf_pos: list[bool] = []
    scores: list[float] = []
    errors = 0

    with torch.no_grad():
        for i, r in enumerate(rows):
            text = r.get("text")
            # Hardening against malformed enterprise webhook bodies.
            if not isinstance(text, str) or not text.strip():
                clf_pos.append(False)
                scores.append(0.0)
                errors += 1
                continue
            try:
                enc = tok(text, truncation=True, max_length=MAX_TOKENS, return_tensors="pt")
                logits = model(**enc).logits[0]
                probs = torch.softmax(logits, dim=-1)
                score = float(sum(probs[j] for j in positive_ids))
            except Exception as e:  # noqa: BLE001 — never let one payload abort the run
                print(f"  [warn] payload {i} failed: {e}", flush=True)
                score = 0.0
                errors += 1
            clf_pos.append(score >= 0.5)
            scores.append(score)
            if (i + 1) % 100 == 0:
                print(f"  {i + 1}/{len(rows)}", flush=True)

    edge_reject = [d["decision"] == "reject" for d in edge]
    edge_positive = [d["decision"] != "forward" for d in edge]
    full_positive = [er or cp for er, cp in zip(edge_reject, clf_pos)]

    out = {
        "model": MODEL_ID,
        "n": len(rows),
        "malicious": sum(1 for y in labels if y == 1),
        "benign": sum(1 for y in labels if y == 0),
        "skipped_or_errored": errors,
        "edge_only": confusion(edge_positive, labels),
        "classifier_only": confusion(clf_pos, labels),
        "full_system": confusion(full_positive, labels),
    }
    (HERE / "results").mkdir(exist_ok=True)
    (HERE / "results" / "prompt_guard.json").write_text(json.dumps(out, indent=2))

    def pct(w):
        return f"{w[0] * 100:.2f}% [{w[1] * 100:.2f}%, {w[2] * 100:.2f}%]"

    md = f"""# Full-System Detection — Edge + Llama Prompt Guard 2 86M (independent, multilingual)

Model: `{MODEL_ID}` (CPU)  |  Corpus: deepset/prompt-injections, N={out['n']} \
(malicious={out['malicious']}, benign={out['benign']}; DE+EN)  |  skipped/errored={errors}
Composition: full-system positive = edge hard-reject OR Prompt Guard 2 == malicious.

| Configuration | Recall (Mitigation) | FPR | Precision |
|---------------|---------------------|-----|-----------|
| Edge only | {pct(out['edge_only']['recall'])} | {pct(out['edge_only']['fpr'])} | {out['edge_only']['precision'] * 100:.2f}% |
| Prompt Guard 2 only | {pct(out['classifier_only']['recall'])} | {pct(out['classifier_only']['fpr'])} | {out['classifier_only']['precision'] * 100:.2f}% |
| **Full System (Edge + Prompt Guard 2 86M)** | **{pct(out['full_system']['recall'])}** | **{pct(out['full_system']['fpr'])}** | {out['full_system']['precision'] * 100:.2f}% |

All figures are independently measured on the bilingual deepset corpus (NOT vendor
self-reported). Confidence intervals are Wilson score at 95%.
"""
    (HERE / "results" / "prompt_guard.md").write_text(md)
    print(md)


if __name__ == "__main__":
    main()
