"""Phase 5a-bis — recalibrated OOD test on FRESH, disjoint, never-scored data.

Fixes the 5a flaw: the ship threshold is now calibrated on a LARGE benign set drawn
from the SAME distribution as the OOD-test benign (dolly), so the FPR line transfers.

Honesty controls:
  - EXCLUDE every text hash already used/scored in 5a (train + val + ood_test).
  - Fresh HackAPrompt injections + fresh dolly benign (disjoint calib vs test).
  - Near-dup drop (arctic cosine >= 0.95) of OOD vs the (unchanged) 5a train set.
  - Train head on the SAME cached PG2 train embeddings. OOD touched EXACTLY once.
Ship gate = pg2 + logreg. SUCCESS = OOD recall >= 50% @ FPR <= 1%, Wilson lower > 28.3%.
"""
from __future__ import annotations
import json, os, re, hashlib, math
from pathlib import Path
import numpy as np
from datasets import load_dataset
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sentence_transformers import SentenceTransformer

HERE = Path(__file__).resolve().parent
C = HERE / "corpus5a"
SEED = 20260706  # distinct from 5a's 20260705
Z = 1.959963985
BASELINE_UPPER = 0.2826
N_INJ, N_CALIB, N_TEST = 800, 2000, 2000
PG2 = os.environ.get("MODEL_ID", "meta-llama/Llama-Prompt-Guard-2-86M")
rng = np.random.default_rng(SEED)


def norm(t): return re.sub(r"\s+", " ", (t or "").strip().lower())
def H(t): return hashlib.sha1(norm(t).encode()).hexdigest()
def wilson(k, n):
    if n == 0: return (float("nan"),) * 3
    p = k / n; z2 = Z * Z; d = 1 + z2 / n
    c = (p + z2 / (2 * n)) / d
    h = (Z / d) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return p, max(0.0, c - h), min(1.0, c + h)
def metrics_at(s, y, t):
    pred = s >= t
    tp = int(((pred) & (y == 1)).sum()); fn = int(((~pred) & (y == 1)).sum())
    fp = int(((pred) & (y == 0)).sum()); tn = int(((~pred) & (y == 0)).sum())
    return {"recall": wilson(tp, tp+fn), "fpr": wilson(fp, fp+tn),
            "precision": tp/(tp+fp) if (tp+fp) else float("nan"), "tp": tp, "fp": fp, "fn": fn, "tn": tn}
def uniq_new(texts, spent):
    seen = set(); out = []
    for t in texts:
        if not (isinstance(t, str) and t.strip()): continue
        k = H(t)
        if k in spent or k in seen: continue
        seen.add(k); out.append(t)
    return out
def sample(lst, n):
    lst = list(lst)
    if len(lst) <= n: return lst
    return [lst[i] for i in rng.choice(len(lst), n, replace=False)]


def main():
    tok = os.environ.get("HF_TOKEN")
    # everything already used/scored in 5a -> excluded
    spent = set()
    for f in ["train", "val", "ood_test"]:
        for l in (C / f"{f}.jsonl").read_text().splitlines():
            spent.add(H(json.loads(l)["text"]))

    print("fetching FRESH disjoint HackAPrompt injections ...", flush=True)
    hp = load_dataset("hackaprompt/hackaprompt-dataset", split="train", token=tok)
    col = next(c for c in ["prompt", "user_input", "prompt_text", "text"] if c in hp.column_names)
    hp_pool = uniq_new((hp[i][col] for i in range(min(len(hp), 60000))), spent)
    hp_fresh = sample(hp_pool, N_INJ)

    print("fetching FRESH disjoint dolly benign (calib + test) ...", flush=True)
    dl = load_dataset("databricks/databricks-dolly-15k", split="train")
    dolly = uniq_new((r["instruction"] for r in dl), spent)
    rng.shuffle(dolly)
    calib_b = dolly[:N_CALIB]; test_b = dolly[N_CALIB:N_CALIB + N_TEST]

    ood_rows = [{"text": t, "label": 1} for t in hp_fresh] + [{"text": t, "label": 0} for t in test_b]

    # near-dup drop OOD vs the unchanged 5a train set (arctic cosine >= 0.95)
    print("near-dup filtering OOD vs train (arctic) ...", flush=True)
    arctic = SentenceTransformer("Snowflake/snowflake-arctic-embed-m", device="cpu")
    tr_arctic = np.load(C / "train.arctic.npy")
    def enc_arctic(txts): return arctic.encode(txts, normalize_embeddings=True, batch_size=64, show_progress_bar=False).astype(np.float32)
    ood_arc = enc_arctic([r["text"] for r in ood_rows])
    keep = [i for i in range(len(ood_rows)) if (ood_arc[i] @ tr_arctic.T).max() < 0.95]
    dropped = len(ood_rows) - len(keep)
    ood_rows = [ood_rows[i] for i in keep]; ood_arc = ood_arc[keep]
    calib_arc = enc_arctic(calib_b)
    print(f"  near-dup dropped from OOD: {dropped}", flush=True)

    # PG2 penultimate (pooler) embeddings for calib + ood
    print("extracting PG2 embeddings for calib + OOD ...", flush=True)
    tk = AutoTokenizer.from_pretrained(PG2, token=tok)
    model = AutoModelForSequenceClassification.from_pretrained(PG2, token=tok).eval()
    base = getattr(model, "deberta", None) or model.base_model
    pooler = getattr(model, "pooler", None)
    @torch.no_grad()
    def enc_pg2(txts):
        out = []
        for i in range(0, len(txts), 32):
            e = tk(txts[i:i+32], padding=True, truncation=True, max_length=512, return_tensors="pt")
            hs = base(**e).last_hidden_state
            out.append((pooler(hs) if pooler is not None else hs[:, 0]).cpu().numpy().astype(np.float32))
        return np.concatenate(out) if out else np.zeros((0, model.config.hidden_size), np.float32)
    ood_pg2 = enc_pg2([r["text"] for r in ood_rows]); calib_pg2 = enc_pg2(calib_b)

    yood = np.array([r["label"] for r in ood_rows])
    ytr = np.array([json.loads(l)["label"] for l in (C / "train.jsonl").read_text().splitlines()])

    def run(emb, Xtr, Xcal, Xood, head):
        clf = (LogisticRegression(max_iter=2000, class_weight="balanced")
               if head == "logreg" else RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0, n_jobs=-1))
        clf.fit(Xtr, ytr)
        scal = clf.predict_proba(Xcal)[:, 1]; sood = clf.predict_proba(Xood)[:, 1]
        t = float(np.quantile(scal, 0.99))            # <=1% FPR on SAME-dist calib benign
        m = metrics_at(sood, yood, t)
        m["auc"] = float(roc_auc_score(yood, sood)) if len(set(yood)) > 1 else float("nan")
        m["thr"] = t; m["calib_fpr"] = float((scal >= t).mean())
        return {"emb": emb, "head": head, **m}

    Xtr_pg2 = np.load(C / "train.pg2.npy"); Xtr_arc = np.load(C / "train.arctic.npy")
    results = [run("pg2", Xtr_pg2, calib_pg2, ood_pg2, "logreg"),
               run("pg2", Xtr_pg2, calib_pg2, ood_pg2, "rf"),
               run("arctic", Xtr_arc, calib_arc, ood_arc, "logreg"),
               run("arctic", Xtr_arc, calib_arc, ood_arc, "rf")]

    def verdict(m):
        r, rlo, fpr = m["recall"][0], m["recall"][1], m["fpr"][0]
        if fpr > 0.01: return f"NULL (FPR {fpr*100:.1f}% > 1%)"
        if r >= 0.50 and rlo > BASELINE_UPPER: return "SUCCESS"
        if 0.30 <= r < 0.50: return "PARTIAL"
        if r >= 0.50: return "PARTIAL (CI overlaps baseline)"
        return "NULL"

    def pc(w): return f"{w[0]*100:.1f}% [{w[1]*100:.1f},{w[2]*100:.1f}]"
    inj = int((yood == 1).sum()); ben = int((yood == 0).sum())
    md = [f"# Phase 5a-bis — recalibrated OOD (fresh disjoint). SHIP GATE = pg2+logreg.",
          f"\nOOD: {inj} fresh HackAPrompt injections + {ben} fresh dolly benign (near-dup dropped {dropped}).",
          f"Threshold = 99th pct of {N_CALIB} same-distribution dolly-calib benign (FPR<=1% by construction).\n",
          "| emb+head | OOD Recall | OOD FPR | calib FPR | precision | AUC | verdict |",
          "|---|---|---|---|---|---|---|"]
    for r in results:
        star = " ⭐" if (r["emb"], r["head"]) == ("pg2", "logreg") else ""
        md.append(f"| {r['emb']}+{r['head']}{star} | **{pc(r['recall'])}** | {pc(r['fpr'])} | "
                  f"{r['calib_fpr']*100:.1f}% | {r['precision']*100:.1f}% | {r['auc']:.3f} | {verdict(r)} |")
    gate = next(r for r in results if (r["emb"], r["head"]) == ("pg2", "logreg"))
    md.append(f"\n## SHIP-GATE VERDICT (pg2+logreg): **{verdict(gate)}**")
    C.joinpath("bis_results.md").write_text("\n".join(md))
    C.joinpath("bis_results.json").write_text(json.dumps(results, indent=2, default=list))
    print("\n".join(md))


if __name__ == "__main__":
    main()
