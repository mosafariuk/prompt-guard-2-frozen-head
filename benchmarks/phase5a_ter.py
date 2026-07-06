"""Phase 5a-ter — stricter calibration (99.5th pct / ~0.5% FPR target) on FRESH data.

Pre-registered change (docs §5b, fixed before this run): threshold = 99.5th percentile
of calibration benign. Success bar UNCHANGED: OOD recall >= 50% @ point-estimate FPR
<= 1%, Wilson lower > 28.3%.

Leakage: excludes every text from 5a (jsonl) AND 5a-bis (reproduced deterministically
from its seed 20260706 with identical selection logic), then draws fresh disjoint data
with seed 20260707. OOD touched exactly once. Final attempt on this approach.
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
Z = 1.959963985
BASELINE_UPPER = 0.2826
N_INJ, N_CALIB, N_TEST = 800, 2000, 2000
PCTL = 99.5  # <-- pre-registered stricter calibration (was 99.0 in 5a-bis)
PG2 = os.environ.get("MODEL_ID", "meta-llama/Llama-Prompt-Guard-2-86M")


def norm(t): return re.sub(r"\s+", " ", (t or "").strip().lower())
def Hh(t): return hashlib.sha1(norm(t).encode()).hexdigest()
def wilson(k, n):
    if n == 0: return (float("nan"),) * 3
    p = k / n; z2 = Z * Z; d = 1 + z2 / n
    c = (p + z2 / (2 * n)) / d
    h = (Z / d) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return p, max(0.0, c - h), min(1.0, c + h)
def metrics_at(s, y, t):
    pred = s >= t
    tp = int((pred & (y == 1)).sum()); fn = int((~pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum()); tn = int((~pred & (y == 0)).sum())
    return {"recall": wilson(tp, tp+fn), "fpr": wilson(fp, fp+tn),
            "precision": tp/(tp+fp) if (tp+fp) else float("nan"), "tp": tp, "fp": fp, "fn": fn, "tn": tn}
def uniq_new(texts, spent):
    seen = set(); out = []
    for t in texts:
        if not (isinstance(t, str) and t.strip()): continue
        k = Hh(t)
        if k in spent or k in seen: continue
        seen.add(k); out.append(t)
    return out


def select(hp_texts, dolly_texts, spent, seed):
    """Deterministic selection identical in structure to 5a-bis (rng order: hp then dolly)."""
    rng = np.random.default_rng(seed)
    hp_pool = uniq_new(hp_texts, spent)
    hp = [hp_pool[i] for i in rng.choice(len(hp_pool), min(N_INJ, len(hp_pool)), replace=False)]
    dolly_pool = uniq_new(dolly_texts, spent)
    rng.shuffle(dolly_pool)
    return hp, dolly_pool[:N_CALIB], dolly_pool[N_CALIB:N_CALIB + N_TEST]


def main():
    tok = os.environ.get("HF_TOKEN")
    spent = set()
    for f in ["train", "val", "ood_test"]:
        for l in (C / f"{f}.jsonl").read_text().splitlines():
            spent.add(Hh(json.loads(l)["text"]))

    hp_ds = load_dataset("hackaprompt/hackaprompt-dataset", split="train", token=tok)
    col = next(c for c in ["prompt", "user_input", "prompt_text", "text"] if c in hp_ds.column_names)
    hp_all = [hp_ds[i][col] for i in range(min(len(hp_ds), 60000))]
    dolly_all = [r["instruction"] for r in load_dataset("databricks/databricks-dolly-15k", split="train")]

    # Reproduce 5a-bis's exact selection (seed 20260706) and exclude it.
    bis_hp, bis_cal, bis_test = select(hp_all, dolly_all, spent, 20260706)
    for t in bis_hp + bis_cal + bis_test:
        spent.add(Hh(t))
    print(f"excluded 5a + 5a-bis: {len(spent)} hashes", flush=True)

    # Fresh 5a-ter draw (seed 20260707), disjoint from everything above.
    hp_f, cal_f, test_f = select(hp_all, dolly_all, spent, 20260707)
    ood_rows = [{"text": t, "label": 1} for t in hp_f] + [{"text": t, "label": 0} for t in test_f]

    arctic = SentenceTransformer("Snowflake/snowflake-arctic-embed-m", device="cpu")
    tr_arctic = np.load(C / "train.arctic.npy")
    def enc_a(x): return arctic.encode(x, normalize_embeddings=True, batch_size=64, show_progress_bar=False).astype(np.float32)
    ood_arc = enc_a([r["text"] for r in ood_rows])
    keep = [i for i in range(len(ood_rows)) if (ood_arc[i] @ tr_arctic.T).max() < 0.95]
    dropped = len(ood_rows) - len(keep)
    ood_rows = [ood_rows[i] for i in keep]; ood_arc = ood_arc[keep]
    cal_arc = enc_a(cal_f)
    print(f"near-dup dropped: {dropped}", flush=True)

    tk = AutoTokenizer.from_pretrained(PG2, token=tok)
    model = AutoModelForSequenceClassification.from_pretrained(PG2, token=tok).eval()
    base = getattr(model, "deberta", None) or model.base_model
    pooler = getattr(model, "pooler", None)
    @torch.no_grad()
    def enc_p(x):
        o = []
        for i in range(0, len(x), 32):
            e = tk(x[i:i+32], padding=True, truncation=True, max_length=512, return_tensors="pt")
            hs = base(**e).last_hidden_state
            o.append((pooler(hs) if pooler is not None else hs[:, 0]).cpu().numpy().astype(np.float32))
        return np.concatenate(o) if o else np.zeros((0, model.config.hidden_size), np.float32)
    ood_pg2 = enc_p([r["text"] for r in ood_rows]); cal_pg2 = enc_p(cal_f)

    yood = np.array([r["label"] for r in ood_rows])
    ytr = np.array([json.loads(l)["label"] for l in (C / "train.jsonl").read_text().splitlines()])

    def run(emb, Xtr, Xcal, Xood, head):
        clf = (LogisticRegression(max_iter=2000, class_weight="balanced") if head == "logreg"
               else RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0, n_jobs=-1))
        clf.fit(Xtr, ytr)
        scal = clf.predict_proba(Xcal)[:, 1]; sood = clf.predict_proba(Xood)[:, 1]
        t = float(np.percentile(scal, PCTL))
        m = metrics_at(sood, yood, t)
        m["auc"] = float(roc_auc_score(yood, sood)) if len(set(yood)) > 1 else float("nan")
        m["calib_fpr"] = float((scal >= t).mean()); m["emb"] = emb; m["head"] = head
        return m

    Xtr_p = np.load(C / "train.pg2.npy"); Xtr_a = np.load(C / "train.arctic.npy")
    results = [run("pg2", Xtr_p, cal_pg2, ood_pg2, "logreg"), run("pg2", Xtr_p, cal_pg2, ood_pg2, "rf"),
               run("arctic", Xtr_a, cal_arc, ood_arc, "logreg"), run("arctic", Xtr_a, cal_arc, ood_arc, "rf")]

    def verdict(m):
        r, rlo, fpr = m["recall"][0], m["recall"][1], m["fpr"][0]
        if fpr > 0.01: return f"NULL (FPR {fpr*100:.2f}% > 1%)"
        if r >= 0.50 and rlo > BASELINE_UPPER: return "SUCCESS"
        if 0.30 <= r < 0.50: return "PARTIAL"
        if r >= 0.50: return "PARTIAL (CI overlaps baseline)"
        return "NULL"
    def pc(w): return f"{w[0]*100:.1f}% [{w[1]*100:.1f},{w[2]*100:.1f}]"
    inj = int((yood == 1).sum()); ben = int((yood == 0).sum())
    md = [f"# Phase 5a-ter — 99.5th-pct calibration, FRESH disjoint. SHIP GATE = pg2+logreg.",
          f"\nOOD: {inj} fresh HackAPrompt injections + {ben} fresh dolly benign (near-dup dropped {dropped}).",
          f"Threshold = {PCTL}th pct of {N_CALIB} same-dist calib benign (target ~0.5% FPR).\n",
          "| emb+head | OOD Recall | OOD FPR | calib FPR | precision | AUC | verdict |",
          "|---|---|---|---|---|---|---|"]
    for r in results:
        star = " ⭐" if (r["emb"], r["head"]) == ("pg2", "logreg") else ""
        md.append(f"| {r['emb']}+{r['head']}{star} | **{pc(r['recall'])}** | {pc(r['fpr'])} | "
                  f"{r['calib_fpr']*100:.2f}% | {r['precision']*100:.1f}% | {r['auc']:.3f} | {verdict(r)} |")
    gate = next(r for r in results if (r["emb"], r["head"]) == ("pg2", "logreg"))
    md.append(f"\n## SHIP-GATE VERDICT (pg2+logreg): **{verdict(gate)}**")
    C.joinpath("ter_results.md").write_text("\n".join(md))
    C.joinpath("ter_results.json").write_text(json.dumps(results, indent=2, default=list))
    print("\n".join(md))


if __name__ == "__main__":
    main()
