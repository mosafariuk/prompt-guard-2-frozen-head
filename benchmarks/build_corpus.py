"""Phase 5a Step 1-2 — build + dedup the injection-classifier corpus.

License-confirmed sources ONLY (verified-facts Part 8):
  TRAIN      : deepset(train) [both classes] + Lakera gandalf(train) [injection]
               + OpenOrca(sample) [benign, MIT]
  VALIDATION : deepset(test) [both]  (in-distribution; thresholds only)
  OOD TEST   : HackAPrompt(sample) [injection, MIT, gated] + dolly(sample) [benign, distinct source]

Leakage controls (pre-registered):
  - EXACT dedup on normalized text, within AND across splits. Cross-split conflicts
    are resolved by DROPPING the eval-side item (train wins), so OOD stays pure.
  - NEAR-dup dedup via arctic-embed cosine: drop OOD/val items with max cosine >= 0.95
    to ANY train item; drop within-split pairs >= 0.98.
  Order: exact-dedup -> embed(arctic) -> near-dup-dedup. Saves clean splits + embeddings.

Run in the bench image (has sentence-transformers); needs `datasets` + HF_TOKEN:
  docker run --rm -v $PWD:/work -v deepscan-models:/models -e HF_HOME=/models \
    -e HF_TOKEN=... -w /work deepscan-bench \
    bash -c "pip install -q datasets && python build_corpus.py"
"""
from __future__ import annotations
import hashlib, json, os, re, sys
from pathlib import Path
import numpy as np

HERE = Path(__file__).resolve().parent
OUT = HERE / "corpus5a"; OUT.mkdir(exist_ok=True)
SEED = 20260705
N_BENIGN_TRAIN = int(os.environ.get("N_BENIGN_TRAIN", "800"))
N_OOD_INJ = int(os.environ.get("N_OOD_INJ", "500"))
N_OOD_BENIGN = int(os.environ.get("N_OOD_BENIGN", "500"))
rng = np.random.default_rng(SEED)


def norm(t: str) -> str:
    return re.sub(r"\s+", " ", (t or "").strip().lower())


def take(lst, n):
    lst = list(lst)
    if len(lst) <= n:
        return lst
    idx = rng.choice(len(lst), size=n, replace=False)
    return [lst[i] for i in idx]


def load():
    from datasets import load_dataset
    tok = os.environ.get("HF_TOKEN")
    train, val, ood = [], [], []

    # deepset (Apache-2.0): text, label (0 benign / 1 injection)
    dp = load_dataset("deepset/prompt-injections")
    for r in dp["train"]:
        train.append({"text": r["text"], "label": int(r["label"]), "source": "deepset"})
    for r in dp["test"]:
        val.append({"text": r["text"], "label": int(r["label"]), "source": "deepset"})

    # gandalf (MIT): injection-only -> label 1
    gd = load_dataset("Lakera/gandalf_ignore_instructions")
    for r in gd["train"]:
        train.append({"text": r["text"], "label": 1, "source": "gandalf"})

    # OpenOrca (MIT) benign for train balance -> label 0 (stream, take N)
    oo = load_dataset("Open-Orca/OpenOrca", split="train", streaming=True)
    buf = []
    for i, r in enumerate(oo):
        q = r.get("question")
        if isinstance(q, str) and q.strip():
            buf.append(q)
        if len(buf) >= N_BENIGN_TRAIN * 3:
            break
    for q in take(buf, N_BENIGN_TRAIN):
        train.append({"text": q, "label": 0, "source": "openorca"})

    # dolly (CC BY-SA 3.0) benign for OOD -> label 0 (distinct source from train benign)
    dl = load_dataset("databricks/databricks-dolly-15k", split="train")
    dolly = [r["instruction"] for r in dl if isinstance(r.get("instruction"), str) and r["instruction"].strip()]
    for q in take(dolly, N_OOD_BENIGN):
        ood.append({"text": q, "label": 0, "source": "dolly"})

    # HackAPrompt (MIT, GATED): OOD injections -> label 1
    try:
        hp = load_dataset("hackaprompt/hackaprompt-dataset", split="train", token=tok)
        col = next((c for c in ["prompt", "user_input", "prompt_text", "text"] if c in hp.column_names), None)
        if col is None:
            print(f"[HackAPrompt] unknown text column in {hp.column_names}; skipping OOD injections", flush=True)
        else:
            hp_rows = [r[col] for r in hp.select(range(min(len(hp), N_OOD_INJ * 4))) if isinstance(r.get(col), str) and r[col].strip()]
            for t in take(hp_rows, N_OOD_INJ):
                ood.append({"text": t, "label": 1, "source": "hackaprompt"})
    except Exception as e:
        print(f"[HackAPrompt GATED/unavailable: {type(e).__name__}] -> accept the gate at "
              "huggingface.co/datasets/hackaprompt/hackaprompt-dataset then re-run. "
              "Building train/val + OOD-benign only for now.", flush=True)

    return train, val, ood


def exact_dedup(train, val, ood):
    seen = set(); out_train = []
    for r in train:
        h = hashlib.sha1(norm(r["text"]).encode()).hexdigest()
        if h not in seen:
            seen.add(h); r["_h"] = h; out_train.append(r)
    train_h = {r["_h"] for r in out_train}

    def clean_eval(rows):
        s = set(); keep = []
        for r in rows:
            h = hashlib.sha1(norm(r["text"]).encode()).hexdigest()
            if h in train_h or h in s:  # drop cross-split (train wins) + within-split dup
                continue
            s.add(h); r["_h"] = h; keep.append(r)
        return keep

    return out_train, clean_eval(val), clean_eval(ood)


def embed(rows, model):
    if not rows:
        return np.zeros((0, 768), dtype=np.float32)
    return model.encode([r["text"] for r in rows], normalize_embeddings=True,
                        batch_size=64, show_progress_bar=False).astype(np.float32)


def neardup_drop(eval_rows, eval_emb, train_emb, thr=0.95):
    if len(eval_rows) == 0 or len(train_emb) == 0:
        return eval_rows, eval_emb, 0
    # cosine (embeddings already L2-normalized) -> max sim to any train item
    keep_idx, dropped = [], 0
    for i in range(len(eval_rows)):
        sims = eval_emb[i] @ train_emb.T
        if sims.max() >= thr:
            dropped += 1
        else:
            keep_idx.append(i)
    return [eval_rows[i] for i in keep_idx], eval_emb[keep_idx], dropped


def save(name, rows, emb):
    with open(OUT / f"{name}.jsonl", "w") as f:
        for r in rows:
            f.write(json.dumps({"text": r["text"], "label": r["label"], "source": r["source"]}) + "\n")
    np.save(OUT / f"{name}.arctic.npy", emb)


def main():
    from sentence_transformers import SentenceTransformer
    print("fetching datasets ...", flush=True)
    train, val, ood = load()
    print(f"raw: train={len(train)} val={len(val)} ood={len(ood)}", flush=True)

    train, val, ood = exact_dedup(train, val, ood)
    print(f"after exact-dedup: train={len(train)} val={len(val)} ood={len(ood)}", flush=True)

    print("embedding (arctic-embed-m, CPU) for near-dup + head training ...", flush=True)
    emb_model = SentenceTransformer("Snowflake/snowflake-arctic-embed-m", device="cpu")
    tr_emb = embed(train, emb_model)
    val_emb = embed(val, emb_model)
    ood_emb = embed(ood, emb_model)

    val, val_emb, vd = neardup_drop(val, val_emb, tr_emb)
    ood, ood_emb, od = neardup_drop(ood, ood_emb, tr_emb)
    print(f"near-dup dropped: val={vd} ood={od}", flush=True)

    save("train", train, tr_emb); save("val", val, val_emb); save("ood_test", ood, ood_emb)

    def dist(rows):
        pos = sum(1 for r in rows if r["label"] == 1)
        return f"n={len(rows)} inj={pos} benign={len(rows)-pos} sources={sorted(set(r['source'] for r in rows))}"
    summary = {"train": dist(train), "val": dist(val), "ood_test": dist(ood), "seed": SEED}
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print("\n=== CORPUS SUMMARY ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    has_ood_inj = any(r["label"] == 1 for r in ood)
    print(f"\nOOD injection present: {has_ood_inj}"
          + ("" if has_ood_inj else "  <-- accept HackAPrompt gate + re-run to complete the OOD ship-gate"))


if __name__ == "__main__":
    main()
