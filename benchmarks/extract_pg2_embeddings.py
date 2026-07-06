"""Phase 5a Step 2 — extract frozen Prompt Guard 2 penultimate embeddings.

PG2 is DebertaV2ForSequenceClassification: deberta -> ContextPooler -> dropout ->
classifier. The pooler output is EXACTLY the representation PG2's own head classifies
on, so a head trained on it isolates "is the signal in PG2's embedding space?" (the
Phase-5a hypothesis). We cache pooler output per split as .npy for fast head training.

Run in the bench image (torch+transformers), model cached in /models, HF_TOKEN set.
"""
from __future__ import annotations
import json, os, sys
from pathlib import Path
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus5a"
PG2 = os.environ.get("MODEL_ID", "meta-llama/Llama-Prompt-Guard-2-86M")
MAXLEN = 512
BATCH = 32


def main():
    tok = os.environ.get("HF_TOKEN")
    tokenizer = AutoTokenizer.from_pretrained(PG2, token=tok)
    model = AutoModelForSequenceClassification.from_pretrained(PG2, token=tok).eval()

    # DebertaV2: base encoder + ContextPooler. Fall back to CLS token if absent.
    base = getattr(model, "deberta", None) or getattr(model, "base_model", None)
    pooler = getattr(model, "pooler", None)
    if base is None:
        sys.exit(f"could not locate base encoder on {type(model).__name__}")
    print(f"model={type(model).__name__} pooler={'yes' if pooler else 'CLS-fallback'}", flush=True)

    @torch.no_grad()
    def embed(texts):
        out = []
        for i in range(0, len(texts), BATCH):
            enc = tokenizer(texts[i:i + BATCH], padding=True, truncation=True,
                            max_length=MAXLEN, return_tensors="pt")
            hs = base(**enc).last_hidden_state              # (B,T,H)
            emb = pooler(hs) if pooler is not None else hs[:, 0]  # (B,H)
            out.append(emb.cpu().numpy().astype(np.float32))
            if (i // BATCH) % 10 == 0:
                print(f"    {i+len(enc['input_ids'])}/{len(texts)}", flush=True)
        return np.concatenate(out, axis=0) if out else np.zeros((0, model.config.hidden_size), np.float32)

    for split in ["train", "val", "ood_test"]:
        rows = [json.loads(l) for l in (CORPUS / f"{split}.jsonl").read_text().splitlines()]
        texts = [r["text"] for r in rows]
        print(f"embedding {split}: {len(texts)} texts", flush=True)
        emb = embed(texts)
        np.save(CORPUS / f"{split}.pg2.npy", emb)
        print(f"  saved {split}.pg2.npy shape={emb.shape}", flush=True)


if __name__ == "__main__":
    main()
