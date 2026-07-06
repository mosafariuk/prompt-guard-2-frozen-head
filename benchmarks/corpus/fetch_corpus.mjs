// Fetch the deepset/prompt-injections corpus (paper Section VII-A).
//
// Provenance (verified 2026-07-04, verified-facts Part 4b): 662 rows total
// (546 train / 116 test), binary labels 0=legit / 1=injection, columns
// text/label, DE+EN, Apache 2.0. Pulled via the Hugging Face datasets-server
// rows API (no auth needed for a public dataset). Writes corpus/payloads.json.
//
// Run: node corpus/fetch_corpus.mjs

import { writeFileSync } from "node:fs";

const DATASET = "deepset/prompt-injections";
const CONFIG = "default";
const BASE = "https://datasets-server.huggingface.co/rows";
const PAGE = 100; // API max length per request

async function fetchSplit(split) {
  const rows = [];
  for (let offset = 0; ; offset += PAGE) {
    const url = `${BASE}?dataset=${encodeURIComponent(DATASET)}&config=${CONFIG}&split=${split}&offset=${offset}&length=${PAGE}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HF API ${res.status} for ${split}@${offset}: ${await res.text()}`);
    const json = await res.json();
    const batch = json.rows ?? [];
    if (batch.length === 0) break;
    for (const item of batch) {
      // row shape: { text: string, label: 0|1 }
      const r = item.row;
      if (typeof r?.text === "string" && (r.label === 0 || r.label === 1)) {
        rows.push({ text: r.text, label: r.label });
      }
    }
    if (batch.length < PAGE) break;
  }
  return rows;
}

const train = await fetchSplit("train");
const test = await fetchSplit("test");
const rows = [...train, ...test];

const out = {
  provenance: `deepset/prompt-injections (Hugging Face), Apache 2.0. Fetched via datasets-server. train=${train.length}, test=${test.length}, total=${rows.length}. label: 1=injection, 0=legit.`,
  rows,
};

writeFileSync(new URL("payloads.json", import.meta.url), JSON.stringify(out, null, 2));
const pos = rows.filter((r) => r.label === 1).length;
console.log(`Wrote corpus/payloads.json: ${rows.length} rows (${pos} injection, ${rows.length - pos} legit).`);
if (rows.length < 100) {
  console.warn("WARNING: fewer rows than expected — check the HF API / dataset availability.");
}
