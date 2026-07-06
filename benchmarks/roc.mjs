// Offline ROC/AUC over the REAL screening code (paper Section VII-D).
//
// ROC is inherently an offline analysis over scored examples, so we import the
// firewall's own screen()/sanitizeForScan() (not a reimplementation) and sweep
// the decision threshold. The score is the soft feature score; a blocking-class
// hit is treated as a maximal-confidence positive (score = +Inf), matching the
// runtime semantics where one hard signature forces reject regardless of score.
//
// Run: npx tsx roc.mjs   (tsx resolves the .js imports to the firewall's .ts)

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { screen } from "../edge-firewall/src/heuristics.js";
import { sanitizeForScan } from "../edge-firewall/src/sanitize.js";
import { rocAuc } from "./lib/stats.mjs";

const THRESHOLD = 1.0; // theta used at runtime; ROC sweeps around it
const BIG = 1e6; // blocking hit => maximal positive score

function loadCorpus() {
  for (const f of ["corpus/payloads.json", "corpus/sample_payloads.json"]) {
    try {
      const j = JSON.parse(readFileSync(new URL(f, import.meta.url), "utf8"));
      return { rows: j.rows, provenance: j.provenance ?? f };
    } catch {
      /* try next */
    }
  }
  throw new Error("no corpus found; run `npm run corpus` first");
}

const { rows, provenance } = loadCorpus();

const scored = rows.map((r) => {
  const res = screen(sanitizeForScan(r.text), THRESHOLD);
  const blocking = res.blockingSignatures.length > 0;
  return { score: blocking ? BIG : res.score, label: r.label };
});

const { auc, roc } = rocAuc(scored);

mkdirSync(new URL("results/", import.meta.url), { recursive: true });
writeFileSync(
  new URL("results/roc.json", import.meta.url),
  JSON.stringify({ auc, roc, n: rows.length, provenance }, null, 2),
);

// Console summary (paper-ready).
console.log(`ROC/AUC over ${rows.length} payloads (${provenance})`);
console.log(`AUC = ${auc.toFixed(4)}`);
console.log("Selected ROC points (fpr, tpr, threshold):");
for (const pt of roc.filter((_, i) => i % Math.max(1, Math.floor(roc.length / 8)) === 0)) {
  console.log(`  fpr=${pt.fpr.toFixed(3)}  tpr=${pt.tpr.toFixed(3)}  thr=${Number.isFinite(pt.threshold) ? pt.threshold.toFixed(2) : pt.threshold}`);
}
