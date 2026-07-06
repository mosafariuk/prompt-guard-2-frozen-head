// Aggregate benchmark outputs into the paper's Section VII placeholders.
// Reads results/{latency,detection,roc}.json and prints a table mapping each
// placeholder to its measured value, plus a paper-pasteable block.
//
// Run: node report.mjs   (after latency/detection/roc have produced results/)

import { readFileSync } from "node:fs";

function tryRead(f) {
  try {
    return JSON.parse(readFileSync(new URL(f, import.meta.url), "utf8"));
  } catch {
    return null;
  }
}

const lat = tryRead("results/latency.json");
const det = tryRead("results/detection.json");
const roc = tryRead("results/roc.json");

const pct = (x) => (x == null ? "—" : (x * 100).toFixed(2) + "%");
const ms = (x) => (x == null ? "—" : Number(x).toFixed(2) + " ms");

console.log("# Section VII — Measured Values (fills paper placeholders)\n");
console.log("| Placeholder | Measured | Source |");
console.log("|-------------|----------|--------|");
console.log(`| \\langle p50\\rangle | ${ms(lat?.warm?.p50)} | latency.k6.js (warm) |`);
console.log(`| \\langle p90\\rangle | ${ms(lat?.warm?.p90)} | latency.k6.js (warm) |`);
console.log(`| \\langle p99\\rangle | ${ms(lat?.warm?.p99)} | latency.k6.js (warm) |`);
console.log(`| cold-start p99 | ${ms(lat?.cold?.p99)} | latency.k6.js (cold) |`);
console.log(`| \\langle Recall\\rangle (mitigation) | ${pct(det?.recall?.p)} [${pct(det?.recall?.lower)}, ${pct(det?.recall?.upper)}] | detection (${det?.mode ?? "n/a"}) |`);
console.log(`| \\langle FPR\\rangle | ${pct(det?.fpr?.p)} [${pct(det?.fpr?.lower)}, ${pct(det?.fpr?.upper)}] | detection |`);
console.log(`| \\langle FNR\\rangle | ${pct(det?.fnr?.p)} | detection |`);
console.log(`| \\langle AUC\\rangle | ${roc?.auc == null ? "—" : roc.auc.toFixed(4)} | roc.mjs |`);

console.log("\n## SLO / claim checks\n");
if (lat) console.log(`- p99 < 50 ms SLO: ${lat.slo_met ? "MET" : "NOT MET"} (p99 = ${ms(lat.warm?.p99)})`);
if (det) {
  const credited = (det.recall?.lower ?? 0) > 0.99;
  console.log(`- ">99% mitigation" (Wilson lower > 99%): ${credited ? "CREDITED" : "NOT credited"} (lower bound = ${pct(det.recall?.lower)}, N_malicious=${det.malicious})`);
}
if (!lat) console.log("\n(No latency.json yet — run `npm run latency` against a deployed worker.)");
if (!det) console.log("(No detection.json yet — run `npm run detection`.)");
console.log("\nNOTE: these are the ONLY numbers that fill the paper's Section VII; the");
console.log("draft ships with placeholders until a real run populates them (Section VII intro).");
