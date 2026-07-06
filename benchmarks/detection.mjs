// Detection-efficacy harness (paper Section VII-D).
//
// Two modes:
//   - END-TO-END (WORKER_URL set): HMAC-signs each payload and POSTs to the
//     deployed firewall; the decision is read from the HTTP response. This is the
//     real, deployed-system measurement the paper reports.
//   - LOCAL (no WORKER_URL): imports the firewall's screen() to classify offline.
//     Useful for CI and for verifying the harness without infrastructure. Clearly
//     labeled as NOT end-to-end.
//
// Emits confusion matrix, FNR/FPR/Recall/Precision with Wilson 95% CIs, and a
// per-family recall breakdown -> results/detection.{json,md}.
//
// Run: npx tsx detection.mjs   (WORKER_URL=... for end-to-end)

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHmac, createHash, randomBytes } from "node:crypto";
import { screen } from "../edge-firewall/src/heuristics.js";
import { sanitizeForScan } from "../edge-firewall/src/sanitize.js";
import { wilson } from "./lib/stats.mjs";

const WORKER_URL = process.env.WORKER_URL ?? null;
const TENANT_ID = process.env.BENCH_TENANT_ID ?? "tenant-bench";
const KID = process.env.BENCH_KID ?? "1";
const TENANT_KEY_B64 = process.env.BENCH_TENANT_KEY ?? ""; // base64 secret in KV
const THRESHOLD = Number.parseFloat(process.env.SCORE_THRESHOLD ?? "1.0");

function loadCorpus() {
  for (const f of ["corpus/payloads.json", "corpus/sample_payloads.json"]) {
    try {
      const j = JSON.parse(readFileSync(new URL(f, import.meta.url), "utf8"));
      return { rows: j.rows, provenance: j.provenance ?? f };
    } catch {
      /* next */
    }
  }
  throw new Error("no corpus found; run `npm run corpus` first");
}

// Sign a request body exactly as the firewall expects (Section IV-B).
function signHeaders(body) {
  const t = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(18).toString("base64url"); // matches /^[A-Za-z0-9_-]{16,128}$/
  const hbody = createHash("sha256").update(body).digest("hex");
  const message = `${TENANT_ID}.${KID}.${t}.${nonce}.${hbody}`;
  const key = Buffer.from(TENANT_KEY_B64, "base64");
  const v1 = createHmac("sha256", key).update(message).digest("hex");
  return { "x-webhook-signature": `tid=${TENANT_ID},kid=${KID},t=${t},n=${nonce},v1=${v1}`, "content-type": "application/json" };
}

// Predicted positive iff the firewall does NOT forward (reject or escalate).
async function classify(text) {
  if (WORKER_URL) {
    const body = JSON.stringify({ event: text });
    const res = await fetch(WORKER_URL, { method: "POST", headers: signHeaders(body), body });
    // 403 = reject; 200 with x-firewall-escalate = escalate; 200 = forward.
    if (res.status === 403) return "reject";
    if (res.headers.get("x-firewall-escalate") === "1") return "escalate";
    if (res.status === 200) return "forward";
    return "reject"; // 4xx auth errors count as blocked
  }
  return screen(sanitizeForScan(text), THRESHOLD).decision;
}

const FAMILIES = [
  { name: "direct_override", re: /ignore|disregard|forget|new instructions/i },
  { name: "extraction", re: /system prompt|repeat the words|initial instructions|configuration/i },
  { name: "roleplay", re: /dan|do anything|developer mode|pretend|no restrictions/i },
  { name: "delimiter_token", re: /<\|.*?\|>|### system|assistant:|system:|\[inst\]/i },
  { name: "bypass", re: /jailbreak|content filter|unlock/i },
];

function familyOf(text) {
  for (const f of FAMILIES) if (f.re.test(text)) return f.name;
  return "other";
}

const { rows, provenance } = loadCorpus();
let tp = 0;
let fp = 0;
let tn = 0;
let fn = 0;
const famStats = new Map();
const edgeDecisions = []; // per-payload dump for the full-system benchmark

for (const r of rows) {
  const decision = await classify(r.text);
  const predictedPositive = decision !== "forward";
  edgeDecisions.push({ label: r.label, decision });
  if (r.label === 1 && predictedPositive) tp++;
  else if (r.label === 1 && !predictedPositive) fn++;
  else if (r.label === 0 && predictedPositive) fp++;
  else tn++;

  if (r.label === 1) {
    const fam = familyOf(r.text);
    const s = famStats.get(fam) ?? { tp: 0, total: 0 };
    s.total++;
    if (predictedPositive) s.tp++;
    famStats.set(fam, s);
  }
}

const recall = wilson(tp, tp + fn);
const precision = wilson(tp, tp + fp);
const fpr = wilson(fp, fp + tn);
const fnr = { p: 1 - recall.p, lower: 1 - recall.upper, upper: 1 - recall.lower };

const result = {
  mode: WORKER_URL ? "end-to-end" : "local-screening",
  provenance,
  n: rows.length,
  malicious: tp + fn,
  benign: fp + tn,
  confusion: { tp, fp, tn, fn },
  recall,
  precision,
  fpr,
  fnr,
  perFamily: Object.fromEntries(
    [...famStats].map(([k, v]) => [k, { recall: v.tp / v.total, tp: v.tp, total: v.total }]),
  ),
};

mkdirSync(new URL("results/", import.meta.url), { recursive: true });
writeFileSync(new URL("results/detection.json", import.meta.url), JSON.stringify(result, null, 2));
// Per-payload edge decisions -> consumed by full_system.py to compose the layers.
writeFileSync(
  new URL("results/edge_decisions.json", import.meta.url),
  JSON.stringify({ provenance, decisions: edgeDecisions }, null, 2),
);

const pct = (x) => (x * 100).toFixed(2) + "%";
const ci = (w) => `${pct(w.p)} [${pct(w.lower)}, ${pct(w.upper)}]`;
const md = `# Detection Efficacy (Section VII-D) — ${result.mode}

Corpus: ${provenance}
N=${result.n}  (malicious=${result.malicious}, benign=${result.benign})

## Confusion matrix
|          | pred + | pred - |
|----------|--------|--------|
| actual + | ${tp} (TP) | ${fn} (FN) |
| actual - | ${fp} (FP) | ${tn} (TN) |

## Rates (Wilson 95% CI)
| metric | value [95% CI] |
|--------|----------------|
| Mitigation (Recall) | ${ci(recall)} |
| Precision | ${ci(precision)} |
| FPR | ${ci(fpr)} |
| FNR | ${ci(fnr)} |

> ">99% mitigation" is credited only if the Recall **lower** bound exceeds 99%.
> Lower bound here: ${pct(recall.lower)} (N may be too small for a 0.99 lower bound — report honestly).

## Per-family recall (malicious only)
| family | recall | tp/total |
|--------|--------|----------|
${Object.entries(result.perFamily).map(([k, v]) => `| ${k} | ${pct(v.recall)} | ${v.tp}/${v.total} |`).join("\n")}
`;
writeFileSync(new URL("results/detection.md", import.meta.url), md);
console.log(md);
