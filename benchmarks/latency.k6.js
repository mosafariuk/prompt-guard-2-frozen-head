// k6 latency benchmark (paper Section VII-B/C).
//
// Fires HMAC-signed webhooks at the deployed firewall and measures the ADDED
// latency distribution. Separates COLD-start isolates from WARM steady state via
// two k6 scenarios (Section VII-C). Emits p50/p90/p99 in a paper-ready form and
// encodes the <50 ms p99 SLO as a k6 threshold so a breach fails the run.
//
// Run:
//   WORKER_URL=https://edge-llm-firewall.example.workers.dev \
//   BENCH_TENANT_KEY=<base64 secret also stored in TENANT_KEYS KV> \
//   k6 run latency.k6.js
//
// Prereqs: provision the bench tenant key in KV:
//   wrangler kv key put --binding TENANT_KEYS "tenant-bench:1" "<base64 secret>"

import http from "k6/http";
import crypto from "k6/crypto";
import encoding from "k6/encoding";
import { Trend } from "k6/metrics";
import { SharedArray } from "k6/data";

const WORKER_URL = __ENV.WORKER_URL;
const TENANT_ID = __ENV.BENCH_TENANT_ID || "tenant-bench";
const KID = __ENV.BENCH_KID || "1";
const KEY_B64 = __ENV.BENCH_TENANT_KEY || "";
const KEY = encoding.b64decode(KEY_B64, "std", "b"); // ArrayBuffer raw key bytes

// Load the corpus once, shared across VUs (memory-efficient).
const corpus = new SharedArray("payloads", function () {
  let data;
  try {
    data = JSON.parse(open("./corpus/payloads.json"));
  } catch (e) {
    data = JSON.parse(open("./corpus/sample_payloads.json"));
  }
  return data.rows;
});

// Custom trends so warm/cold are reported independently of the global metric.
const warmLatency = new Trend("firewall_added_latency_warm", true);
const coldLatency = new Trend("firewall_added_latency_cold", true);

export const options = {
  scenarios: {
    // Cold: a burst of first-hits to (likely) fresh isolates, measured separately
    // because the module-scope automaton build (Section III-A) is a one-time cost.
    cold: {
      executor: "per-vu-iterations",
      vus: 20,
      iterations: 1,
      exec: "coldHit",
      startTime: "0s",
      tags: { phase: "cold" },
    },
    // Warm: steady-state load after a short warmup, the distribution the paper
    // reports for p50/p90/p99.
    warm: {
      executor: "constant-arrival-rate",
      rate: 200,
      timeUnit: "1s",
      duration: "60s",
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: "warmHit",
      startTime: "10s", // let isolates warm before measuring
      tags: { phase: "warm" },
    },
  },
  thresholds: {
    // The SLO from Section VII-B, as an enforced gate.
    "firewall_added_latency_warm": ["p(99)<50"],
    "http_req_failed": ["rate<0.01"],
  },
};

function signedRequest() {
  const payload = corpus[Math.floor(Math.random() * corpus.length)];
  const body = JSON.stringify({ event: payload.text });
  const t = Math.floor(Date.now() / 1000);
  // Unique nonce matching /^[A-Za-z0-9_-]{16,128}$/.
  const nonce = `k6_${__VU}_${__ITER}_${Date.now()}`;
  const hbody = crypto.sha256(body, "hex");
  const message = `${TENANT_ID}.${KID}.${t}.${nonce}.${hbody}`;
  const v1 = crypto.hmac("sha256", KEY, message, "hex");
  const headers = {
    "Content-Type": "application/json",
    "X-Webhook-Signature": `tid=${TENANT_ID},kid=${KID},t=${t},n=${nonce},v1=${v1}`,
  };
  return { body, headers };
}

export function warmHit() {
  const { body, headers } = signedRequest();
  const res = http.post(WORKER_URL, body, { headers });
  warmLatency.add(res.timings.duration);
}

export function coldHit() {
  const { body, headers } = signedRequest();
  const res = http.post(WORKER_URL, body, { headers });
  coldLatency.add(res.timings.duration);
}

// Emit paper-ready output (Section VII-C). handleSummary runs once at the end.
export function handleSummary(data) {
  const warm = data.metrics.firewall_added_latency_warm?.values ?? {};
  const cold = data.metrics.firewall_added_latency_cold?.values ?? {};
  const out = {
    warm: {
      p50: warm["p(50)"], p90: warm["p(90)"], p99: warm["p(99)"],
      p999: warm["p(99.9)"], avg: warm.avg, max: warm.max, count: warm.count,
    },
    cold: { p50: cold["p(50)"], p90: cold["p(90)"], p99: cold["p(99)"], avg: cold.avg, count: cold.count },
    slo_p99_ms: 50,
    slo_met: (warm["p(99)"] ?? Infinity) < 50,
  };
  const md = `# Latency (Section VII-C)

| percentile | warm (ms) | cold (ms) |
|-----------|-----------|-----------|
| p50 | ${fmt(out.warm.p50)} | ${fmt(out.cold.p50)} |
| p90 | ${fmt(out.warm.p90)} | ${fmt(out.cold.p90)} |
| p99 | ${fmt(out.warm.p99)} | ${fmt(out.cold.p99)} |
| p99.9 | ${fmt(out.warm.p999)} | — |

SLO (p99 warm < 50 ms): ${out.slo_met ? "MET" : "NOT MET"} (measured p99 = ${fmt(out.warm.p99)} ms)
`;
  return {
    "results/latency.json": JSON.stringify(out, null, 2),
    "results/latency.md": md,
    stdout: md,
  };
}

function fmt(x) {
  return x === undefined ? "n/a" : Number(x).toFixed(2);
}
