// k6 latency benchmark for the Tier-3a deep-scan endpoint (paper §VII / §IX).
//
// Load-tests the on-prem FastAPI service (POST /v1/deep-scan) under high concurrency
// to isolate the model's PURE PROCESSING latency from network overhead — run it
// from the origin host itself (against 127.0.0.1) so the measurement excludes WAN.
// Separates cold-start (first hits, model warm-up) from warm steady state and
// records p50/p90/p99.
//
// Run (on the Debian origin host):
//   DEEPSCAN_URL=http://127.0.0.1:8080/v1/deep-scan \
//   DEEPSCAN_SHARED_SECRET=<secret> \
//   k6 run latency_escalation.k6.js

import http from "k6/http";
import { Trend, Rate } from "k6/metrics";
import { SharedArray } from "k6/data";

const URL = __ENV.DEEPSCAN_URL || "http://127.0.0.1:8080/v1/deep-scan";
const SECRET = __ENV.DEEPSCAN_SHARED_SECRET || "";
const RATE = parseInt(__ENV.RATE || "50", 10);       // req/s in the warm phase
const DURATION = __ENV.DURATION || "60s";

const corpus = new SharedArray("payloads", function () {
  let data;
  try { data = JSON.parse(open("./corpus/payloads.json")); }
  catch (e) { data = JSON.parse(open("./corpus/sample_payloads.json")); }
  return data.rows;
});

const warm = new Trend("deepscan_latency_warm", true);
const cold = new Trend("deepscan_latency_cold", true);
const blocked = new Rate("deepscan_blocked");

export const options = {
  scenarios: {
    cold: { executor: "per-vu-iterations", vus: 10, iterations: 1, exec: "coldHit", startTime: "0s" },
    warm: {
      executor: "constant-arrival-rate",
      rate: RATE, timeUnit: "1s", duration: DURATION,
      preAllocatedVUs: 20, maxVUs: 100, exec: "warmHit", startTime: "15s", // warm-up first
    },
  },
  thresholds: {
    // Soft SLO for an on-prem CPU encoder; tune to your host. Records regardless.
    "deepscan_latency_warm": ["p(99)<500"],
    "http_req_failed": ["rate<0.01"],
  },
};

function req() {
  const p = corpus[Math.floor(Math.random() * corpus.length)];
  const body = JSON.stringify({ text: p.text, tenant_id: "tenant-bench" });
  const params = { headers: { "Content-Type": "application/json", "X-Edge-Auth": SECRET } };
  return { body, params };
}

function fire(trend) {
  const { body, params } = req();
  const res = http.post(URL, body, params);
  trend.add(res.timings.duration);
  if (res.status === 200) {
    try { blocked.add(JSON.parse(res.body).action === "block"); } catch (_) { /* ignore */ }
  }
}

export function warmHit() { fire(warm); }
export function coldHit() { fire(cold); }

export function handleSummary(data) {
  const w = data.metrics.deepscan_latency_warm?.values ?? {};
  const c = data.metrics.deepscan_latency_cold?.values ?? {};
  const out = {
    endpoint: URL,
    warm: { p50: w["p(50)"], p90: w["p(90)"], p99: w["p(99)"], avg: w.avg, max: w.max, count: w.count },
    cold: { p50: c["p(50)"], p90: c["p(90)"], p99: c["p(99)"], avg: c.avg, count: c.count },
  };
  const f = (x) => (x === undefined ? "n/a" : Number(x).toFixed(2));
  const md = `# Tier-3a Deep-Scan Latency (Section VII-C / IX)

Endpoint: ${URL}  (measured from the origin host; excludes WAN)

| percentile | warm (ms) | cold (ms) |
|-----------|-----------|-----------|
| p50 | ${f(out.warm.p50)} | ${f(out.cold.p50)} |
| p90 | ${f(out.warm.p90)} | ${f(out.cold.p90)} |
| p99 | ${f(out.warm.p99)} | ${f(out.cold.p99)} |
`;
  return { "results/latency_escalation.json": JSON.stringify(out, null, 2),
           "results/latency_escalation.md": md, stdout: md };
}
