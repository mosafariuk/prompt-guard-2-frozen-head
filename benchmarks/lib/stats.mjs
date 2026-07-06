// Statistical primitives for the evaluation harness (paper Section VII-E).
// Pure, dependency-free, so the numbers are auditable.

// Linear-interpolation percentile over an unsorted numeric array.
export function percentile(values, p) {
  if (values.length === 0) return NaN;
  const s = [...values].sort((a, b) => a - b);
  if (s.length === 1) return s[0];
  const rank = (p / 100) * (s.length - 1);
  const lo = Math.floor(rank);
  const hi = Math.ceil(rank);
  if (lo === hi) return s[lo];
  return s[lo] + (rank - lo) * (s[hi] - s[lo]);
}

// Wilson score interval for a binomial proportion (Section VII-E). Correct near
// 0/1 where the normal (Wald) approximation collapses — the >99% recall regime.
// Returns { p, lower, upper } at confidence `conf` (default 0.95).
export function wilson(successes, n, conf = 0.95) {
  if (n === 0) return { p: NaN, lower: NaN, upper: NaN };
  // z for two-sided conf: 1.959964 at 95%.
  const z = conf === 0.95 ? 1.959963985 : inverseNormal((1 + conf) / 2);
  const phat = successes / n;
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const center = (phat + z2 / (2 * n)) / denom;
  const half = (z / denom) * Math.sqrt((phat * (1 - phat)) / n + z2 / (4 * n * n));
  return { p: phat, lower: Math.max(0, center - half), upper: Math.min(1, center + half) };
}

// Trapezoidal AUC from labeled scores (Section VII-D). `points` = [{score,label}]
// with label in {0,1}. Sweeps every distinct threshold, computes (FPR,TPR),
// integrates by the trapezoid rule. Returns { auc, roc:[{fpr,tpr,threshold}] }.
export function rocAuc(points) {
  const P = points.filter((d) => d.label === 1).length;
  const N = points.length - P;
  if (P === 0 || N === 0) return { auc: NaN, roc: [] };
  // Descending thresholds => sweep from "classify nothing positive" downward.
  const thresholds = [...new Set(points.map((d) => d.score))].sort((a, b) => b - a);
  const roc = [{ fpr: 0, tpr: 0, threshold: Infinity }];
  for (const t of thresholds) {
    let tp = 0;
    let fp = 0;
    for (const d of points) {
      if (d.score >= t) {
        if (d.label === 1) tp++;
        else fp++;
      }
    }
    roc.push({ fpr: fp / N, tpr: tp / P, threshold: t });
  }
  roc.push({ fpr: 1, tpr: 1, threshold: -Infinity });
  let auc = 0;
  for (let i = 1; i < roc.length; i++) {
    auc += ((roc[i].fpr - roc[i - 1].fpr) * (roc[i].tpr + roc[i - 1].tpr)) / 2;
  }
  return { auc, roc };
}

// Acklam's inverse-normal approximation (for non-95% confidence levels).
function inverseNormal(p) {
  const a = [-39.6968302866538, 220.946098424521, -275.928510446969, 138.357751867269, -30.6647980661472, 2.50662827745924];
  const b = [-54.4760987982241, 161.585836858041, -155.698979859887, 66.8013118877197, -13.2806815528857];
  const c = [-0.00778489400243029, -0.322396458041136, -2.40075827716184, -2.54973253934373, 4.37466414146497, 2.93816398269878];
  const d = [0.00778469570904146, 0.32246712907004, 2.445134137143, 3.75440866190742];
  const pl = 0.02425;
  if (p < pl) {
    const q = Math.sqrt(-2 * Math.log(p));
    return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) /
      ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1);
  } else if (p <= 1 - pl) {
    const q = p - 0.5;
    const r = q * q;
    return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q /
      (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1);
  }
  const q = Math.sqrt(-2 * Math.log(1 - p));
  return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) /
    ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1);
}
