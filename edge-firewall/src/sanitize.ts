// Input canonicalization (Section V-E) and PAN/PII redaction (Section VI-F).
//
// Two DISTINCT transforms with different purposes:
//   sanitizeForScan  -> canonical text the Aho-Corasick scanner sees. Folds
//                       encoding/homoglyph/zero-width evasions so signatures
//                       match. Applied to a COPY; the forwarded payload is the
//                       original authenticated bytes (Section V-E).
//   redactForLog     -> PAN/PII-masked text for the threat log. Guarantees raw
//                       cardholder data never reaches the logging tier
//                       (Section VI-F data minimization). Runs at the EDGE,
//                       before the queue enqueue, so CHD is out of PCI log scope.
//
// Both are O(n) single (or small-constant) passes, preserving the N_max bound
// and the linear cost model of Section III-C / V-F.

const ZERO_WIDTH = /[​-‍﻿⁠]/g; // ZWSP, ZWNJ, ZWJ, BOM, WJ

// Canonicalize for signature scanning.
export function sanitizeForScan(raw: string): string {
  // 1. Unicode NFKC: fold compatibility/homoglyph variants to canonical forms.
  let s = raw.normalize("NFKC");
  // 2. Remove zero-width characters (a signature-splitting evasion).
  s = s.replace(ZERO_WIDTH, "");
  // 3. Case fold (signatures are authored lowercase).
  s = s.toLowerCase();
  // 4. Collapse runs of whitespace to a single space so "ignore   previous"
  //    matches "ignore previous". Bounded O(n); output length <= input length.
  s = s.replace(/\s+/g, " ");
  return s;
}

// --- PAN redaction (Section VI-F) --------------------------------------------

// Luhn checksum: distinguishes real PANs from arbitrary digit runs, keeping the
// false-redaction rate low. O(len) over a candidate run.
function luhnValid(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48; // '0' = 48
    if (d < 0 || d > 9) return false;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// Matches candidate PANs: 13-19 digit runs, optionally separated by space/hyphen
// in groups (e.g. "4111 1111 1111 1111"). Word-boundary-anchored.
const PAN_CANDIDATE = /\b(?:\d[ -]?){13,19}\b/g;

// Mask a validated PAN to first-6/last-4 (the max PCI-DSS Req 3 permits on
// display); everything between becomes '*'. Non-PAN candidates are left intact.
function maskPan(match: string): string {
  const digits = match.replace(/[ -]/g, "");
  if (digits.length < 13 || digits.length > 19 || !luhnValid(digits)) {
    return match; // not a real PAN; do not alter (avoids over-redaction)
  }
  const first6 = digits.slice(0, 6);
  const last4 = digits.slice(-4);
  return `${first6}${"*".repeat(digits.length - 10)}${last4}`;
}

// Common PII patterns (extend per deployment/jurisdiction).
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const US_SSN = /\b\d{3}-\d{2}-\d{4}\b/g;

// Produce a log-safe redaction of the raw payload. Truncated to a bounded length
// so a huge payload cannot bloat a log row before TOAST even applies.
export function redactForLog(raw: string, maxLen = 4096): string {
  let s = raw.length > maxLen ? raw.slice(0, maxLen) + "…[truncated]" : raw;
  s = s.replace(PAN_CANDIDATE, maskPan);
  s = s.replace(EMAIL, "[email]");
  s = s.replace(US_SSN, "[ssn]");
  return s;
}
