// Aho-Corasick multi-pattern matcher (paper Section V-B).
//
// WHY Aho-Corasick and not per-pattern regex/KMP:
//   - Build: O(m) in total pattern length m. Done ONCE at module scope (see
//     signatures.ts / index.ts) so it is amortized across the isolate lifetime
//     and contributes ZERO to per-request CPU (Section III-A).
//   - Search: O(n + z), n = input length, z = matches, in a SINGLE pass over the
//     input regardless of how many signatures exist. No backtracking (unlike a
//     regex alternation, which risks ReDoS -> a DoS surface, Table I row 7).
//
// The automaton is a trie augmented with failure (suffix) links and output links,
// i.e. a deterministic finite automaton. Transitions are keyed by UTF-16 code
// unit; inputs are NFKC-normalized + casefolded before search (sanitize.ts), so
// signatures are authored in lowercase canonical form.

export interface Pattern {
  readonly id: string; // human-readable signature name (for the audit log)
  readonly text: string; // canonical (lowercase) signature string
  readonly blocking: boolean; // true => a single match forces reject (hard hit)
  readonly weight: number; // contribution to the soft score if non-blocking
}

interface Node {
  next: Map<number, number>; // code unit -> node index (goto)
  fail: number; // failure link
  outputs: number[]; // indices into `patterns` ending at this node
}

export interface Match {
  readonly patternIndex: number;
  readonly end: number; // index of last char of the match in the input
}

export class AhoCorasick {
  private readonly nodes: Node[];
  private readonly patterns: readonly Pattern[];

  constructor(patterns: readonly Pattern[]) {
    this.patterns = patterns;
    // Root is node 0.
    this.nodes = [{ next: new Map(), fail: 0, outputs: [] }];
    this.buildTrie();
    this.buildFailureLinks();
  }

  // --- O(m) construction -----------------------------------------------------
  private buildTrie(): void {
    for (let p = 0; p < this.patterns.length; p++) {
      let state = 0;
      const text = this.patterns[p]!.text;
      for (let i = 0; i < text.length; i++) {
        const c = text.charCodeAt(i);
        let nxt = this.nodes[state]!.next.get(c);
        if (nxt === undefined) {
          nxt = this.nodes.length;
          this.nodes.push({ next: new Map(), fail: 0, outputs: [] });
          this.nodes[state]!.next.set(c, nxt);
        }
        state = nxt;
      }
      this.nodes[state]!.outputs.push(p);
    }
  }

  // BFS to compute failure links and merge outputs along suffix links.
  private buildFailureLinks(): void {
    const queue: number[] = [];
    const root = this.nodes[0]!;
    for (const child of root.next.values()) {
      this.nodes[child]!.fail = 0;
      queue.push(child);
    }
    let head = 0;
    while (head < queue.length) {
      const u = queue[head++]!;
      const node = this.nodes[u]!;
      for (const [c, v] of node.next) {
        // Find fail link for child v by walking u's fail chain.
        let f = node.fail;
        while (f !== 0 && !this.nodes[f]!.next.has(c)) {
          f = this.nodes[f]!.fail;
        }
        const candidate = this.nodes[f]!.next.get(c);
        this.nodes[v]!.fail = candidate !== undefined && candidate !== v ? candidate : 0;
        // Merge outputs from the failure target (suffix matches).
        const failOutputs = this.nodes[this.nodes[v]!.fail]!.outputs;
        if (failOutputs.length > 0) {
          this.nodes[v]!.outputs.push(...failOutputs);
        }
        queue.push(v);
      }
    }
  }

  // --- O(n + z) search -------------------------------------------------------
  // `stopOnBlocking`: early-exit on the first blocking-class match (Section V-B
  // match cap). Safe for a reject decision; only limits enumeration for logging.
  // `capMatches`: bound on reported non-blocking matches (bounds z for logging).
  search(
    input: string,
    stopOnBlocking = true,
    capMatches = 64,
  ): { matches: Match[]; blockingHit: boolean } {
    const matches: Match[] = [];
    let blockingHit = false;
    let state = 0;
    for (let i = 0; i < input.length; i++) {
      const c = input.charCodeAt(i);
      // Follow failure links until a transition exists or we are at root.
      while (state !== 0 && !this.nodes[state]!.next.has(c)) {
        state = this.nodes[state]!.fail;
      }
      state = this.nodes[state]!.next.get(c) ?? 0;
      const outputs = this.nodes[state]!.outputs;
      for (let k = 0; k < outputs.length; k++) {
        const pi = outputs[k]!;
        if (this.patterns[pi]!.blocking) {
          blockingHit = true;
          matches.push({ patternIndex: pi, end: i });
          if (stopOnBlocking) return { matches, blockingHit };
        } else if (matches.length < capMatches) {
          matches.push({ patternIndex: pi, end: i });
        }
      }
    }
    return { matches, blockingHit };
  }

  patternAt(index: number): Pattern {
    return this.patterns[index]!;
  }
}
