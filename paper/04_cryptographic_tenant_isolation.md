# IV. Cryptographic Tenant Isolation

Section II-D reduced the cross-tenant obligation to a cryptographic property: a webhook must
authenticate not merely *authenticity* ("some authorized party sent this") but *tenant identity*
("tenant $t_b$ authorized this"). This section discharges that obligation. We fix MAC preliminaries
(§IV-A), define the tenant-bound signing scheme (§IV-B), prove tenant binding for static keys
(§IV-C, Theorem 1), lift the result to key rotation (§IV-D, Theorem 2), and treat replay as an
orthogonal freshness property (§IV-E). §IV-F states why the tenant identifier must reside *inside*
the signed message.

## IV-A. Preliminaries: MACs, EUF-CMA, and HMAC

**MAC syntax.** A message authentication code is a triple $\Pi=(\mathsf{KGen},\mathsf{Mac},
\mathsf{Vrfy})$: $\mathsf{KGen}$ outputs a key $k\in\{0,1\}^n$; $\mathsf{Mac}_k(m)\to\tau$ produces
a tag; $\mathsf{Vrfy}_k(m,\tau)\in\{0,1\}$ verifies. Correctness requires
$\mathsf{Vrfy}_k(m,\mathsf{Mac}_k(m))=1$ for all $k,m$.

**EUF-CMA.** Existential unforgeability under chosen-message attack is defined by the game
$\mathbf{Exp}^{\text{euf-cma}}_{\Pi}(\mathcal{A})$:

1. Challenger runs $k\leftarrow\mathsf{KGen}(1^n)$ and initializes $\mathcal{Q}\leftarrow\emptyset$.
2. $\mathcal{A}$ is given oracle access to $\mathsf{Mac}_k(\cdot)$ (each query $m$ appended to
   $\mathcal{Q}$) and $\mathsf{Vrfy}_k(\cdot,\cdot)$.
3. $\mathcal{A}$ outputs $(m^\*,\tau^\*)$.
4. $\mathcal{A}$ **wins** iff $\mathsf{Vrfy}_k(m^\*,\tau^\*)=1 \wedge m^\*\notin\mathcal{Q}$.

The advantage is $\mathbf{Adv}^{\text{euf-cma}}_{\Pi}(\mathcal{A})=\Pr[\mathcal{A}\text{ wins}]$,
and $\Pi$ is EUF-CMA-secure if this is negligible for all PPT $\mathcal{A}$. **The freshness
condition $m^\*\notin\mathcal{Q}$ is essential and is precisely why unforgeability says nothing
about replay of an already-signed message** (§IV-E).

**HMAC.** For a hash $H$ with block length $B$, $\mathsf{HMAC}_k(m)=H\big((k'\oplus\mathrm{opad})\,\|\,
H((k'\oplus\mathrm{ipad})\,\|\,m)\big)$, with $\mathrm{ipad}=\texttt{0x36}^B$,
$\mathrm{opad}=\texttt{0x5C}^B$, and $k'$ the key zero-padded to $B$ bytes [RFC2104], [FIPS198-1].
We rely on the standard result that HMAC is a pseudorandom function (PRF) when the underlying
compression function is a PRF [BCK96], and that any PRF is an EUF-CMA-secure MAC with
$$\mathbf{Adv}^{\text{euf-cma}}_{\mathsf{HMAC}}(\mathcal{A}) \;\le\;
\mathbf{Adv}^{\text{prf}}_{\mathsf{HMAC}}(\mathcal{B}) + 2^{-n},\tag{1}$$
where $n$ is the tag length in bits (for HMAC-SHA256, $n=256$, so $2^{-n}$ is cryptographically
negligible). We treat (1) as a trust root (§II-A) and reduce all subsequent claims to it.

**Multi-user security.** Because a multi-tenant deployment instantiates $u$ *independent* keys
(one per tenant, or per tenant-epoch under rotation), the operative notion is *multi-user*
security. In the multi-user PRF (mu-PRF) game, $\mathcal{A}$ interacts with $u$ independent
instances and distinguishes them jointly from $u$ random functions; in the multi-user EUF-CMA
(mu-EUF-CMA) game, $\mathcal{A}$ wins by producing a forgery under *any* one of the $u$ instances.
The naive hybrid bound loses a factor $u$,
$\mathbf{Adv}^{\text{mu-prf}}_{\mathsf{HMAC},u}\le u\cdot\mathbf{Adv}^{\text{prf}}_{\mathsf{HMAC}}$,
which is unacceptable when $u$ scales to $10^5$–$10^6$ tenants. We instead invoke the *tight*
multi-user analysis of HMAC [BBT16], under which
$$\mathbf{Adv}^{\text{mu-euf-cma}}_{\mathsf{HMAC},u}(\mathcal{A})\;\le\;
\mathbf{Adv}^{\text{mu-prf}}_{\mathsf{HMAC},u}(\mathcal{A})+Q_v\,2^{-n},\tag{2}$$
where the mu-PRF term **carries no linear-in-$u$ factor** — it is bounded by the adversary's
*aggregate* query budget and a birthday term, independent of the number of instances — and $Q_v$
is the number of verification queries. Equations (1)–(2) are the only cryptographic assumptions
used below.

## IV-B. The Tenant-Bound Webhook Signing Scheme

For tenant $t_i$ holding key $k_{i,\kappa}$ under key-id $\kappa$, define the **canonical signed
message**
$$m \;=\; \mathsf{tid}_i \,\|\, \kappa \,\|\, t_s \,\|\, \eta \,\|\, H_{\text{body}},$$
where $\mathsf{tid}_i$ is the tenant identifier, $\kappa$ the key-id, $t_s$ a Unix timestamp,
$\eta$ a random nonce ($\lambda$ bits), and $H_{\text{body}}=\mathsf{SHA256}(\text{payload})$ a
digest binding the body. The transmitted signature is $\tau=\mathsf{HMAC}_{k_{i,\kappa}}(m)$, sent
with $(\mathsf{tid}_i,\kappa,t_s,\eta)$ in headers. Each field is length-prefixed (or delimited by a
byte absent from the field alphabet) so that the encoding is injective — no two distinct field
tuples share a serialization, foreclosing canonicalization-ambiguity attacks. This mirrors the
Stripe scheme (signed payload $=$ `timestamp . "." . body`, `v1=HMAC-SHA256`) [Stripe-sig] but
additionally binds $\mathsf{tid}_i$ and $\kappa$.

Verification at the edge (Fig. 1, step 2): recompute $\tau'=\mathsf{HMAC}_{k_{i,\kappa}}(m)$ using
the key selected by $(\mathsf{tid}_i,\kappa)$ and accept iff $\tau'=\tau$ under a constant-time
comparison (to avoid timing side channels), the timestamp is fresh, and the nonce is unseen
(§IV-E).

## IV-C. Tenant Binding under Static Keys (Theorem 1)

**Tenant-binding game** $\mathbf{Exp}^{\text{bind}}$. Let each tenant $t_i\in\mathcal{T}$ have an
independent key $k_i\leftarrow\mathsf{KGen}(1^n)$ (single key per tenant in this subsection).
The adversary $\mathcal{A}$:

1. selects a corrupt set $\mathcal{C}\subset\mathcal{T}$ and receives $\{k_i : t_i\in\mathcal{C}\}$;
2. for every uncorrupted tenant $t_j\notin\mathcal{C}$, obtains oracle access to
   $\mathsf{Mac}_{k_j}(\cdot)$ (this over-approximates the Dolev–Yao capability: observing $t_j$'s
   legitimate webhooks is a *known*-message attack, a special case of chosen-message);
3. outputs a target $t_b\notin\mathcal{C}$ and a pair $(m^\*,\tau^\*)$ with $\mathsf{tid}(m^\*)=
   \mathsf{tid}_b$.

$\mathcal{A}$ **wins** iff $\mathsf{Vrfy}_{k_b}(m^\*,\tau^\*)=1$ and $m^\*$ was never returned by
$t_b$'s signing oracle. Intuitively: the attacker, even owning every other tenant's key and seeing
all of $t_b$'s traffic, produces a *new* webhook that the system attributes to $t_b$.

> **Theorem 1 (Tenant binding, static keys — multi-user).** Let $u=|\mathcal{T}\setminus
> \mathcal{C}|$ be the number of uncorrupted tenants. For the scheme of §IV-B with independent
> per-tenant keys and any PPT adversary $\mathcal{A}$, there exists a PPT $\mathcal{B}$ with
> $$\mathbf{Adv}^{\text{bind}}(\mathcal{A}) \;\le\;
> \mathbf{Adv}^{\text{mu-euf-cma}}_{\mathsf{HMAC},u}(\mathcal{B})
> \;\le\; \mathbf{Adv}^{\text{mu-prf}}_{\mathsf{HMAC},u}(\mathcal{B})+Q_v\,2^{-n}.$$
> By the tight multi-user security of HMAC (Eq. 2, [BBT16]) the right-hand side is **independent
> of the tenant-pool size $u$** — it is bounded by $\mathcal{A}$'s aggregate query budget and a
> birthday term, not by the number of tenants.

*Proof (multi-user reduction, no target guessing).* $\mathcal{B}$ plays mu-EUF-CMA against the $u$
uncorrupted-tenant instances $\{k_j : t_j\notin\mathcal{C}\}$. It generates the corrupt tenants'
keys itself and answers their key-reveal and signing queries directly; each signing query for an
uncorrupted $t_j$ is forwarded to instance $j$'s $\mathsf{Mac}$ oracle, recording the queried $m$.
When $\mathcal{A}$ halts with $(m^\*,\tau^\*)$ where $\mathsf{tid}(m^\*)=\mathsf{tid}_b$ for some
uncorrupted $t_b$ and $m^\*$ was never signed by $t_b$, then — because the encoding is injective
and $\mathsf{tid}$ occupies a fixed field — $(b, m^\*,\tau^\*)$ is verbatim a valid forgery under
instance $b$ with $m^\*$ fresh for that instance: a win in the mu-EUF-CMA game. **No guess of the
target is required**, because a forgery under *any* uncorrupted instance already wins the
multi-user game; this is exactly what removes the factor-$u$ loss. The second inequality is the
generic mu-PRF $\Rightarrow$ mu-MAC step (Eq. 2). $\square$

The theorem formalizes the §II-D requirement: because $\mathsf{tid}_i$ is *inside* the MAC input,
attributing a webhook to $t_b$ is exactly as hard as forging HMAC in the multi-user game —
independent of how many *other* tenant keys the adversary holds *and* independent of the tenant
population. This is the shared-key attribution failure (§II-D, mode 2) provably eliminated, with a
bound that does not degrade at enterprise scale.

## IV-D. Key Rotation in the Formal Model (Theorem 2)

Static keys are unrealistic: keys must rotate for compromise recovery and hygiene. We model
rotation without abandoning Theorem 1.

**Rotation model.** Each tenant maintains a set of keys $\{k_{i,\kappa}\}$ indexed by key-id
$\kappa$, each with a validity window $[\,a_\kappa, b_\kappa\,)$. Windows *overlap*: when rotating
from $\kappa$ to $\kappa+1$, both are valid for a rollover interval, so in-flight producers signing
under the old key are not rejected. Let $L=\max_i \max_t |\{\kappa : t\in[a_\kappa,b_\kappa)\}|$ be
the maximum number of simultaneously valid keys for any tenant at any time (typically $L=2$). The
verifier selects the key by the *authenticated* $\kappa$ carried in $m$ and accepts iff the tag
validates under $k_{i,\kappa}$ and $\kappa$ is currently valid.

> **Theorem 2 (Tenant binding under rotation).** Let $u'=\sum_{t_i\notin\mathcal{C}}
> |\{\kappa : k_{i,\kappa}\text{ currently valid}\}| \le uL$ be the total number of
> simultaneously-valid uncorrupted keys. Then
> $$\mathbf{Adv}^{\text{bind-rot}}(\mathcal{A}) \;\le\;
> \mathbf{Adv}^{\text{mu-euf-cma}}_{\mathsf{HMAC},u'}(\mathcal{B})
> \;\le\; \mathbf{Adv}^{\text{mu-prf}}_{\mathsf{HMAC},u'}(\mathcal{B})+Q_v\,2^{-n},$$
> which by Eq. 2 is **independent of both $u$ and the overlap multiplicity $L$**.

*Proof (each valid key is an instance).* Treat every currently-valid uncorrupted pair
$(t_i,\kappa)$ as one of $u'$ independent mu-EUF-CMA instances. The rotation verifier accepts a
$t_b$-attributed message iff its tag validates under *some* valid $(t_b,\kappa)$ — i.e., iff it is
a forgery under one of those instances. The reduction of Theorem 1 applies verbatim with the
instance set enlarged from $u$ to $u'$: a win for $\mathcal{A}$ is a forgery under some instance,
winning the mu-EUF-CMA game with no target or key guess. Because the tight multi-user bound (Eq. 2)
has no linear-in-instance-count factor, enlarging $u\to u'\le uL$ does not degrade the bound.
$\square$

**Consequences and strategy.** (i) Under the tight multi-user bound the security is independent of
the overlap multiplicity $L$; $L$ affects only *operational* exposure, not the reduction. Keeping
the rollover interval short still matters because it bounds the *compromise window* (iii), not the
advantage. (Under the weaker generic bound one would pay a factor $u'\le uL$; we avoid this via
[BBT16].)
(ii) Because $\kappa$ is authenticated inside $m$, an attacker cannot force verification under a
*revoked* key (a downgrade): tampering with $\kappa$ breaks the tag. (iii) On compromise of
$k_{i,\kappa}$, the operator advances $\kappa$ and shrinks the old window to $\{$now$\}$; the
exposure is bounded by the rollover interval. Keys are stored in the edge secret store / KV and
selected by $(\mathsf{tid}_i,\kappa)$ at verification; retrieval is I/O, not CPU (§III-B).
(iv) Forward secrecy is *not* claimed: HMAC keys are symmetric, so a leaked $k_{i,\kappa}$ forges
messages within $\kappa$'s window. Rotation bounds, but does not retroactively protect, that window.

## IV-E. Replay Resistance as an Orthogonal Freshness Property

Theorem 1's freshness clause ($m^\*\notin\mathcal{Q}$) means a *replayed* legitimate webhook
$(m,\tau)$ — where $m$ *was* signed by $t_b$ — is **not** an unforgeability break. Replay is a
distinct property requiring freshness, which the $t_s$ and $\eta$ fields provide.

**Freshness game.** The verifier maintains a nonce cache $\mathcal{N}$ and accepts $(m,\tau)$ only
if: (a) $\tau$ verifies (§IV-C); (b) $|t_{\text{now}}-t_s|\le\Delta$ (timestamp tolerance); and
(c) $\eta\notin\mathcal{N}$, after which $\eta$ is inserted with TTL $2\Delta$. An adversary
replaying a captured $(m,\tau)$ succeeds only if it arrives (i) within $\Delta$ of $t_s$ *and*
(ii) with $\eta$ already evicted from $\mathcal{N}$. But $\mathcal{N}$ retains every nonce for
$2\Delta\ge\Delta$, so within the timestamp window the nonce is necessarily still present and the
replay is rejected; outside the window the timestamp check rejects it. Hence
$$\Pr[\text{replay accepted}] \;\le\; \Pr[\text{nonce-store loss within }2\Delta]\;+\;2^{-\lambda},$$
where the first term is the probability the nonce store fails to retain $\eta$ over the window (an
availability parameter of the KV/DO store) and $2^{-\lambda}$ bounds an accidental nonce collision
causing false eviction. With $\lambda=128$ the collision term is negligible, so replay resistance
reduces to nonce-store reliability over $2\Delta$.

**Parameterization and cost.** $\Delta$ trades replay window against tolerance to clock skew and
producer/delivery latency; Stripe uses $\Delta=300\text{ s}$ by default [Stripe-sig], which we
adopt as a baseline. The nonce check is a single keyed lookup in edge KV or a Durable Object; it is
a subrequest (I/O), so it does **not** consume the CPU budget of §III-C — replay defense is free
against the sub-millisecond screening analysis. A stateless fallback (timestamp-only, no nonce)
degrades to "at-most-one replay per $\Delta$ window per message" and is offered as a
lower-assurance mode when KV latency is unacceptable.

## IV-F. Why the Tenant Identifier Must Be Inside the Signature

If $\mathsf{tid}_i$ were transmitted only as an *unauthenticated* header (outside $m$), an attacker
holding any single valid $(m,\tau)$ under key $k$ could attach an arbitrary $\mathsf{tid}$ header,
and — if the origin selected the verification key by the *header* rather than by the signed field —
cause $t_b$-authored content to execute in $t_a$'s context or vice versa. This is exactly the
confused-deputy instantiation of §II-D mode 2. Binding $\mathsf{tid}_i$ (and $\kappa$) *inside* the
MAC input makes the identifier immutable under the unforgeability guarantee: any change to
$\mathsf{tid}$ changes $m$, which invalidates $\tau$ unless the attacker can forge — contradicting
Theorem 1. The binding is therefore not a convention but a proven property, which is the sense in
which §II-D's isolation obligation is *discharged* rather than merely *addressed*.

---

### Citation keys
- **[RFC2104]** H. Krawczyk, M. Bellare, R. Canetti, "HMAC: Keyed-Hashing for Message Authentication," RFC 2104, IETF, Feb. 1997.
- **[FIPS198-1]** NIST, "The Keyed-Hash Message Authentication Code (HMAC)," FIPS PUB 198-1, 2008.
- **[BCK96]** M. Bellare, R. Canetti, H. Krawczyk, "Keying Hash Functions for Message Authentication," CRYPTO 1996. (HMAC/NMAC PRF security; see also M. Bellare, "New Proofs for NMAC and HMAC," CRYPTO 2006.)
- **[BBT16]** M. Bellare, D. J. Bernstein, S. Tessaro, "Hash-Function Based PRFs: AMAC and Its Multi-User Security," EUROCRYPT 2016. (Tight multi-user security of HMAC-style PRFs.)
- **[Stripe-sig]** Stripe, "Verify webhook signatures," docs.stripe.com/webhooks/signature (accessed 2026-07-04).

> Evidence status: HMAC construction (RFC 2104), FIPS 198-1 standardization, the PRF⇒MAC bound
> (BCK96/Bellare06), the tight multi-user HMAC bound (BBT16), and the Stripe timestamped scheme are
> primary-sourced (verified-facts Part 3;
> fetched from primaries, flagged for a final quote-level re-verification before submission). The
> tenant-binding and rotation theorems (IV-C/D) and the replay bound (IV-E) are original results;
> their proofs reduce solely to the standard EUF-CMA/PRF assumptions and assert no unverified
> external facts.
