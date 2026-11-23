"""Builds docs/CommitRPS_Technical_Report.pdf from measured results (docs/results/*.json).
Run:  python3 docs/report/build_report.py   (needs playwright + Chrome)"""
import json, pathlib, html
from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parents[2]
R = ROOT / 'docs/results'
att = json.loads((R / 'attacks.json').read_text())
bench = json.loads((R / 'bench.json').read_text())
sweep = json.loads((R / 'sweep.json').read_text())
FIG = (ROOT / 'docs/report/figs').as_uri()
DIA = (ROOT / 'docs/diagrams/png').as_uri()
e = html.escape

def fig(src, cap, w='100%'):
    fig.n += 1
    return f'<figure><img src="{src}" style="max-width:{w};max-height:205mm;width:auto;height:auto"/><figcaption>Figure {fig.n}. {cap}</figcaption></figure>'
fig.n = 0

b = {r['name']: r for r in bench['rows']}
def ms(name): return f"{b[name]['msPerOp']:.2f}"

a1, a2, a5, a6, a7 = att['A1'], att['A2'], att['A5'], att['A6'], att['A7']
bench_rows = ''.join(f"<tr><td>{e(r['name'])}</td><td class=n>{r['opsPerSec']:,}</td><td class=n>{r['msPerOp']:.3f}</td></tr>" for r in bench['rows'])
sweep_rows = ''.join(f"<tr><td class=n>{s['bits']}</td><td class=n>{s['guesses']:,}</td><td class=n>{s['ms']}</td></tr>" for s in sweep['salt'])

HTML = f"""<!doctype html><html><head><meta charset="utf-8"><style>
@page {{ size: A4; margin: 20mm 18mm 20mm 18mm; }}
body {{ font: 10.6pt/1.5 'Georgia', 'DejaVu Serif', serif; color:#1b1f27; }}
h1,h2,h3,h4 {{ font-family: 'Helvetica Neue', Arial, sans-serif; color:#14181f; line-height:1.2; }}
h1 {{ font-size: 25pt; margin: 0 0 6pt; }}
h2 {{ font-size: 15pt; margin: 22pt 0 8pt; padding-bottom: 4pt; border-bottom: 2px solid #c98a12; break-after: avoid; }}
h3 {{ font-size: 11.5pt; margin: 14pt 0 5pt; break-after: avoid; }}
p {{ margin: 0 0 7pt; text-align: justify; }}
code, .m {{ font-family: 'DejaVu Sans Mono', Menlo, monospace; font-size: 8.6pt; background:#f3f4f7; padding:0 3px; border-radius:3px; }}
pre {{ font-family: 'DejaVu Sans Mono', monospace; font-size: 8.3pt; background:#f5f6f9; border-left:3px solid #c98a12; padding:8px 10px; white-space:pre-wrap; break-inside: avoid; }}
table {{ border-collapse: collapse; width:100%; margin: 6pt 0 10pt; font: 8.9pt/1.35 Arial, sans-serif; break-inside: avoid; }}
th {{ background:#f1ede4; text-align:left; }}
th, td {{ border:1px solid #d9dce3; padding:4px 6px; vertical-align: top; }}
td.n, th.n {{ text-align:right; font-variant-numeric: tabular-nums; }}
figure {{ margin: 8pt 0 12pt; text-align:center; break-inside: avoid; }}
figure img {{ border:1px solid #e1e4ea; }}
figcaption {{ font: italic 8.8pt Arial, sans-serif; color:#555; margin-top:4pt; }}
.cover {{ height: 247mm; display:flex; flex-direction:column; justify-content:space-between; break-after: page; }}
.band {{ background:#14181f; color:#fff; padding:26pt 24pt; border-radius:6px; }}
.band h1 {{ color:#fff; }} .band .sub {{ color:#f2b33d; font: 600 11pt Arial; letter-spacing:.06em; text-transform:uppercase; }}
.meta td {{ border:none; padding:3px 0; font-size:10.5pt; }}
.callout {{ background:#fbf6ea; border-left:3px solid #c98a12; padding:7pt 10pt; margin:8pt 0; font-size:9.8pt; break-inside: avoid; }}
.toc {{ columns: 2; font: 10pt/1.8 Arial, sans-serif; }}
.ok {{ color:#1f8a4c; font-weight:bold; }} .bad {{ color:#c0392b; font-weight:bold; }}
.pb {{ break-before: page; }}
</style></head><body>

<section class="cover">
 <div class="band">
  <div class="sub">CS-3002 Information Security · Term Project · Topic 13</div>
  <h1>CommitRPS</h1>
  <p style="font-size:14pt;color:#dfe3ea;text-align:left">A decentralized rock-paper-scissors tournament secured by Pedersen commitments with random blinding factors</p>
  <p style="color:#9aa3b2;text-align:left">Technical documentation: architecture, threat model, cryptographic library choices, implementation hurdles and security analysis</p>
 </div>
 <div>
  <table class="meta">
   <tr><td style="width:36%"><b>Algorithm</b></td><td>Pedersen Commitment Scheme with random blinding factors (ristretto255)</td></tr>
   <tr><td><b>Objective</b></td><td>Commit to a hidden value, stay bound to it, and open/prove it later</td></tr>
   <tr><td><b>Application</b></td><td>Commit-reveal rock-paper-scissors tournament with anti-cheating guarantees</td></tr>
   <tr><td><b>Live deployment</b></td><td>https://&lt;your-app&gt;.onrender.com</td></tr>
   <tr><td><b>Source code</b></td><td>https://github.com/&lt;team&gt;/commitrps</td></tr>
   <tr><td><b>Team</b></td><td>Member 1 (roll no.) · Member 2 (roll no.) · Member 3 (roll no.)</td></tr>
   <tr><td><b>Date</b></td><td>November 2026</td></tr>
  </table>
 </div>
</section>

<h2 style="margin-top:0">Abstract</h2>
<p>Online rock-paper-scissors has a basic fairness problem: whoever moves second can see the first move. The standard fix is a <i>commit-reveal</i> protocol. Every player first publishes a commitment to their move, and only once all commitments are fixed do players open them. CommitRPS is a full-stack, publicly deployable web application that implements this protocol with <b>Pedersen commitments</b> <span class="m">C = m·G + r·H</span> on the prime-order <b>ristretto255</b> group, using fresh uniformly random blinding factors. These commitments are <i>perfectly hiding</i> and <i>computationally binding</i>. On top of the raw scheme we add (i) a nothing-up-my-sleeve generator <span class="m">H</span> from RFC 9380 hash-to-curve, (ii) a context-bound Okamoto zero-knowledge proof of knowledge of the opening, which makes the otherwise malleable commitments non-malleable, (iii) Ed25519 signatures on every protocol message, (iv) reveal deadlines against selective abort, and (v) a hash-chained, publicly verifiable audit log. All primitives come from the audited <span class="m">@noble</span> libraries. An Attack Lab demonstrates eight attacks against weakened configurations and shows each one failing against the shipped configuration. For example, without the proof of knowledge a copy-cat attacker wins <b>{a2['vulnerable']['winRate']}%</b> of rounds instead of 33.3%; with it, <b>{a2['mitigated']['rejected']}/{a2['rounds']}</b> mauled commitments are rejected.</p>

<h3>Contents</h3>
<div class="toc">1. Problem &amp; objectives<br>2. Cryptographic background<br>3. Threat model<br>4. System architecture<br>5. Protocol workflows<br>6. Cryptographic library choices<br>7. Key lifecycle management<br>8. Implementation &amp; hurdles<br>9. Security evaluation &amp; attacks<br>10. Security vs. usability<br>11. Testing &amp; verification<br>12. User interface &amp; onboarding<br>13. Deployment &amp; source control<br>14. Limitations &amp; future work<br>15. Conclusion<br>References · Appendix</div>

<h2>1. Problem statement &amp; objectives</h2>
<p>In a <i>decentralized</i> tournament there is no trusted dealer who collects moves in secret. Messages go through a server that might be curious or even malicious, and players might cheat. Our goal is a system in which:</p>
<ul>
<li><b>Nobody</b> (opponent, server operator, network eavesdropper) learns a player's move before that player reveals it. This is <i>hiding</i>.</li>
<li>No player can change their move after seeing the opponent's. This is <i>binding</i>.</li>
<li>No player can derive their commitment from an opponent's commitment. This is <i>non-malleability</i>.</li>
<li>The referee cannot forge, alter or invent moves, and anyone can audit a finished tournament (<i>public verifiability</i>).</li>
<li>Refusing to reveal after seeing the other move does not pay off (<i>fairness against aborts</i>).</li>
</ul>
<p>The topic brief describes a "hash commitment of the move" with a salt revealed in round two. We implement that scheme too, as a selectable mode, and compare it with Pedersen throughout. The primary scheme, as the assignment requires, is the <b>Pedersen commitment with random blinding factors</b>.</p>

<h2>2. Cryptographic background</h2>
<h3>2.1 Commitment schemes</h3>
<p>A commitment scheme has two algorithms. <span class="m">Commit(m; r) → C</span> and <span class="m">Open(C, m, r) → {{0,1}}</span>. <i>Hiding</i> means C reveals nothing about m. <i>Binding</i> means no efficient adversary can find <span class="m">(m, r) ≠ (m′, r′)</span> with <span class="m">Commit(m; r) = Commit(m′; r′)</span>. A scheme cannot be both perfectly hiding and perfectly binding, so every design picks which property rests on a computational assumption.</p>
<h3>2.2 Pedersen commitments</h3>
<p>Let 𝔾 be a group of prime order ℓ with generators G and H such that nobody knows <span class="m">log_G(H)</span>. To commit to <span class="m">m ∈ Z_ℓ</span>, sample <span class="m">r ← Z_ℓ</span> uniformly and output <span class="m">C = m·G + r·H</span>.</p>
<ul>
<li><b>Perfectly hiding:</b> for uniform r, r·H is a uniform group element, so C is uniform and independent of m. For every candidate move m′ there is exactly one r′ that opens C to m′, so even an unbounded adversary learns nothing.</li>
<li><b>Computationally binding:</b> two openings give <span class="m">mG + rH = m′G + r′H</span>, so <span class="m">log_G(H) = (m − m′)/(r′ − r)</span>. Breaking binding is as hard as computing a discrete logarithm.</li>
<li><b>Additively homomorphic:</b> <span class="m">C(m₁,r₁) + C(m₂,r₂) = C(m₁+m₂, r₁+r₂)</span>. Useful for confidential transactions, but here it makes the scheme <b>malleable</b> (§9, attack A2).</li>
</ul>
<p>We encode <span class="m">rock = 1, paper = 2, scissors = 3</span>. The group is <b>ristretto255</b> (RFC 9496), a prime-order quotient of Curve25519 with ℓ ≈ 2<sup>252</sup> and about 126-bit security. It removes the cofactor-8 pitfalls of raw Ed25519 points: every valid 32-byte encoding is a unique group element.</p>
<h3>2.3 Generating H with nothing up our sleeve</h3>
<p>If whoever chose H knew <span class="m">t = log_G(H)</span>, they could open any commitment to any move (attack A4). We derive <span class="m">H = hash_to_curve("CommitRPS/v1/pedersen/H")</span> with RFC 9380 (<span class="m">ristretto255_XMD:SHA-512_R255MAP_RO_</span>, domain-separation tag <span class="m">CommitRPS-v1-NUMS-H…</span>). The output behaves like a random oracle, so nobody, us included, knows t. Every browser re-derives H and the Inspector checks that it matches the server's published value.</p>
<h3>2.4 Proof of knowledge of the opening (Okamoto Σ-protocol)</h3>
<p>To stop a player from submitting a commitment derived from someone else's, each commitment carries a non-interactive zero-knowledge proof that the sender knows <span class="m">(m, r)</span>:</p>
<pre>Prover:   a, b ← Z_ℓ;   T = a·G + b·H
          c  = SHA-512("CommitRPS/v1/pok-opening" ‖ ctx ‖ G ‖ H ‖ C ‖ T) mod ℓ
          s₁ = a + c·m,   s₂ = b + c·r              proof π = (T, s₁, s₂)
Verifier: s₁·G + s₂·H  ==  T + c·C
ctx = "CommitRPS/v1|t=&lt;tournament&gt;|m=&lt;match&gt;|r=&lt;round&gt;|p=&lt;player&gt;"</pre>
<p>Completeness follows by substitution. Special soundness: two accepting transcripts with different c reveal (m, r). Honest-verifier zero-knowledge holds because (T, s₁, s₂) can be simulated. Putting <i>ctx</i>, which includes the player id, into the Fiat–Shamir hash means a proof cannot be transplanted to another player, match or round. An attacker who computes <span class="m">C′ = C + G</span> knows neither m nor r, so he cannot prove knowledge of an opening of C′. This makes the commitment <b>non-malleable</b> in the random-oracle model.</p>
<h3>2.5 Salted hash commitments (comparison mode)</h3>
<p><span class="m">C = SHA-256("CommitRPS/v1/hash-commit|" ‖ ctx ‖ "|" ‖ move ‖ "|" ‖ salt)</span> with a 256-bit CSPRNG salt. This is <i>computationally</i> hiding (preimage resistance, random-oracle heuristic) and computationally binding (collision resistance). It is not homomorphic, so it needs no proof of knowledge, but it is only as hiding as the salt is unpredictable (attack A1).</p>
<table><tr><th></th><th>Pedersen (ristretto255)</th><th>Salted SHA-256</th></tr>
<tr><td>Hiding</td><td>Perfect (information-theoretic)</td><td>Computational</td></tr>
<tr><td>Binding</td><td>Computational: DLog (~2<sup>126</sup>)</td><td>Computational: collisions (~2<sup>128</sup>)</td></tr>
<tr><td>Homomorphic / malleable</td><td>Yes / yes → needs PoK</td><td>No / no</td></tr>
<tr><td>Commitment size</td><td>32 B (+96 B proof)</td><td>32 B</td></tr>
<tr><td>Post-quantum</td><td>Binding breaks (Shor), hiding holds forever</td><td>Both hold (Grover only)</td></tr></table>

<h2>3. Threat model</h2>
<p><b>Adversaries.</b> (1) A <b>malicious player</b>: active, runs arbitrary client code, can copy or transform any published value, and chooses when or whether to reveal. (2) The <b>referee server</b>: we treat it as <b>untrusted for secrecy and integrity</b>. It may be honest-but-curious (reads all stored data) or malicious (alters stored data, forges messages), but we rely on it for liveness. Denial of service is out of scope. (3) A <b>network attacker</b>, neutralised by TLS (HTTPS/WSS with HSTS). All adversaries are computationally bounded (no DLog on ristretto255, no SHA-256 collisions, Ed25519 is EUF-CMA).</p>
<p><b>Trust boundaries.</b> The only trusted component is the player's own browser, which holds their Ed25519 secret key and the opening (m, r) of the current round. Everything that crosses the browser↔server boundary is either hiding (C, π), authenticated (signatures), or revealed on purpose. The database and audit log are untrusted storage whose integrity is <i>verified</i> rather than <i>assumed</i>.</p>
<table><tr><th>Goal</th><th>Guarantee</th><th>Holds against</th></tr>
<tr><td>Hiding of move before reveal</td><td>Perfect</td><td>Opponent, curious/malicious server, eavesdropper, even unbounded</td></tr>
<tr><td>Binding of move</td><td>Computational (DLog)</td><td>Malicious player, malicious server</td></tr>
<tr><td>Non-malleability</td><td>Computational (ROM)</td><td>Malicious player</td></tr>
<tr><td>Authenticity of commits/reveals</td><td>EUF-CMA of Ed25519</td><td>Malicious server, other players</td></tr>
<tr><td>Fairness against abort</td><td>Deadline + forfeit rule</td><td>Malicious player (enforced by the referee; liveness assumption)</td></tr>
<tr><td>Auditability</td><td>Hash chain + signatures + PoK</td><td>Malicious storage/server (detects changes, cannot prevent deletion)</td></tr></table>
<p>The full attack-surface map (14 entry points) is in <span class="m">docs/THREAT_MODEL.md</span> and summarised in §9.1.</p>

<h2>4. System architecture</h2>
{fig(DIA + '/architecture.png', 'Component architecture and trust boundaries. Only commitments, proofs and signatures cross into the untrusted zone before reveal.')}
<p>The code is organised so that the <b>same cryptographic module runs on both sides</b>:</p>
<table><tr><th>Component</th><th>Files</th><th>Responsibility</th></tr>
<tr><td>Crypto core</td><td>shared/crypto.js</td><td>Pedersen commit/open, NUMS H, Okamoto PoK, hash commitments, canonical encodings, Ed25519 message formats, <span class="m">checkCommit/checkReveal</span></td></tr>
<tr><td>Adversary module</td><td>shared/attacks.js</td><td>Eight attack simulations, each run in a vulnerable and a hardened configuration</td></tr>
<tr><td>Client UI</td><td>client/*.js</td><td>Lobby, match screen, guided tour, Inspector, Attack Lab, Benchmarks, Account (key lifecycle)</td></tr>
<tr><td>API layer</td><td>server/index.js</td><td>Express REST + WebSocket push, CSP and security headers, per-IP token-bucket rate limiting, payload limits</td></tr>
<tr><td>Referee</td><td>server/game.js</td><td>Identity &amp; sessions, key rotation/revocation, tournament brackets, commit→reveal state machine, deadlines, bots, audit log</td></tr>
<tr><td>Storage</td><td>server/db.js</td><td>SQLite (built-in <span class="m">node:sqlite</span>): players, key history, hashed sessions, single-use challenges, matches, moves, audit log</td></tr></table>
<p><b>Why a referee at all, if it is untrusted?</b> Peer-to-peer browsers cannot reach each other reliably (NAT) and someone has to enforce deadlines. We keep the referee for liveness and coordination only. Every security-relevant decision can be re-checked by any participant from signed data.</p>

<h2>5. Protocol workflows</h2>
{fig(DIA + '/sequence.png', 'Sequence diagram of one game round: setup, commit phase (amber) and reveal phase (teal).', '92%')}
<p><b>Registration.</b> The browser generates an Ed25519 key pair, fetches a single-use nonce, and signs <span class="m">CommitRPS/v1|register|name=…|pk=…|nonce=…</span> (proof of possession). The server stores only the public key and returns a 256-bit bearer token. Only <span class="m">SHA-256(token)</span> is stored.</p>
<p><b>Commit.</b> The client picks m and computes <span class="m">r</span> from 64 CSPRNG bytes reduced mod ℓ, then <span class="m">C</span>, <span class="m">π</span>, and <span class="m">σ = Sign(sk, "commit"|ctx|scheme|C|T)</span>. It saves (m, r) in localStorage <i>before</i> sending, so a crash cannot strand a commitment. The referee rebuilds ctx from its own view of the match, verifies σ and π, rejects exact duplicates, stores the row and appends an audit entry. When both commitments exist, the match switches to <span class="m">reveal</span> and the deadline starts.</p>
<p><b>Reveal.</b> Before revealing, each browser <b>independently verifies the opponent's signature and proof</b>. It then sends <span class="m">(m, r, Sign(sk, "reveal"|ctx|C|m|r))</span>. The referee checks <span class="m">m·G + r·H = C</span>. A signed but wrong opening is non-repudiable evidence of cheating, so the sender forfeits. When both openings are valid the round is judged; a tie starts a new round with fresh commitments. Afterwards each browser re-verifies the opponent's opening too.</p>
{fig(DIA + '/dataflow.png', 'Data-flow diagram: how a plaintext move becomes a commitment, crosses the network, and becomes plaintext again only at reveal.', '100%')}
{fig(DIA + '/statemachine.png', 'Match state machine enforced by the referee, including deadline and forfeit transitions.', '78%')}

<h2>6. Cryptographic library choices</h2>
<p>The brief requires peer-reviewed libraries instead of home-made primitives. We compose primitives into a protocol; we never implement field or curve arithmetic, hashing or signatures ourselves.</p>
<table><tr><th>Need</th><th>Library / standard</th><th>Why</th></tr>
<tr><td>Prime-order group, point encoding</td><td>@noble/curves 2.x: ristretto255 (RFC 9496)</td><td>Audited (Cure53, Trail of Bits, Kudelski), zero dependencies, identical in browser and Node, constant-time scalar multiplication for secret scalars</td></tr>
<tr><td>Generator H</td><td>@noble/curves <span class="m">ristretto255_hasher.hashToCurve</span> (RFC 9380)</td><td>Standardised, verifiable NUMS derivation</td></tr>
<tr><td>Signatures</td><td>@noble/curves Ed25519 (RFC 8032)</td><td>Deterministic nonces (no RNG failure at signing), 64-byte signatures, fast verification</td></tr>
<tr><td>Hashing / Fiat–Shamir</td><td>@noble/hashes SHA-256, SHA-512</td><td>Audited, standard</td></tr>
<tr><td>Randomness</td><td>Web Crypto <span class="m">crypto.getRandomValues</span> / Node <span class="m">crypto.randomBytes</span></td><td>OS CSPRNG; never <span class="m">Math.random</span></td></tr>
<tr><td>Server-side token checks</td><td>Node <span class="m">crypto.timingSafeEqual</span>, <span class="m">createHash</span></td><td>Constant-time comparisons (OpenSSL-backed)</td></tr></table>
<p><b>Alternatives considered.</b> OpenSSL/PyCryptodome do not expose ristretto255 point arithmetic. libsodium has it, but its WebAssembly build is larger and would mean separate client and server code paths. Web Crypto has Ed25519 but no generic group operations. Running one audited JavaScript library on both ends removed a whole class of cross-implementation encoding bugs.</p>

<h2>7. Key lifecycle management</h2>
<table><tr><th>Stage</th><th>Long-term identity key (Ed25519)</th><th>Per-round secret (m, r) / salt</th><th>Session token</th></tr>
<tr><td>Generation</td><td>In the browser, from the CSPRNG</td><td>In the browser, per round: 64 random bytes mod ℓ (bias &lt; 2<sup>-250</sup>)</td><td>Server, 32 random bytes</td></tr>
<tr><td>Distribution</td><td>Only the public key is sent; proof of possession by signing a single-use 2-minute nonce</td><td>Never distributed until reveal</td><td>Returned once over TLS</td></tr>
<tr><td>Storage</td><td>Browser localStorage behind a strict CSP; optional JSON backup file</td><td>localStorage, keyed by match and round</td><td>Server stores SHA-256 only; 12 h expiry</td></tr>
<tr><td>Rotation</td><td>Old key signs hand-over to new key; new key co-signs; old sessions killed; history kept</td><td>Fresh every round (ties included)</td><td>New token at every login/rotation</td></tr>
<tr><td>Revocation</td><td>Signed revoke request → key status <i>revoked</i>, all sessions deleted, logins refused</td><td>Published at reveal (end of life)</td><td>Logout, expiry, or key revocation</td></tr></table>
<p>The server keeps <b>every public key ever used</b> with its status, and every move row records the key that signed it. Commitments made before a rotation therefore stay verifiable afterwards.</p>

<h2>8. Implementation details &amp; hurdles</h2>
<ul>
<li><b>Topic wording vs. algorithm.</b> The brief names Pedersen commitments but describes a salted hash in the scenario. We implemented both: Pedersen as the default and the hash scheme as a per-tournament option. That turned the mismatch into the comparison in §2.5.</li>
<li><b>Discovering malleability.</b> Our first prototype was textbook Pedersen. Writing the Attack Lab showed that <span class="m">C + G</span> lets an opponent beat any rock or paper without learning anything (A2). We added the context-bound Okamoto proof and a duplicate-commitment check.</li>
<li><b>Zero scalars.</b> noble rejects multiplication by 0. A weak-RNG experiment that drew r = 0 crashed, so the Pedersen helper now maps 0·P to the identity explicitly.</li>
<li><b>Canonical encodings.</b> Scalars ≥ ℓ are rejected on decode, and points go through canonical ristretto decoding. Otherwise <span class="m">s</span> and <span class="m">s + ℓ</span> would be two valid encodings of one proof (signature/proof malleability).</li>
<li><b>Audit chain and rollbacks.</b> The first version cached the chain head in memory. A rolled-back transaction (a rejected commit) then broke the chain. The head is now read inside the same transaction, and "rejected" events are logged after rollback.</li>
<li><b>Never losing an opening.</b> (m, r) is written to localStorage <i>before</i> the commit request goes out, so a refresh or crash cannot leave a player unable to reveal (and forfeit).</li>
<li><b>Stale UI repaint.</b> A delayed auto-reveal could repaint the tournament screen after the user had navigated away. Each page now has a liveness guard.</li>
<li><b>Timing measurements in the browser.</b> Browsers coarsen <span class="m">performance.now()</span> to defeat Spectre, so the timing attack runs on the server with <span class="m">process.hrtime</span> and is exposed through <span class="m">/api/lab/timing</span>.</li>
<li><b>Restart safety for bots.</b> Bot secrets live only in memory. After a restart, matches with orphaned bots are closed in favour of the human player instead of hanging forever.</li>
</ul>

<h2>9. Security evaluation</h2>
<h3>9.1 Attack surface map</h3>
<table><tr><th>Entry point</th><th>Risk</th><th>Mitigation</th><th>Evidence</th></tr>
<tr><td>Commitment value</td><td>Brute-force small move space</td><td>Perfect hiding; 256-bit salt</td><td>A1</td></tr>
<tr><td>Blinding-factor RNG</td><td>Low entropy reveals move</td><td>CSPRNG, 512-bit sample mod ℓ</td><td>A5</td></tr>
<tr><td>Generator setup</td><td>Trapdoor → equivocation</td><td>RFC 9380 NUMS H, re-derived by clients</td><td>A4</td></tr>
<tr><td>POST /commit</td><td>Mauling, copying, replay</td><td>Context-bound PoK, signatures, duplicate check</td><td>A2, A3, API test</td></tr>
<tr><td>POST /reveal</td><td>Equivocation, lying reveal</td><td>Opening check → forfeit</td><td>API test</td></tr>
<tr><td>Reveal phase</td><td>Selective abort</td><td>Deadline → forfeit</td><td>A7</td></tr>
<tr><td>Database / referee</td><td>Tampering, forged moves</td><td>Signatures, hash chain, client re-verification</td><td>A8, Inspector</td></tr>
<tr><td>Sessions</td><td>DB theft, timing leaks</td><td>Hashed tokens, timingSafeEqual, expiry</td><td>A6</td></tr>
<tr><td>Login / register</td><td>Replay</td><td>Single-use nonces</td><td>API test</td></tr>
<tr><td>Browser</td><td>XSS stealing keys</td><td>CSP <span class="m">script-src 'self'</span>, escaping, no 3rd-party JS</td><td>Header test</td></tr>
<tr><td>API</td><td>Flooding</td><td>Token-bucket rate limits, 16 kB bodies</td><td>—</td></tr></table>

<h3>9.2 Simulated attacks and countermeasures</h3>
<p>All attacks live in <span class="m">shared/attacks.js</span>, run live in the Attack Lab, and are reproduced by <span class="m">npm run attacks</span>. The numbers below come from that script.</p>
<table><tr><th>#</th><th>Attack</th><th>Against weakened config</th><th>Against shipped config</th></tr>
<tr><td>A1</td><td>Brute-force hash commitment</td><td class="bad">Unsalted: recovered in {a1['log'][0]['guesses']} guess ({a1['log'][0]['ms']} ms). 16-bit salt: {a1['log'][1]['guesses']:,} guesses, {a1['log'][1]['ms']} ms</td><td class="ok">256-bit salt: {e(a1['log'][2]['note'])}</td></tr>
<tr><td>A2</td><td>Malleability C′ = C + G</td><td class="bad">Attacker wins {a2['vulnerable']['winRate']}% ({a2['vulnerable']['win']}/{a2['rounds']}) vs 33.3% fair</td><td class="ok">{a2['mitigated']['rejected']}/{a2['rounds']} rejected at commit</td></tr>
<tr><td>A3</td><td>Copy / replay commitment</td><td class="bad">Copied opening accepted → forced draws</td><td class="ok">Rejected by context binding and signature</td></tr>
<tr><td>A4</td><td>Trapdoor H = t·G</td><td class="bad">"rock" opened as "scissors"</td><td class="ok">Same algebra fails without log_G(H)</td></tr>
<tr><td>A5</td><td>16-bit weak RNG for r</td><td class="bad">Move recovered after {a5['vulnerable']['tries']:,} group ops ({a5['vulnerable']['ms']} ms)</td><td class="ok">Perfect hiding: every move remains consistent with C</td></tr>
<tr><td>A6</td><td>Timing leak in comparison</td><td class="bad">Early-exit compare: full-match ÷ no-match time = {a6['naiveSpread']}×</td><td class="ok">Constant-time: ratio {a6['ctSpread']}× (flat, noise only)</td></tr>
<tr><td>A7</td><td>Selective abort</td><td class="bad">Cheater loses 0/{a7['rounds']}; {a7['vulnerable']['stalled']} matches stall</td><td class="ok">Aborts become {a7['mitigated']['loss']} losses; 0 stalls</td></tr>
<tr><td>A8</td><td>Referee swaps a commitment / forges reveal</td><td class="bad">Undetectable without signatures</td><td class="ok">Both rejected by signature check</td></tr></table>
{fig(FIG + '/mall_abort.png', 'Outcome distributions for the copy-cat malleability attack (A2) and selective abort (A7), without and with the countermeasure.', '92%')}
{fig(FIG + '/sweep.png', 'Attacker time to recover a move as a function of salt / blinding-factor entropy. Cost doubles per bit; the shipped 256/252-bit values put recovery beyond physical limits.', '78%')}
{fig(FIG + '/timing.png', 'Timing side-channel (A6): an early-exit comparison leaks the length of the matching prefix; the constant-time comparison does not.', '78%')}
<p><b>Why A2 succeeds 2/3 of the time.</b> The attacker opens C′ to m+1. If the victim played rock (1) or paper (2), m+1 is the winning reply. If the victim played scissors (3), m+1 = 4 is invalid and the attacker forfeits. The expected win rate is 2/3, which matches the measured {a2['vulnerable']['winRate']}%.</p>
<p><b>Why A7 is a protocol problem, not a crypto problem.</b> A commitment cannot force its owner to open it. The fix is an incentive: not revealing before the deadline counts as a loss. With that rule, aborting is never better than revealing.</p>

<h2>10. Security vs. usability trade-offs</h2>
<table><tr><th>Operation (Node {e(bench['node'])}, shared cloud VM)</th><th class=n>ops/s</th><th class=n>ms/op</th></tr>{bench_rows}</table>
{fig(FIG + '/bench.png', 'Per-operation cost of each primitive.', '82%')}
<ul>
<li><b>Latency.</b> A full Pedersen commit (commitment + PoK + signature) costs ≈ {ms('Full client commit (Pedersen+PoK+sig)')} ms in Node and about 1.5 ms in desktop Chrome. That is roughly {float(ms('Full client commit (Pedersen+PoK+sig)'))/float(ms('Full client commit (hash+sig)')):.0f}× the hash scheme ({ms('Full client commit (hash+sig)')} ms), but still one to two orders of magnitude below a network round trip (50–200 ms on the public internet). Users cannot notice the difference.</li>
<li><b>Bandwidth.</b> Pedersen commit requests are {bench['sizes']['pedersen']['commitMsg']} B against {bench['sizes']['hash']['commitMsg']} B for the hash scheme. The 96-byte proof is the price of non-malleability. That is irrelevant for a web game, but it would matter on-chain, where every byte costs gas.</li>
<li><b>Server load.</b> The referee verifies about {b['Full verifier check (Pedersen)']['opsPerSec']} Pedersen commits per second per core, far more than a classroom tournament needs. Rate limiting, not crypto, is the binding constraint.</li>
<li><b>Interaction.</b> Commit-reveal needs two messages per player per round instead of one, plus waiting for the slowest player. Auto-reveal (after local verification) hides most of this from users.</li>
<li><b>Reveal deadline.</b> Short deadlines punish aborts quickly but can forfeit honest players on bad connections. We default to 60 s and let the creator choose 30 s – 2 min.</li>
<li><b>Key storage.</b> Keys in localStorage mean instant, password-free onboarding. The cost is that a compromised browser leaks the key. We accept this for a game, mitigate it with CSP plus rotation and revocation, and note WebAuthn or non-extractable keys as future work.</li>
<li><b>Entropy parameters.</b> Figure 6 shows that attacker cost grows as 2<sup>bits</sup> while honest cost is constant, so there is no usability reason to use anything below full-size salts and blinding factors.</li>
</ul>

<h2>11. Testing &amp; verification</h2>
<table><tr><th>Suite</th><th>What it checks</th></tr>
<tr><td>Unit (test/crypto.test.js)</td><td>NUMS H; commit/open round-trip and binding for every move; fresh randomness; homomorphism; PoK completeness, context binding, rejection of mauled commitments; canonical scalar rejection; hash commitments; signed commit/reveal pipeline for both schemes; every attack's vulnerable/mitigated outcome</td></tr>
<tr><td>Integration (test/api.test.js)</td><td>Spawns the real server on an in-memory DB. Checks signed, single-use challenges; full matches against bots for both schemes while verifying the opponent's commitment client-side; mauled and copied commits rejected over HTTP; lying reveal leads to forfeit; key rotation kills old sessions; revocation</td></tr>
<tr><td>End-to-end (Playwright, Chrome)</td><td>Register → quick match → seal → auto-reveal → result; 4-player bracket to a champion; Inspector verifies chain and all proofs; tamper simulation detected; all 8 lab attacks; benchmarks; zero console errors</td></tr></table>
<p>All 14 automated tests pass (<span class="m">npm test</span>).</p>

<h2>12. User interface &amp; onboarding</h2>
<p>The interface makes the cryptography visible: a five-step phase bar (Choose → Seal → Wait → Reveal → Verify), the live formula for the chosen move, the actual commitment, proof and signature values (click to copy), and a checklist of what <i>your</i> browser verified about the opponent. First-time users get an automatic guided tour (seven steps in the lobby, six on the match screen), a "?" tooltip on every cryptographic term, and a one-click "Quick match vs bot".</p>
{fig(FIG + '/01-home.png', 'Lobby: in-browser key generation, tournament creation with scheme and deadline selection, open tournaments.', '86%')}
{fig(FIG + '/04-reveal.png', 'Match screen during the reveal phase: own sealed commitment with proof and signature, and the opponent’s commitment verified locally.', '86%')}
{fig(FIG + '/06-tournament.png', '4-player bracket after completion, with round history and per-move verification (tie replayed in round 2).', '86%')}
{fig(FIG + '/13-tour.png', 'Guided walkthrough highlighting the identity card.', '78%')}
{fig(FIG + '/08-tamper.png', 'Inspector: the hash chain and signatures detect a simulated tampered entry.', '86%')}

<h2>13. Deployment &amp; source control</h2>
<p>The app is a single Node.js 22 service (Express + ws), with the frontend bundled by esbuild during <span class="m">npm install</span>. Deployment files: <span class="m">render.yaml</span> (Render Blueprint, free plan, health check <span class="m">/api/health</span>) and a <span class="m">Dockerfile</span> (Railway, Fly.io, Koyeb). TLS is terminated by the platform; the app sends HSTS on secure requests, a strict Content-Security-Policy, <span class="m">X-Content-Type-Options</span>, <span class="m">Referrer-Policy</span>, <span class="m">frame-ancestors 'none'</span> and COOP. The repository has a conventional-commit history, a README with setup and deployment steps, <span class="m">docs/THREAT_MODEL.md</span>, <span class="m">docs/API.md</span>, diagram sources (Mermaid) and the scripts that regenerate every number in this report.</p>

<h2>14. Limitations &amp; future work</h2>
<ul>
<li><b>Constant-time JavaScript.</b> noble hardens scalar multiplication, but JS BigInt arithmetic (used for s₁ = a + c·m) is not guaranteed constant-time. Remote exploitation is impractical here (values are per-round and published at reveal), but a WebAssembly build of libsodium would close the gap.</li>
<li><b>Referee liveness.</b> A malicious referee can stall or censor. A blockchain or a BFT committee of referees could take over deadline enforcement.</li>
<li><b>Key storage.</b> Moving the identity key to WebAuthn/passkeys or non-extractable Web Crypto keys would protect it from XSS.</li>
<li><b>Bots</b> are run by the operator, who can see the bot's own move. They are a demo convenience, not a trusted party.</li>
<li><b>Persistence</b> on free tiers is ephemeral; a managed Postgres would be needed for a long-lived archive.</li>
<li><b>Post-quantum.</b> A lattice-based or hash-based commitment would keep binding against quantum adversaries.</li>
</ul>

<h2>15. Conclusion</h2>
<p>CommitRPS shows that a Pedersen commitment with random blinding factors is a good primitive for fair simultaneous moves: it hides perfectly, binds under the discrete-log assumption, and costs about a millisecond. Turning the textbook scheme into a secure system took more than the formula, though. It needed a verifiable generator, fresh high-entropy blinding, a context-bound proof of knowledge against malleability, signatures against a dishonest referee, deadlines against aborts, and an auditable log. The Attack Lab shows each of these countermeasures is necessary: removing any one of them re-enables a concrete, measurable attack.</p>

<h2>References</h2>
<ol style="font-size:9.4pt">
<li>T. P. Pedersen, "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing," CRYPTO '91, LNCS 576, 1992.</li>
<li>T. Okamoto, "Provably Secure and Practical Identification Schemes and Corresponding Signature Schemes," CRYPTO '92.</li>
<li>A. Fiat, A. Shamir, "How to Prove Yourself: Practical Solutions to Identification and Signature Problems," CRYPTO '86.</li>
<li>RFC 9496: The ristretto255 and decaf448 Groups, IETF, 2023.</li>
<li>RFC 9380: Hashing to Elliptic Curves, IETF, 2023.</li>
<li>RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA), IETF, 2017.</li>
<li>D. Boneh, V. Shoup, <i>A Graduate Course in Applied Cryptography</i>, ch. 8 &amp; 19 (commitments, Σ-protocols).</li>
<li>I. Damgård, "On Σ-protocols," lecture notes, Aarhus University.</li>
<li>P. Miller, noble-curves and noble-hashes, https://github.com/paulmillr/noble-curves (audit reports in repository).</li>
<li>M. Blum, "Coin Flipping by Telephone," CRYPTO '81 (commit-reveal for fair games).</li>
</ol>

<h2>Appendix A: REST API summary</h2>
<table><tr><th>Endpoint</th><th>Purpose</th></tr>
<tr><td>GET /api/challenge</td><td>Single-use nonce for proof of possession</td></tr>
<tr><td>POST /api/register, /api/login</td><td>Signed challenge → session token</td></tr>
<tr><td>POST /api/keys/rotate, /api/keys/revoke</td><td>Key lifecycle (signed)</td></tr>
<tr><td>GET/POST /api/tournaments, /:id/join, /:id/bots</td><td>Tournament management</td></tr>
<tr><td>POST /api/matches/:id/commit</td><td>{{commitment, proof{{T,s1,s2}}, signature}}</td></tr>
<tr><td>POST /api/matches/:id/reveal</td><td>{{move, opening, signature}}</td></tr>
<tr><td>GET /api/audit, /api/params</td><td>Transparency log and public parameters</td></tr>
<tr><td>WS /ws</td><td>Subscribe to tournament updates</td></tr></table>
<h2>Appendix B: Reproducing the results</h2>
<pre>npm install            # installs deps and builds the frontend
npm test               # 14 unit + integration tests
npm run attacks        # → docs/results/attacks.json
npm run bench          # → docs/results/bench.json
node scripts/sweep.mjs # → docs/results/sweep.json
python3 docs/report/build_report.py   # regenerates this PDF</pre>
</body></html>"""

out_html = ROOT / 'docs/report/report.html'
out_html.write_text(HTML)
with sync_playwright() as p:
    br = p.chromium.launch(executable_path='/usr/bin/google-chrome', args=['--no-sandbox'])
    pg = br.new_page()
    pg.goto(out_html.as_uri()); pg.wait_for_timeout(500)
    pg.pdf(path=str(ROOT / 'docs/CommitRPS_Technical_Report.pdf'), format='A4', print_background=True,
           display_header_footer=True, header_template='<div></div>',
           footer_template='<div style="font:8px Arial;color:#888;width:100%;text-align:center">CommitRPS · Technical Report · <span class="pageNumber"></span> / <span class="totalPages"></span></div>',
           margin={'top': '18mm', 'bottom': '18mm', 'left': '16mm', 'right': '16mm'})
    br.close()
print('PDF written')
