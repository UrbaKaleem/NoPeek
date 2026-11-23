# CommitRPS — Threat Model & Attack Surface

## 1. Assets

| Asset | Why it matters |
|---|---|
| A player's move *m* before the reveal phase | If it leaks, the opponent picks the winning reply (**hiding**). |
| The binding between a commitment and its move | If a player can change their move after seeing the opponent's, the game is rigged (**binding**). |
| Player signing keys (Ed25519 secret key) | Anyone holding the key can play and reveal as that player. |
| Session tokens | Let the holder call authenticated API endpoints as the player. |
| Match results and the bracket | Must reflect the moves that were actually committed. |
| Integrity of the audit log | Makes the whole tournament publicly verifiable after the fact. |

## 2. Actors & trust assumptions

| Actor | Assumption |
|---|---|
| **Honest player** | Runs the unmodified client; keeps the device and `localStorage` uncompromised. |
| **Malicious player** | Fully **active/malicious** adversary. Can run a modified client, send arbitrary API requests, copy or transform other players' published values, and choose when (or whether) to reveal. Computationally bounded (cannot solve discrete log on ristretto255 or find SHA-256 collisions). |
| **Referee server** | **Untrusted for integrity and secrecy, trusted for liveness.** We assume it may be *honest-but-curious* (reads everything it stores) and we also limit what a *malicious* referee can achieve: it cannot learn a move before reveal, and it cannot forge, alter or invent moves without detection, because commitments and openings are signed by the player and re-verified in every browser and in the Inspector. It **can** delay, drop messages or refuse service (denial of service is out of scope). |
| **Network attacker** | Can observe and tamper with traffic unless TLS is used. Production deployments run behind HTTPS/WSS (Render/Railway terminate TLS; HSTS is sent on secure requests). |
| **Bots** | Demo opponents operated by the server with their own Ed25519 keys. They follow the protocol honestly and their commitments are verified like anyone else's. Their secrets live in server memory, so the operator *could* make a bot cheat by peeking at a bot's own move, but never at a human's move. |

### Trust boundaries
1. **Browser ↔ server** (HTTPS/WSS). Only `C`, the proof, signatures and (after reveal) `(m, r)` cross this boundary.
2. **Server process ↔ SQLite / audit log.** Storage is untrusted for integrity: the hash chain plus player signatures detect tampering.
3. **Player ↔ player.** Players never talk to each other directly; everything goes through the referee and is checked end to end.

## 3. Security goals

| Goal | Mechanism | Strength |
|---|---|---|
| G1 Hiding: nobody learns *m* before reveal | Pedersen `C = mG + rH` with uniform *r* ∈ Z_ℓ | **Perfect** (information-theoretic) |
| G2 Binding: a commitment opens to only one move | Hardness of DLog in ristretto255; NUMS generator H | Computational (~2^126) |
| G3 Non-malleability: nobody can derive a related commitment | Okamoto PoK of (m, r), Fiat–Shamir challenge bound to context | Computational (ROM) |
| G4 Authenticity / non-repudiation | Ed25519 signatures on every commit and reveal | Computational (~2^128) |
| G5 Fairness against aborts | Reveal deadline → non-revealer forfeits | Protocol rule |
| G6 Replay resistance | Context `(tournament, match, round, player)` in proof, signature and hash; one-time challenges; duplicate-commitment check | — |
| G7 Public verifiability | Hash-chained audit log, client-side re-verification | — |

## 4. Attack surface map

| # | Entry point / data | Potential vulnerability | Mitigation in CommitRPS | Demo |
|---|---|---|---|---|
| S1 | Commitment value on the wire / in DB | Brute-forcing a small move space | Pedersen perfectly hiding; hash mode uses 256-bit CSPRNG salt | A1 |
| S2 | Blinding factor generation | Weak RNG (`Math.random`, timestamps) | 64 bytes from `crypto.getRandomValues` reduced mod ℓ (bias < 2^-250) | A5 |
| S3 | Generator setup | Trapdoor `H = tG` allows equivocation | H from RFC 9380 hash-to-curve of a public string, re-derived in every browser (Inspector) | A4 |
| S4 | `POST /commit` | Copy-cat / homomorphic mauling `C' = C + G` | Context-bound PoK; duplicate-commitment rejection | A2, A3 |
| S5 | `POST /reveal` | Opening to a different move | Opening check; signed wrong opening = forfeit | API test |
| S6 | Reveal phase | Selective abort (refuse to open when losing) | Reveal deadline → forfeit | A7 |
| S7 | Stored commitments / results | Malicious referee or DB tampering | Ed25519 signatures + hash chain + client re-verification | A8, Inspector tamper demo |
| S8 | Session tokens | Theft from DB; timing leaks during comparison | Only SHA-256(token) stored; lookup by hash + `timingSafeEqual`; 12 h expiry | A6 |
| S9 | Registration / login | Replay of a signed login | Single-use, 2-minute server nonces | API test |
| S10 | Key compromise | Stolen device / leaked backup | Rotation (old+new key sign) and revocation; key history kept for old signatures | API test |
| S11 | Web frontend | XSS stealing `localStorage` key | Strict CSP (`script-src 'self'`), all output HTML-escaped, no third-party scripts | — |
| S12 | API | Flooding, oversized payloads | Per-IP token-bucket rate limits, 16 kB JSON limit, 4 kB WS frames | — |
| S13 | Encodings | Non-canonical scalars/points (malleable encodings) | Ristretto canonical decoding; scalars ≥ ℓ rejected | unit test |
| S14 | Side channels in crypto code | Non-constant-time scalar multiplication | noble's `multiply` is constant-time for secret scalars; `multiplyUnsafe` only for public values. JS BigInt is not strictly constant-time (documented limitation) | — |

## 5. Out of scope / residual risks
- Denial of service by the referee or the hosting provider.
- Compromise of the player's own device or browser.
- Quantum adversaries: Shor's algorithm breaks DLog. Pedersen **binding** would fail, but **hiding** stays perfect. The hash mode would survive (Grover only halves the security level).
- Collusion between a player and the referee operator to give bots an edge (bots are a demo convenience only).
- Free-tier hosting resets the SQLite file on redeploy. Fine for a demo, not for a real tournament archive.
