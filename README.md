# 🔒 CommitRPS: Pedersen-committed Rock · Paper · Scissors

> **CS-3002 Information Security, Term Project, Topic 13: Cryptographic Commitments**
> Algorithm: **Pedersen Commitment Scheme with random blinding factors**
> Scenario: a decentralized rock-paper-scissors tournament where players commit to their move in round one and reveal it in round two, so nobody can cheat.

**Live demo:** `https://<your-app>.onrender.com` (fill in after deploying, see below)

CommitRPS is a full-stack web app. Players generate an Ed25519 identity key **in the browser**, then join single-elimination tournaments (2/4/8 players, with optional honest bots). Every move is sealed as

```
C = m·G + r·H        (ristretto255, m ∈ {1,2,3}, r ← Z_ℓ uniformly at random)
```

together with a **zero-knowledge proof of knowledge of (m, r)** bound to the player and match, plus an **Ed25519 signature**. The referee only opens the reveal phase once both commitments are in. Every browser re-verifies the opponent's signature, proof and opening itself, and anyone can re-verify the whole tournament from a **hash-chained audit log**.

A second scheme, **salted SHA-256 hash commitments** (the "hash of move + salt" variant from the topic brief), can be selected per tournament for comparison.

## Features

| Area | What's there |
|---|---|
| Crypto core | Pedersen commitments on ristretto255, NUMS generator H via RFC 9380 hash-to-curve, Okamoto Σ-protocol PoK (Fiat–Shamir), salted & context-bound SHA-256 commitments, Ed25519 signatures. All primitives come from the audited [`@noble/curves`](https://github.com/paulmillr/noble-curves) / [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) libraries. |
| Game | Lobby, tournaments with CSPRNG-seeded brackets, tie replays, commit/reveal deadlines with forfeits, honest bots, live WebSocket updates |
| Key lifecycle | In-browser key generation, challenge–response registration (proof of possession), hashed bearer sessions, key backup/import, rotation (old and new key both sign), revocation, key history |
| UX | Guided tour, tooltips on every crypto term, 5-step phase bar, live formula, local verification checklist, responsive layout |
| Transparency | `/inspector` re-verifies the hash chain and every signature, proof and opening client-side, with a "simulate tampering" button |
| Attack Lab | 8 live attacks, each run against a vulnerable and a hardened configuration (see below) |
| Benchmarks | In-browser timing of every operation and bytes on the wire, plus a security-vs-usability discussion |

## Attack Lab

| ID | Attack | Vulnerable config | Shipped mitigation |
|---|---|---|---|
| A1 | Brute-force hash commitment | unsalted / 16-bit salt → recovered instantly | 256-bit CSPRNG salt; Pedersen is perfectly hiding |
| A2 | Malleability `C' = C + G` | attacker wins ≈ 66 % instead of 33 % | context-bound PoK, 100 % of mauled commits rejected |
| A3 | Copy / replay commitment | forced draws, replays | context binding + signatures |
| A4 | Trapdoor generator `H = tG` | open "rock" as "scissors" | H from hash-to-curve (nothing up our sleeve) |
| A5 | Weak RNG for *r* | move recovered before reveal | 512-bit CSPRNG sample mod ℓ |
| A6 | Timing side-channel | early-exit compare leaks prefix (≈ 50–120× spread) | hashed tokens + constant-time compare |
| A7 | Selective abort | cheater never loses | reveal deadline → forfeit |
| A8 | Malicious referee tampering | — | player signatures + browser re-verification |

Run them from the CLI with `npm run attacks` (results go to `docs/results/attacks.json`).

## Architecture

```
client/        browser app (vanilla ES modules, bundled by esbuild → public/)
shared/        crypto.js (protocol) + attacks.js (adversary simulations), used by BOTH client and server
server/        index.js (Express REST, WebSocket, CSP, rate limits) · game.js (referee) · db.js (SQLite)
test/          unit tests (crypto, attacks) + API integration tests (full tournaments, attacks, key lifecycle)
scripts/       run-attacks, bench, sweep (numbers used in the report)
docs/          threat model, API reference, diagrams, technical report (PDF), slides (PPTX)
```

See `docs/diagrams/` for the sequence diagram, architecture and trust boundaries, data-flow diagram and match state machine, and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the adversary model.

## Run locally

Requires **Node.js ≥ 22.5** (uses the built-in `node:sqlite`).

```bash
npm install        # also builds the frontend into public/
npm start          # http://localhost:3000
npm test           # 14 unit + integration tests
npm run attacks    # run all 8 attacks
npm run bench      # micro-benchmarks
```

Environment variables: `PORT` (3000), `DB_PATH` (`./data/commitrps.db`), `COMMIT_TIMEOUT_SEC` (300).

## Deploy (free)

**Render:** push this repo to GitHub → Render dashboard → *New* → *Blueprint* → select the repo. `render.yaml` does the rest. Health check: `/api/health`.
**Railway / Fly / Koyeb:** deploy with the included `Dockerfile`.

> Free-tier disks are ephemeral, so the SQLite database resets on redeploy. That is fine for demos. Mount a volume at `/app/data` to keep it.

## Security notes
- The server never sees a move before its owner reveals it, and cannot change one without breaking a signature.
- Keys live in the browser's `localStorage`, protected by a strict CSP (`script-src 'self'`). Use **Account → Download key backup** to move between devices.
- JavaScript BigInt arithmetic is not guaranteed constant-time. noble's point multiplication is hardened, but this remains a documented limitation (see report §8).

## Team
| Name | Roll no. | Role |
|---|---|---|
| Urba Kaleem | 24i-2108 | Crypto core & attacks Backend, API, deployment |
| Hafsa Naeem| 24i-2001 | Frontend, UX, documentation |

## License
MIT
