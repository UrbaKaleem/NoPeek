# CommitRPS API

Base URL: the deployed origin. All bodies are JSON. Authenticated endpoints need `Authorization: Bearer <token>`.

## Identity & keys
| Method | Path | Body | Notes |
|---|---|---|---|
| GET | `/api/challenge` | — | → `{nonce}`. Single-use, valid for 2 min. |
| POST | `/api/register` | `{name, publicKey, nonce, signature}` | `signature = Ed25519(sk, "CommitRPS/v1\|register\|name=…\|pk=…\|nonce=…")` → `{playerId, name, token}` |
| POST | `/api/login` | `{publicKey, nonce, signature}` | Same signed message as register. |
| GET | `/api/me` | — 🔒 | Profile and key history. |
| POST | `/api/keys/rotate` | `{newKey, nonce, oldSig, newSig}` 🔒 | Both keys sign `…\|rotate\|p=…\|old=…\|new=…\|nonce=…`. |
| POST | `/api/keys/revoke` | `{nonce, signature}` 🔒 | Kills the key and all its sessions. |
| POST | `/api/logout` | — 🔒 | |

## Tournaments & matches
| Method | Path | Body |
|---|---|---|
| GET | `/api/tournaments` | — |
| POST | `/api/tournaments` 🔒 | `{name, size: 2\|4\|8, scheme: "pedersen"\|"hash", revealTimeout}` |
| GET | `/api/tournaments/:id` | — (bracket, players, every move) |
| POST | `/api/tournaments/:id/join` 🔒 | — |
| POST | `/api/tournaments/:id/bots` 🔒 | `{count}` |
| GET | `/api/matches/:id` | — |
| POST | `/api/matches/:id/commit` 🔒 | `{commitment, proof:{T,s1,s2}\|null, signature}` |
| POST | `/api/matches/:id/reveal` 🔒 | `{move, opening, signature}` |

Context string used in proofs, hashes and signatures:
`CommitRPS/v1|t=<tournamentId>|m=<matchId>|r=<gameRound>|p=<playerId>`

## Transparency & lab
| Method | Path | Notes |
|---|---|---|
| GET | `/api/params` | Public group parameters G, H, and the seed H was derived from. |
| GET | `/api/audit?tournament=<id>` | Hash-chained log; `hash = SHA-256(prev_hash ‖ JSON{ts,type,tournamentId,payload})`. |
| GET | `/api/lab/timing` | Runs the timing side-channel experiment on the server. |
| GET | `/api/health` | Liveness probe. |

## WebSocket `/ws`
Send `{"type":"subscribe","tournamentId":"<id>"}` (or `"*"`). You receive `{"type":"tournament.updated","tournamentId":…}`; then re-fetch over REST.
