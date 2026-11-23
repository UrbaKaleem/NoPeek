/**
 * Adversary simulation module. Each attack runs twice: against a deliberately
 * weakened configuration ("vulnerable") and against the configuration CommitRPS
 * actually ships ("mitigated"). Runs in the browser (Attack Lab) and in Node
 * (tests + report numbers). Nothing here is used by the live game.
 */
import {
  G, H, L, mod, pedersen, pointFromHex, scalarToHex, hexToScalar, randomScalar,
  moveToScalar, scalarToMove, MOVE_NAMES, judge, verifyOpening, proveOpening, verifyProof,
  hashCommit, newSalt, verifyHashCommit, context, generateIdentity, sign, verifySig, messages,
  bytesToHex, utf8ToBytes,
} from './crypto.js';
import { sha256 } from '@noble/hashes/sha2.js';

const now = () => (globalThis.performance ? performance.now() : Date.now());
const MOVES = ['rock', 'paper', 'scissors'];
const pick = () => MOVES[Number(randomScalar() % 3n)];
const ctxFor = (playerId, round = 1) => context({ tournamentId: 'lab', matchId: 'm1', round, playerId });

// ---------------------------------------------------------------------------
// A1. Brute-forcing a weak hash commitment (no salt / short salt)
// ---------------------------------------------------------------------------
export function attackHashBruteforce({ saltBits = 16 } = {}) {
  const log = [];
  const secret = pick();

  // (a) unsalted: C = SHA256(move)
  const unsalted = bytesToHex(sha256(utf8ToBytes(secret)));
  let t0 = now(); let guesses = 0; let found = null;
  for (const g of MOVES) { guesses++; if (bytesToHex(sha256(utf8ToBytes(g))) === unsalted) { found = g; break; } }
  log.push({ label: 'Unsalted SHA-256(move)', guesses, ms: +(now() - t0).toFixed(3), recovered: found, correct: found === secret });

  // (b) short salt of `saltBits` bits
  const saltSpace = 2 ** saltBits;
  const saltInt = Number(randomScalar() % BigInt(saltSpace));
  const saltHex = saltInt.toString(16).padStart(Math.ceil(saltBits / 4) + (Math.ceil(saltBits / 4) % 2), '0');
  const C = hashCommit(secret, saltHex, '');
  t0 = now(); guesses = 0; found = null;
  outer: for (let s = 0; s < saltSpace; s++) {
    const sh = s.toString(16).padStart(saltHex.length, '0');
    for (const g of MOVES) {
      guesses++;
      if (hashCommit(g, sh, '') === C) { found = g; break outer; }
    }
  }
  const msShort = now() - t0;
  log.push({ label: `${saltBits}-bit salt`, guesses, ms: +msShort.toFixed(1), recovered: found, correct: found === secret });

  // (c) 256-bit CSPRNG salt (what we ship): extrapolate cost
  const perGuessMs = msShort / Math.max(guesses, 1);
  const years = (perGuessMs * 3 * 2 ** 255) / 1000 / 3600 / 24 / 365; // expected guesses
  log.push({ label: '256-bit CSPRNG salt (shipped)', guesses: '≈ 3·2^255 expected', ms: null, recovered: null, correct: false, note: `≈ ${years.toExponential(2)} years at this speed` });

  return { id: 'A1', title: 'Brute-force a weak hash commitment', secret, log,
    verdict: 'Move space is only 3 values, so without a large random salt the commitment hides nothing. A 256-bit salt makes guessing infeasible.' };
}

// ---------------------------------------------------------------------------
// A2. Pedersen malleability ("copycat + G") — the opponent never learns your move,
//     but can still beat it by deriving his commitment from yours.
// ---------------------------------------------------------------------------
export function attackMalleability({ rounds = 300 } = {}) {
  const run = (requireProof) => {
    let win = 0, loss = 0, tie = 0, rejected = 0;
    for (let i = 0; i < rounds; i++) {
      const victimMove = pick();
      const m = moveToScalar(victimMove);
      const r = randomScalar();
      const C = pedersen(m, r);
      const victimProof = proveOpening({ m, r, C }, ctxFor('victim', i));
      // Attacker: C' = C + G  (commitment to m+1 with the same, unknown, r)
      const Cp = C.add(G).toHex();
      if (requireProof) {
        // Best he can do: replay the victim's proof under his own context.
        const okReplay = verifyProof(Cp, victimProof, ctxFor('attacker', i));
        // Or forge one with random values.
        const forged = { T: pedersen(randomScalar(), randomScalar()).toHex(), s1: scalarToHex(randomScalar()), s2: scalarToHex(randomScalar()) };
        const okForge = verifyProof(Cp, forged, ctxFor('attacker', i));
        if (!okReplay && !okForge) { rejected++; continue; }
      }
      // Victim reveals (m, r). Attacker now opens C' with (m+1, r).
      const attackerMove = scalarToMove(m + 1n); // null if m = 3 → invalid opening
      if (!attackerMove) { loss++; continue; }
      if (!verifyOpening(Cp, attackerMove, scalarToHex(r))) { loss++; continue; }
      const j = judge(attackerMove, victimMove);
      if (j > 0) win++; else if (j < 0) loss++; else tie++;
    }
    return { win, loss, tie, rejected, winRate: +(100 * win / rounds).toFixed(1) };
  };
  const vulnerable = run(false);
  const mitigated = run(true);
  return { id: 'A2', title: 'Malleability: copycat C′ = C + G', rounds, vulnerable, mitigated,
    verdict: `Without a proof of knowledge the attacker wins ${vulnerable.winRate}% of rounds (fair play: 33.3%). With the context-bound Okamoto proof, ${mitigated.rejected}/${rounds} mauled commitments were rejected at commit time.` };
}

// ---------------------------------------------------------------------------
// A3. Commitment copy / replay (hash scheme, no context binding)
// ---------------------------------------------------------------------------
export function attackReplay() {
  const victimMove = pick();
  const salt = newSalt();
  // Vulnerable: ctx = '' (commitment not bound to player / match)
  const Cv = hashCommit(victimMove, salt, '');
  const copiedAccepted = verifyHashCommit(Cv, victimMove, salt, ''); // attacker re-uses victim's reveal
  // Mitigated: commitment bound to (tournament, match, round, playerId)
  const Cbound = hashCommit(victimMove, salt, ctxFor('victim'));
  const copiedBound = verifyHashCommit(Cbound, victimMove, salt, ctxFor('attacker'));
  // Also: signature binds the commitment to the victim's key
  const victim = generateIdentity(); const attacker = generateIdentity();
  const msg = messages.commit({ ctx: ctxFor('victim'), scheme: 'hash', commitment: Cbound });
  const sig = sign(msg, victim.secretKey);
  const sigUnderAttacker = verifySig(messages.commit({ ctx: ctxFor('attacker'), scheme: 'hash', commitment: Cbound }), sig, attacker.publicKey);
  return { id: 'A3', title: 'Copy / replay an opponent\'s commitment', victimMove,
    vulnerable: { accepted: copiedAccepted, effect: 'attacker mirrors the victim and forces a draw every round (or replays an old match)' },
    mitigated: { contextBoundAccepted: copiedBound, signatureAccepted: sigUnderAttacker },
    verdict: 'Binding the commitment to tournament/match/round/player and signing it with the player\'s Ed25519 key makes copied or replayed commitments fail verification.' };
}

// ---------------------------------------------------------------------------
// A4. Trapdoor setup: if someone knows t = log_G(H), they can equivocate.
// ---------------------------------------------------------------------------
export function attackTrapdoor() {
  const t = randomScalar();             // the trapdoor a dishonest setup would keep
  const badH = G.multiply(t);
  const m = 1n; const r = randomScalar();
  const C = pedersen(m, r, badH);       // committed to "rock"
  // Open as scissors (3): need r' with m + r t = m' + r' t  →  r' = r + (m - m')·t⁻¹
  const tInv = modInv(t);
  const target = 3n;
  const rp = mod(r + mod(m - target) * tInv);
  const equivocated = pedersen(target, rp, badH).equals(C);
  // Against the NUMS H the same algebra needs log_G(H), which nobody knows. Try the
  // same trick with a guessed t — it fails.
  const Cgood = pedersen(m, r);
  const guessT = randomScalar();
  const rGuess = mod(r + mod(m - target) * modInv(guessT));
  const goodEquivocated = verifyOpening(Cgood.toHex(), 'scissors', scalarToHex(rGuess));
  return { id: 'A4', title: 'Trapdoor generator H = t·G (equivocation)',
    vulnerable: { committed: 'rock', openedAs: 'scissors', accepted: equivocated },
    mitigated: { accepted: goodEquivocated, H: H.toHex() },
    verdict: 'Binding only holds if nobody knows log_G(H). CommitRPS derives H with RFC 9380 hash-to-curve from a public string, so the operator has no trapdoor.' };
}
function modInv(a) { // Fermat: a^(ℓ-2) mod ℓ
  let res = 1n, base = mod(a), e = L - 2n;
  while (e > 0n) { if (e & 1n) res = (res * base) % L; base = (base * base) % L; e >>= 1n; }
  return res;
}

// ---------------------------------------------------------------------------
// A5. Weak randomness for the blinding factor
// ---------------------------------------------------------------------------
export function attackWeakRng({ bits = 14 } = {}) {
  const secret = pick();
  const space = 2 ** bits;
  const r = BigInt(Math.floor(Math.random() * space)); // what a careless dev might write
  const C = pedersen(moveToScalar(secret), r);
  // Attacker precomputes r·H incrementally and tests each move.
  const t0 = now(); let tries = 0; let found = null;
  const mG = [1n, 2n, 3n].map((m) => G.multiply(m));
  let rH = null;
  for (let i = 0n; i < BigInt(space) && !found; i++) {
    rH = i === 0n ? null : (rH ? rH.add(H) : H);
    for (let k = 0; k < 3; k++) {
      tries++;
      const cand = rH ? mG[k].add(rH) : mG[k];
      if (cand.equals(C)) { found = MOVE_NAMES[k + 1]; break; }
    }
  }
  const ms = now() - t0;
  // Perfect hiding: with a uniform r, EVERY move is consistent with C.
  return { id: 'A5', title: `Weak RNG: blinding factor from ${bits}-bit Math.random()`, secret,
    vulnerable: { tries, ms: +ms.toFixed(1), recovered: found, correct: found === secret },
    mitigated: { note: 'r is uniform in Z_ℓ (64 CSPRNG bytes mod ℓ). Pedersen is then perfectly hiding: for every move m′ there exists an r′ with C = m′G + r′H, so even an unbounded attacker learns nothing.' },
    verdict: 'The commitment is only as hiding as its randomness. A low-entropy r lets the opponent read your move before you reveal it.' };
}

// ---------------------------------------------------------------------------
// A6. Timing side-channel on a secret comparison (session tokens)
// ---------------------------------------------------------------------------
export function naiveEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false; // early exit leaks prefix length
  return true;
}
export function ctEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
export function attackTiming({ iters = 7000, len = 2048, hr = null } = {}) {
  const clock = hr || now;
  const secret = Array.from({ length: len }, (_, i) => 'abcdef0123456789'[(i * 7 + 3) % 16]).join('');
  const prefixes = [0, len / 4, len / 2, (3 * len) / 4, len - 1].map(Math.floor);
  const flat = (str) => str.split('').join(''); // force flat (non-rope) strings so char access is uniform
  const guesses = prefixes.map((p) => flat(secret.slice(0, p) + 'z' + secret.slice(p + 1)));
  const measure = (fn) => prefixes.map((p, k) => {
    const g = guesses[k];
    for (let w = 0; w < 500; w++) fn(secret, g); // warm-up
    const samples = [];
    for (let rep = 0; rep < 7; rep++) {
      const t0 = clock();
      for (let i = 0; i < iters / 7; i++) fn(secret, g);
      samples.push(((clock() - t0) * 1e6) / (iters / 7)); // ns per compare
    }
    samples.sort((x, y) => x - y);
    return { matchingPrefix: p, nsPerCompare: +samples[3].toFixed(1) };
  });
  const naive = measure(naiveEqual);
  const ct = measure(ctEqual);
  const spread = (rows) => +(rows[rows.length - 1].nsPerCompare / Math.max(rows[0].nsPerCompare, 1e-9)).toFixed(2);
  return { id: 'A6', title: 'Timing leak in secret comparison', len, naive, ct,
    naiveSpread: spread(naive), ctSpread: spread(ct),
    verdict: 'An early-exit comparison takes longer the more leading characters match, so an attacker can recover a secret byte by byte. CommitRPS hashes session tokens and compares with crypto.timingSafeEqual / a branch-free loop.' };
}

// ---------------------------------------------------------------------------
// A7. Selective abort (refusing to reveal when you see you will lose)
// ---------------------------------------------------------------------------
export function attackAbort({ rounds = 300 } = {}) {
  // Second revealer sees the first reveal and aborts whenever he would lose.
  const sim = (deadline) => {
    let w = 0, l = 0, t = 0, stalled = 0;
    for (let i = 0; i < rounds; i++) {
      const a = pick(), b = pick();
      const j = judge(b, a); // from the cheater's (b) perspective
      if (j < 0) { if (deadline) l++; else stalled++; continue; } // abort → forfeit (or stall forever)
      if (j > 0) w++; else t++;
    }
    return { win: w, loss: l, tie: t, stalled };
  };
  return { id: 'A7', title: 'Selective abort after seeing the opponent\'s reveal', rounds,
    vulnerable: sim(false), mitigated: sim(true),
    verdict: 'Commitments cannot force someone to open them. Without a deadline, a cheater never loses — matches just stall. CommitRPS enforces a reveal deadline and awards the match to the player who did reveal.' };
}

// ---------------------------------------------------------------------------
// A8. Malicious referee tampering with a stored commitment / reveal
// ---------------------------------------------------------------------------
export function attackTamper() {
  const alice = generateIdentity();
  const ctx = ctxFor('alice');
  const m = moveToScalar('rock'); const r = randomScalar(); const C = pedersen(m, r);
  const proof = proveOpening({ m, r, C }, ctx);
  const sig = sign(messages.commit({ ctx, scheme: 'pedersen', commitment: C.toHex(), proofT: proof.T }), alice.secretKey);
  // Server swaps Alice's commitment for one to "scissors" so she loses.
  const C2 = pedersen(3n, randomScalar()).toHex();
  const sigOk = verifySig(messages.commit({ ctx, scheme: 'pedersen', commitment: C2, proofT: proof.T }), sig, alice.publicKey);
  // Server forges Alice's reveal as "scissors".
  const revealOk = verifySig(messages.reveal({ ctx, scheme: 'pedersen', commitment: C.toHex(), move: 'scissors', opening: scalarToHex(r) }), sig, alice.publicKey);
  return { id: 'A8', title: 'Malicious referee swaps a commitment',
    vulnerable: { note: 'Without signatures, players would have to trust the server\'s copy of every commitment.' },
    mitigated: { swappedCommitmentAccepted: sigOk, forgedRevealAccepted: revealOk },
    verdict: 'Every commit and reveal is signed by the player\'s Ed25519 key, and every browser re-verifies the opponent\'s signature, proof and opening. The referee can delay, but cannot change a move undetected.' };
}

export const ALL_ATTACKS = {
  A1: attackHashBruteforce, A2: attackMalleability, A3: attackReplay, A4: attackTrapdoor,
  A5: attackWeakRng, A6: attackTiming, A7: attackAbort, A8: attackTamper,
};
