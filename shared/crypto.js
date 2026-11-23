/**
 * CommitRPS cryptographic core — shared by the browser client and the Node server.
 *
 * Everything here is built on audited, peer-reviewed primitives from the
 * @noble family (Cure53 / Trail of Bits audits):
 *   - ristretto255 prime-order group (RFC 9496)       → Pedersen commitments
 *   - RFC 9380 hash-to-curve (ristretto255_XMD:SHA-512) → NUMS generator H
 *   - Ed25519 signatures (RFC 8032)                    → player identity / non-repudiation
 *   - SHA-256 / SHA-512                                → hash commitments, Fiat–Shamir
 *   - CSPRNG (crypto.getRandomValues)                  → blinding factors, salts, keys
 *
 * We do NOT implement any primitive ourselves; this file only *composes* them into
 * the commitment protocol (Pedersen commit, opening check, Okamoto proof of
 * knowledge of the opening, salted hash commitment, signed protocol messages).
 */
import { ristretto255, ristretto255_hasher, ed25519 } from '@noble/curves/ed25519.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from '@noble/hashes/utils.js';

export { bytesToHex, hexToBytes, utf8ToBytes, randomBytes };

export const PROTOCOL = 'CommitRPS/v1';
const Point = ristretto255.Point;
export const L = Point.Fn.ORDER; // group order ℓ = 2^252 + 27742317777372353535851937790883648493

// ---------------------------------------------------------------- moves
export const MOVES = { rock: 1n, paper: 2n, scissors: 3n };
export const MOVE_NAMES = { 1: 'rock', 2: 'paper', 3: 'scissors' };
export function moveToScalar(move) {
  const m = MOVES[move];
  if (m === undefined) throw new Error('invalid move');
  return m;
}
export function scalarToMove(m) {
  const name = MOVE_NAMES[Number(m)];
  if (!name || BigInt(m) < 1n || BigInt(m) > 3n) return null;
  return name;
}
/** +1 if a beats b, -1 if b beats a, 0 for a tie. */
export function judge(a, b) {
  if (a === b) return 0;
  const beats = { rock: 'scissors', paper: 'rock', scissors: 'paper' };
  return beats[a] === b ? 1 : -1;
}

// ---------------------------------------------------------------- scalar helpers
export const mod = (a, m = L) => ((a % m) + m) % m;

/** Little-endian 32-byte encoding of a scalar (same convention as Ed25519). */
export function scalarToHex(s) {
  let x = mod(s);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return bytesToHex(out);
}
export function hexToScalar(hex) {
  const b = hexToBytes(hex);
  if (b.length !== 32) throw new Error('scalar must be 32 bytes');
  let x = 0n;
  for (let i = 31; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  if (x >= L) throw new Error('non-canonical scalar'); // reject malleable encodings
  return x;
}
function bytesToNumberLE(b) {
  let x = 0n;
  for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]);
  return x;
}

/**
 * Uniform random scalar in [1, ℓ). 64 bytes from the CSPRNG reduced mod ℓ gives
 * statistical distance < 2^-250 from uniform (no modulo bias).
 */
export function randomScalar() {
  for (;;) {
    const s = mod(bytesToNumberLE(randomBytes(64)));
    if (s !== 0n) return s;
  }
}

/** Hash arbitrary byte strings to a scalar (used for the Fiat–Shamir challenge). */
export function hashToScalar(...parts) {
  return mod(bytesToNumberLE(sha512(concatBytes(...parts))));
}

// ---------------------------------------------------------------- generators
export const G = Point.BASE;
/**
 * H is derived with RFC 9380 hash-to-curve from a public domain string, so it is a
 * "nothing-up-my-sleeve" point: nobody (including the server operator) knows
 * log_G(H). If anyone knew it, they could open a commitment to any move (see the
 * "trapdoor setup" attack in the Attack Lab).
 */
export const H_SEED = `${PROTOCOL}/pedersen/H`;
export const H = ristretto255_hasher.hashToCurve(utf8ToBytes(H_SEED), {
  DST: 'CommitRPS-v1-NUMS-H_ristretto255_XMD:SHA-512_R255MAP_RO_',
});

export const pointFromHex = (hex) => Point.fromHex(hex); // canonical decoding, rejects invalid
export const pointToHex = (P) => P.toHex();

// ---------------------------------------------------------------- Pedersen commitments
/** C = m·G + r·H */
const mul = (P, k) => (k === 0n ? Point.ZERO : P.multiply(k)); // noble rejects k = 0
export function pedersen(m, r, h = H) {
  return mul(G, mod(m)).add(mul(h, mod(r)));
}

/** Commit to a move. Returns everything the client must keep secret until reveal. */
export function commitMove(move, { rng = randomScalar } = {}) {
  const m = moveToScalar(move);
  const r = rng();
  const C = pedersen(m, r);
  return { move, m, r, C, commitment: C.toHex(), blinding: scalarToHex(r) };
}

/** Check that (move, r) opens commitment C. */
export function verifyOpening(commitmentHex, move, blindingHex, h = H) {
  try {
    const C = pointFromHex(commitmentHex);
    const m = moveToScalar(move);
    const r = hexToScalar(blindingHex);
    return pedersen(m, r, h).equals(C);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- context binding
/**
 * The context binds a commitment to one specific (tournament, match, round, player).
 * It is mixed into the Fiat–Shamir challenge and into every signature, which defeats
 * replay across matches and copy/maul attacks between players.
 */
export function context({ tournamentId, matchId, round, playerId }) {
  return `${PROTOCOL}|t=${tournamentId}|m=${matchId}|r=${round}|p=${playerId}`;
}

// ---------------------------------------------------------------- proof of knowledge of opening
/**
 * Okamoto Σ-protocol made non-interactive with Fiat–Shamir:
 *   prover knows (m, r) with C = mG + rH
 *   pick a, b ← Z_ℓ;  T = aG + bH
 *   c = H(ctx, G, H, C, T)
 *   s1 = a + c·m,  s2 = b + c·r
 * verifier: s1·G + s2·H == T + c·C
 *
 * Because ctx contains the player's id, a malicious opponent who derives
 * C' = C + G from the victim's commitment cannot produce a valid proof for C'
 * (he doesn't know r), and cannot reuse the victim's proof (wrong ctx).
 * This turns the malleable Pedersen commitment into a non-malleable one.
 */
export function proveOpening({ m, r, C }, ctx) {
  const a = randomScalar();
  const b = randomScalar();
  const T = pedersen(a, b);
  const c = challenge(ctx, C, T);
  const s1 = mod(a + c * mod(m));
  const s2 = mod(b + c * mod(r));
  return { T: T.toHex(), s1: scalarToHex(s1), s2: scalarToHex(s2) };
}

function challenge(ctx, C, T) {
  return hashToScalar(
    utf8ToBytes(`${PROTOCOL}/pok-opening`),
    utf8ToBytes(ctx),
    G.toBytes(), H.toBytes(), C.toBytes(), T.toBytes(),
  );
}

export function verifyProof(commitmentHex, proof, ctx) {
  try {
    const C = pointFromHex(commitmentHex);
    const T = pointFromHex(proof.T);
    const s1 = hexToScalar(proof.s1);
    const s2 = hexToScalar(proof.s2);
    const c = challenge(ctx, C, T);
    const lhs = G.multiplyUnsafe(s1).add(H.multiplyUnsafe(s2)); // public values only
    const rhs = T.add(C.multiplyUnsafe(c));
    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- salted hash commitments
/**
 * The classic "hash(move || salt)" scheme from the topic brief, done properly:
 * domain-separated, context-bound, 256-bit CSPRNG salt.
 * Computationally hiding (SHA-256 preimage resistance) and computationally binding
 * (collision resistance) — contrast with Pedersen: perfectly hiding, computationally binding.
 */
export function hashCommit(move, saltHex, ctx = '') {
  moveToScalar(move);
  const msg = concatBytes(
    utf8ToBytes(`${PROTOCOL}/hash-commit|`), utf8ToBytes(ctx), utf8ToBytes('|'),
    utf8ToBytes(move), utf8ToBytes('|'), hexToBytes(saltHex),
  );
  return bytesToHex(sha256(msg));
}
export function newSalt(bytes = 32) { return bytesToHex(randomBytes(bytes)); }

/** Constant-time comparison of two equal-length hex strings. */
export function ctEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
export function verifyHashCommit(commitHex, move, saltHex, ctx = '') {
  try { return ctEqualHex(hashCommit(move, saltHex, ctx), commitHex); } catch { return false; }
}

// ---------------------------------------------------------------- identity keys & signatures
export function generateIdentity() {
  const secretKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(secretKey);
  return { secretKey: bytesToHex(secretKey), publicKey: bytesToHex(publicKey) };
}
export function fingerprint(publicKeyHex) {
  return bytesToHex(sha256(hexToBytes(publicKeyHex))).slice(0, 16);
}

/** Canonical message strings — every field is explicit, so nothing can be reinterpreted. */
export const messages = {
  register: ({ name, publicKey, nonce }) => `${PROTOCOL}|register|name=${name}|pk=${publicKey}|nonce=${nonce}`,
  commit: ({ ctx, scheme, commitment, proofT }) => `${PROTOCOL}|commit|${ctx}|scheme=${scheme}|C=${commitment}|T=${proofT || '-'}`,
  reveal: ({ ctx, scheme, commitment, move, opening }) => `${PROTOCOL}|reveal|${ctx}|scheme=${scheme}|C=${commitment}|move=${move}|open=${opening}`,
  revoke: ({ playerId, publicKey, nonce }) => `${PROTOCOL}|revoke|p=${playerId}|pk=${publicKey}|nonce=${nonce}`,
  rotate: ({ playerId, oldKey, newKey, nonce }) => `${PROTOCOL}|rotate|p=${playerId}|old=${oldKey}|new=${newKey}|nonce=${nonce}`,
};

export function sign(message, secretKeyHex) {
  return bytesToHex(ed25519.sign(utf8ToBytes(message), hexToBytes(secretKeyHex)));
}
export function verifySig(message, signatureHex, publicKeyHex) {
  try {
    return ed25519.verify(hexToBytes(signatureHex), utf8ToBytes(message), hexToBytes(publicKeyHex));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- full client-side helpers
/** Everything a client sends in the commit phase. */
export function buildCommit({ move, scheme = 'pedersen', ctx, secretKey, saltBytes = 32 }) {
  if (scheme === 'pedersen') {
    const c = commitMove(move);
    const proof = proveOpening(c, ctx);
    const msg = messages.commit({ ctx, scheme, commitment: c.commitment, proofT: proof.T });
    return {
      public: { scheme, commitment: c.commitment, proof, signature: sign(msg, secretKey) },
      secret: { move, opening: c.blinding },
    };
  }
  if (scheme === 'hash') {
    const salt = newSalt(saltBytes);
    const commitment = hashCommit(move, salt, ctx);
    const msg = messages.commit({ ctx, scheme, commitment });
    return {
      public: { scheme, commitment, proof: null, signature: sign(msg, secretKey) },
      secret: { move, opening: salt },
    };
  }
  throw new Error('unknown scheme');
}
export function buildReveal({ ctx, scheme, commitment, move, opening, secretKey }) {
  const msg = messages.reveal({ ctx, scheme, commitment, move, opening });
  return { move, opening, signature: sign(msg, secretKey) };
}

/** Verifier side (runs on the server AND in every browser — don't trust the referee). */
export function checkCommit({ ctx, scheme, commitment, proof, signature, publicKey }) {
  const msg = messages.commit({ ctx, scheme, commitment, proofT: proof?.T });
  if (!verifySig(msg, signature, publicKey)) return { ok: false, reason: 'bad signature' };
  if (scheme === 'pedersen') {
    try { pointFromHex(commitment); } catch { return { ok: false, reason: 'commitment is not a valid group element' }; }
    if (!proof || !verifyProof(commitment, proof, ctx)) return { ok: false, reason: 'proof of knowledge of opening failed' };
  } else if (scheme === 'hash') {
    if (!/^[0-9a-f]{64}$/.test(commitment)) return { ok: false, reason: 'malformed hash commitment' };
  } else return { ok: false, reason: 'unknown scheme' };
  return { ok: true };
}
export function checkReveal({ ctx, scheme, commitment, move, opening, signature, publicKey }) {
  if (!MOVES[move]) return { ok: false, reason: 'invalid move' };
  const msg = messages.reveal({ ctx, scheme, commitment, move, opening });
  if (!verifySig(msg, signature, publicKey)) return { ok: false, reason: 'bad signature' };
  const ok = scheme === 'pedersen'
    ? verifyOpening(commitment, move, opening)
    : verifyHashCommit(commitment, move, opening, ctx);
  return ok ? { ok: true } : { ok: false, reason: 'opening does not match commitment' };
}
