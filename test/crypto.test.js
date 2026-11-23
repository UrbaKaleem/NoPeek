import test from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../shared/crypto.js';
import * as A from '../shared/attacks.js';

const ctx = C.context({ tournamentId: 't1', matchId: 'm1', round: 1, playerId: 'alice' });

test('H is a fixed NUMS point, distinct from G', () => {
  assert.notEqual(C.H.toHex(), C.G.toHex());
  assert.equal(C.H.toHex().length, 64);
});

test('Pedersen commit/open round-trip for every move', () => {
  for (const mv of ['rock', 'paper', 'scissors']) {
    const c = C.commitMove(mv);
    assert.ok(C.verifyOpening(c.commitment, mv, c.blinding));
    for (const other of ['rock', 'paper', 'scissors'].filter((x) => x !== mv))
      assert.ok(!C.verifyOpening(c.commitment, other, c.blinding), 'binding');
  }
});

test('same move commits to different values (hiding needs fresh r)', () => {
  assert.notEqual(C.commitMove('rock').commitment, C.commitMove('rock').commitment);
});

test('homomorphic: C(m1,r1)+C(m2,r2)=C(m1+m2,r1+r2)', () => {
  const r1 = C.randomScalar(), r2 = C.randomScalar();
  assert.ok(C.pedersen(1n, r1).add(C.pedersen(2n, r2)).equals(C.pedersen(3n, r1 + r2)));
});

test('proof of knowledge verifies and is context-bound', () => {
  const c = C.commitMove('paper');
  const proof = C.proveOpening(c, ctx);
  assert.ok(C.verifyProof(c.commitment, proof, ctx));
  const otherCtx = C.context({ tournamentId: 't1', matchId: 'm1', round: 1, playerId: 'mallory' });
  assert.ok(!C.verifyProof(c.commitment, proof, otherCtx));
  assert.ok(!C.verifyProof(c.C.add(C.G).toHex(), proof, ctx));
});

test('non-canonical scalars are rejected', () => {
  const bad = C.scalarToHex(0n).replace(/^00/, 'ff').replace(/00$/, 'ff');
  assert.throws(() => C.hexToScalar('ff'.repeat(32)));
  assert.ok(bad);
});

test('hash commitment round trip, context-bound', () => {
  const salt = C.newSalt();
  const h = C.hashCommit('rock', salt, ctx);
  assert.ok(C.verifyHashCommit(h, 'rock', salt, ctx));
  assert.ok(!C.verifyHashCommit(h, 'paper', salt, ctx));
  assert.ok(!C.verifyHashCommit(h, 'rock', salt, ctx + 'x'));
});

test('signed commit + reveal pipeline (both schemes)', () => {
  const id = C.generateIdentity();
  for (const scheme of ['pedersen', 'hash']) {
    const b = C.buildCommit({ move: 'scissors', scheme, ctx, secretKey: id.secretKey });
    assert.deepEqual(C.checkCommit({ ctx, ...b.public, publicKey: id.publicKey }), { ok: true });
    const rv = C.buildReveal({ ctx, scheme, commitment: b.public.commitment, ...b.secret, secretKey: id.secretKey });
    assert.deepEqual(C.checkReveal({ ctx, scheme, commitment: b.public.commitment, ...rv, publicKey: id.publicKey }), { ok: true });
    const lie = C.buildReveal({ ctx, scheme, commitment: b.public.commitment, move: 'rock', opening: b.secret.opening, secretKey: id.secretKey });
    assert.equal(C.checkReveal({ ctx, scheme, commitment: b.public.commitment, ...lie, publicKey: id.publicKey }).ok, false);
  }
});

test('attacks: vulnerable configs break, shipped configs hold', () => {
  const a1 = A.attackHashBruteforce({ saltBits: 10 });
  assert.ok(a1.log[0].correct && a1.log[1].correct);
  const a2 = A.attackMalleability({ rounds: 60 });
  assert.ok(a2.vulnerable.winRate > 45);
  assert.equal(a2.mitigated.rejected, 60);
  const a3 = A.attackReplay();
  assert.ok(a3.vulnerable.accepted && !a3.mitigated.contextBoundAccepted && !a3.mitigated.signatureAccepted);
  const a4 = A.attackTrapdoor();
  assert.ok(a4.vulnerable.accepted && !a4.mitigated.accepted);
  const a5 = A.attackWeakRng({ bits: 8 });
  assert.ok(a5.vulnerable.correct);
  const a8 = A.attackTamper();
  assert.ok(!a8.mitigated.swappedCommitmentAccepted && !a8.mitigated.forgedRevealAccepted);
});
