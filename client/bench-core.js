// Benchmarks: measure the cost of each security choice on this device.
import * as C from '../shared/crypto.js';

export function benchSuite(ms = 250) {
  const ctx = C.context({ tournamentId: 't', matchId: 'm', round: 1, playerId: 'p' });
  const id = C.generateIdentity();
  const ped = C.commitMove('rock');
  const proof = C.proveOpening(ped, ctx);
  const salt = C.newSalt();
  const hc = C.hashCommit('rock', salt, ctx);
  const msg = 'x'.repeat(200);
  const sig = C.sign(msg, id.secretKey);
  const bPed = C.buildCommit({ move: 'rock', scheme: 'pedersen', ctx, secretKey: id.secretKey });
  const bHash = C.buildCommit({ move: 'rock', scheme: 'hash', ctx, secretKey: id.secretKey });
  const cases = [
    ['Pedersen commit  C = mG + rH', 'pedersen', () => C.commitMove('paper')],
    ['Pedersen opening check', 'pedersen', () => C.verifyOpening(ped.commitment, 'rock', ped.blinding)],
    ['Okamoto PoK — prove', 'pedersen', () => C.proveOpening(ped, ctx)],
    ['Okamoto PoK — verify', 'pedersen', () => C.verifyProof(ped.commitment, proof, ctx)],
    ['SHA-256 hash commit', 'hash', () => C.hashCommit('rock', salt, ctx)],
    ['SHA-256 hash opening check', 'hash', () => C.verifyHashCommit(hc, 'rock', salt, ctx)],
    ['Ed25519 sign', 'both', () => C.sign(msg, id.secretKey)],
    ['Ed25519 verify', 'both', () => C.verifySig(msg, sig, id.publicKey)],
    ['Full client commit (Pedersen+PoK+sig)', 'pedersen', () => C.buildCommit({ move: 'rock', scheme: 'pedersen', ctx, secretKey: id.secretKey })],
    ['Full client commit (hash+sig)', 'hash', () => C.buildCommit({ move: 'rock', scheme: 'hash', ctx, secretKey: id.secretKey })],
    ['Full verifier check (Pedersen)', 'pedersen', () => C.checkCommit({ ctx, ...bPed.public, publicKey: id.publicKey })],
    ['Full verifier check (hash)', 'hash', () => C.checkCommit({ ctx, ...bHash.public, publicKey: id.publicKey })],
  ];
  const rows = cases.map(([name, scheme, fn]) => {
    for (let i = 0; i < 5; i++) fn();
    let n = 0; const t0 = performance.now();
    while (performance.now() - t0 < ms) { fn(); n++; }
    const el = performance.now() - t0;
    return { name, scheme, opsPerSec: Math.round((n * 1000) / el), msPerOp: el / n };
  });
  const sizes = {
    pedersen: { commitment: 32, proof: 96, signature: 64, opening: 32, commitMsg: JSON.stringify(bPed.public).length },
    hash: { commitment: 32, proof: 0, signature: 64, opening: 32, commitMsg: JSON.stringify(bHash.public).length },
  };
  return { rows, sizes };
}

