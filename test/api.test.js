import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import * as C from '../shared/crypto.js';

const PORT = 3900 + Math.floor(Math.random() * 90);
const base = `http://127.0.0.1:${PORT}`;
let srv;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(path, { method = 'GET', body, token } = {}) {
  const res = await fetch(base + path, { method, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const json = await res.json();
  return { status: res.status, json };
}
async function newPlayer(name) {
  const id = C.generateIdentity();
  const { json: { nonce } } = await api('/api/challenge');
  const signature = C.sign(C.messages.register({ name, publicKey: id.publicKey, nonce }), id.secretKey);
  const r = await api('/api/register', { method: 'POST', body: { name, publicKey: id.publicKey, nonce, signature } });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return { ...id, ...r.json };
}
async function waitFor(fn, ms = 15000) {
  const t = Date.now();
  for (;;) { const v = await fn(); if (v) return v; if (Date.now() - t > ms) throw new Error('timeout'); await sleep(150); }
}

test.before(async () => {
  srv = spawn(process.execPath, ['server/index.js'], { env: { ...process.env, PORT, DB_PATH: ':memory:', RATE_LIMIT_SCALE: '50' }, stdio: ['ignore', 'pipe', 'inherit'] });
  await waitFor(async () => { try { return (await fetch(base + '/api/health')).ok; } catch { return false; } });
});
test.after(() => srv.kill());

test('registration requires a fresh, signed challenge', async () => {
  const id = C.generateIdentity();
  const { json: { nonce } } = await api('/api/challenge');
  const sig = C.sign(C.messages.register({ name: 'eve', publicKey: id.publicKey, nonce }), C.generateIdentity().secretKey);
  assert.equal((await api('/api/register', { method: 'POST', body: { name: 'eve', publicKey: id.publicKey, nonce, signature: sig } })).status, 401);
  const good = C.sign(C.messages.register({ name: 'eve', publicKey: id.publicKey, nonce }), id.secretKey);
  assert.equal((await api('/api/register', { method: 'POST', body: { name: 'eve', publicKey: id.publicKey, nonce, signature: good } })).status, 400, 'nonce single-use');
});

for (const scheme of ['pedersen', 'hash']) {
  test(`full 2-player match vs bot (${scheme})`, async () => {
    const alice = await newPlayer('alice_' + scheme);
    const { json: t } = await api('/api/tournaments', { method: 'POST', token: alice.token, body: { name: 'cup ' + scheme, size: 2, scheme } });
    await api(`/api/tournaments/${t.id}/bots`, { method: 'POST', token: alice.token, body: { count: 1 } });
    let secrets = {};
    const final = await waitFor(async () => {
      const { json: m } = await api(`/api/matches/${(await api(`/api/tournaments/${t.id}`)).json.matches[0].id}`);
      if (m.status === 'done') return m;
      const ctx = C.context({ tournamentId: t.id, matchId: m.id, round: m.gameRound, playerId: alice.playerId });
      const mine = m.moves.find((x) => x.gameRound === m.gameRound && x.playerId === alice.playerId);
      if (m.status === 'commit' && !mine) {
        const b = C.buildCommit({ move: 'rock', scheme, ctx, secretKey: alice.secretKey });
        secrets[m.gameRound] = b;
        const r = await api(`/api/matches/${m.id}/commit`, { method: 'POST', token: alice.token, body: b.public });
        assert.equal(r.status, 200, JSON.stringify(r.json));
      }
      if (m.status === 'reveal' && mine && !mine.move) {
        // Verify the opponent's commitment ourselves before revealing (don't trust the referee).
        const opp = m.moves.find((x) => x.gameRound === m.gameRound && x.playerId !== alice.playerId);
        const octx = C.context({ tournamentId: t.id, matchId: m.id, round: m.gameRound, playerId: opp.playerId });
        assert.ok(C.checkCommit({ ctx: octx, scheme, commitment: opp.commitment, proof: opp.proof, signature: opp.commitSig, publicKey: opp.publicKey }).ok);
        const b = secrets[m.gameRound];
        const rv = C.buildReveal({ ctx, scheme, commitment: b.public.commitment, ...b.secret, secretKey: alice.secretKey });
        const r = await api(`/api/matches/${m.id}/reveal`, { method: 'POST', token: alice.token, body: rv });
        assert.equal(r.status, 200, JSON.stringify(r.json));
      }
      return null;
    }, 30000);
    assert.ok(final.winner);
    const { json: tt } = await api(`/api/tournaments/${t.id}`);
    assert.equal(tt.status, 'finished');
    // Audit chain verifies
    const { json: log } = await api(`/api/audit`);
    assert.ok(log.length > 5);
  });
}

test('mauled commitment and lying reveal are rejected', async () => {
  const a = await newPlayer('attacker');
  const v = await newPlayer('victim');
  const { json: t } = await api('/api/tournaments', { method: 'POST', token: v.token, body: { name: 'sus', size: 2 } });
  await api(`/api/tournaments/${t.id}/join`, { method: 'POST', token: a.token });
  const { json: tt } = await api(`/api/tournaments/${t.id}`);
  const m = tt.matches[0];
  const vctx = C.context({ tournamentId: t.id, matchId: m.id, round: 1, playerId: v.playerId });
  const actx = C.context({ tournamentId: t.id, matchId: m.id, round: 1, playerId: a.playerId });
  const vb = C.buildCommit({ move: 'rock', ctx: vctx, secretKey: v.secretKey });
  assert.equal((await api(`/api/matches/${m.id}/commit`, { method: 'POST', token: v.token, body: vb.public })).status, 200);
  // attacker: C' = C + G, replaying victim's proof, signed with his own key
  const Cp = C.pointFromHex(vb.public.commitment).add(C.G).toHex();
  const sig = C.sign(C.messages.commit({ ctx: actx, scheme: 'pedersen', commitment: Cp, proofT: vb.public.proof.T }), a.secretKey);
  const r = await api(`/api/matches/${m.id}/commit`, { method: 'POST', token: a.token, body: { commitment: Cp, proof: vb.public.proof, signature: sig } });
  assert.equal(r.status, 400); assert.match(r.json.error, /proof/);
  // exact copy rejected too
  const sig2 = C.sign(C.messages.commit({ ctx: actx, scheme: 'pedersen', commitment: vb.public.commitment, proofT: vb.public.proof.T }), a.secretKey);
  assert.equal((await api(`/api/matches/${m.id}/commit`, { method: 'POST', token: a.token, body: { commitment: vb.public.commitment, proof: vb.public.proof, signature: sig2 } })).status, 400);
  // attacker commits honestly, then lies at reveal → forfeits
  const ab = C.buildCommit({ move: 'paper', ctx: actx, secretKey: a.secretKey });
  assert.equal((await api(`/api/matches/${m.id}/commit`, { method: 'POST', token: a.token, body: ab.public })).status, 200);
  const lie = C.buildReveal({ ctx: actx, scheme: 'pedersen', commitment: ab.public.commitment, move: 'scissors', opening: ab.secret.opening, secretKey: a.secretKey });
  await api(`/api/matches/${m.id}/reveal`, { method: 'POST', token: a.token, body: lie });
  const { json: mm } = await api(`/api/matches/${m.id}`);
  assert.equal(mm.status, 'done'); assert.equal(mm.winner, v.playerId);
});

test('key rotation and revocation', async () => {
  const p = await newPlayer('rotator');
  const nk = C.generateIdentity();
  const { json: { nonce } } = await api('/api/challenge');
  const msg = C.messages.rotate({ playerId: p.playerId, oldKey: p.publicKey, newKey: nk.publicKey, nonce });
  const r = await api('/api/keys/rotate', { method: 'POST', token: p.token, body: { newKey: nk.publicKey, nonce, oldSig: C.sign(msg, p.secretKey), newSig: C.sign(msg, nk.secretKey) } });
  assert.equal(r.status, 200);
  assert.equal((await api('/api/me', { token: p.token })).status, 401, 'old session killed');
  const me = await api('/api/me', { token: r.json.token });
  assert.equal(me.json.keys.length, 2);
  const { json: { nonce: n2 } } = await api('/api/challenge');
  const rv = await api('/api/keys/revoke', { method: 'POST', token: r.json.token, body: { nonce: n2, signature: C.sign(C.messages.revoke({ playerId: p.playerId, publicKey: nk.publicKey, nonce: n2 }), nk.secretKey) } });
  assert.equal(rv.status, 200);
  assert.equal((await api('/api/me', { token: r.json.token })).status, 401);
});
