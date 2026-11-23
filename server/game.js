// Referee: identity & sessions, key lifecycle, tournaments, commit/reveal state machine,
// hash-chained audit log, timeouts, and honest demo bots.
import { randomBytes, createHash, timingSafeEqual, randomInt } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { q, tx, onRollback } from './db.js';
import {
  context, checkCommit, checkReveal, judge, verifySig, messages, generateIdentity,
  buildCommit, buildReveal, fingerprint,
} from '../shared/crypto.js';

export const events = new EventEmitter();
events.setMaxListeners(1000);

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const fail = (status, msg) => { throw new ApiError(status, msg); };

const id = (n = 8) => randomBytes(n).toString('hex');
const sha256hex = (s) => createHash('sha256').update(s).digest('hex');
const now = () => Date.now();
const SESSION_TTL = 12 * 3600 * 1000;
const COMMIT_TIMEOUT = Number(process.env.COMMIT_TIMEOUT_SEC || 300) * 1000;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;

// ------------------------------------------------------------------ audit log
// The chain head is read inside the same transaction as the insert, so a rolled-back
// transaction can never leave the chain inconsistent.
export function audit(type, tournamentId, payload) {
  const lastHash = q('SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1').get()?.hash || '0'.repeat(64);
  const ts = now();
  const body = JSON.stringify({ ts, type, tournamentId: tournamentId || null, payload });
  const hash = sha256hex(lastHash + body);
  q('INSERT INTO audit_log (ts,type,tournament_id,payload,prev_hash,hash) VALUES (?,?,?,?,?,?)')
    .run(ts, type, tournamentId || null, JSON.stringify(payload), lastHash, hash);
}
// Events that must be logged even though the surrounding transaction is rolled back.
const auditAfterRollback = (...args) => onRollback(() => audit(...args));
export function getAudit(tournamentId, limit = 500) {
  const rows = tournamentId
    ? q('SELECT * FROM audit_log WHERE tournament_id = ? ORDER BY seq ASC LIMIT ?').all(tournamentId, limit)
    : q('SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?').all(limit).reverse();
  return rows.map((r) => ({ ...r, payload: JSON.parse(r.payload) }));
}

// ------------------------------------------------------------------ identity & sessions
export function newChallenge() {
  const nonce = id(16);
  q('DELETE FROM challenges WHERE expires_at < ?').run(now());
  q('INSERT INTO challenges (nonce, expires_at) VALUES (?, ?)').run(nonce, now() + 120_000);
  return nonce;
}
function consumeChallenge(nonce) {
  const row = typeof nonce === 'string' && q('SELECT * FROM challenges WHERE nonce = ?').get(nonce);
  if (!row || row.expires_at < now()) fail(400, 'challenge expired or unknown');
  q('DELETE FROM challenges WHERE nonce = ?').run(nonce); // single use → no replay
}
function issueSession(playerId, publicKey) {
  const token = randomBytes(32).toString('base64url');
  q('INSERT INTO sessions (token_hash, player_id, public_key, expires_at) VALUES (?,?,?,?)')
    .run(sha256hex(token), playerId, publicKey, now() + SESSION_TTL);
  return token;
}
function cleanName(name) {
  if (typeof name !== 'string') fail(400, 'name required');
  const n = name.trim().replace(/[^\p{L}\p{N} _.-]/gu, '').slice(0, 24);
  if (n.length < 2) fail(400, 'name must be 2–24 letters/digits');
  return n;
}

export function register({ name, publicKey, nonce, signature }) {
  name = cleanName(name);
  if (!HEX64.test(publicKey || '') || !HEX128.test(signature || '')) fail(400, 'malformed key or signature');
  consumeChallenge(nonce);
  // Proof of possession: the client must sign the challenge with the private key.
  if (!verifySig(messages.register({ name, publicKey, nonce }), signature, publicKey)) fail(401, 'bad signature');
  if (q('SELECT 1 FROM player_keys WHERE public_key = ?').get(publicKey)) fail(409, 'key already registered');
  const playerId = 'p_' + id(6);
  tx(() => {
    q('INSERT INTO players (id, name, created_at) VALUES (?,?,?)').run(playerId, name, now());
    q("INSERT INTO player_keys (public_key, player_id, status, created_at) VALUES (?,?,'active',?)").run(publicKey, playerId, now());
  });
  audit('player.register', null, { playerId, name, publicKey, fingerprint: fingerprint(publicKey) });
  return { playerId, name, token: issueSession(playerId, publicKey) };
}

export function login({ publicKey, nonce, signature }) {
  const key = q('SELECT * FROM player_keys WHERE public_key = ?').get(publicKey || '');
  if (!key) fail(404, 'unknown key');
  if (key.status !== 'active') fail(403, `key is ${key.status}`);
  const player = q('SELECT * FROM players WHERE id = ?').get(key.player_id);
  consumeChallenge(nonce);
  if (!verifySig(messages.register({ name: player.name, publicKey, nonce }), signature, publicKey)) fail(401, 'bad signature');
  return { playerId: player.id, name: player.name, token: issueSession(player.id, publicKey) };
}

export function authenticate(token) {
  if (typeof token !== 'string' || token.length < 20 || token.length > 100) return null;
  const h = sha256hex(token);
  const row = q('SELECT * FROM sessions WHERE token_hash = ?').get(h);
  // Lookup is by hash, then a constant-time re-check (defence in depth vs timing leaks).
  if (!row || !timingSafeEqual(Buffer.from(row.token_hash, 'hex'), Buffer.from(h, 'hex'))) return null;
  if (row.expires_at < now()) { q('DELETE FROM sessions WHERE token_hash = ?').run(h); return null; }
  const key = q('SELECT status FROM player_keys WHERE public_key = ?').get(row.public_key);
  if (key?.status !== 'active') return null;
  const player = q('SELECT id, name FROM players WHERE id = ?').get(row.player_id);
  return { ...player, publicKey: row.public_key, tokenHash: h };
}
export function logout(user) { q('DELETE FROM sessions WHERE token_hash = ?').run(user.tokenHash); }

export function rotateKey(user, { newKey, nonce, oldSig, newSig }) {
  if (!HEX64.test(newKey || '')) fail(400, 'malformed key');
  consumeChallenge(nonce);
  const msg = messages.rotate({ playerId: user.id, oldKey: user.publicKey, newKey, nonce });
  if (!verifySig(msg, oldSig, user.publicKey)) fail(401, 'old key signature invalid');
  if (!verifySig(msg, newSig, newKey)) fail(401, 'new key proof-of-possession invalid');
  if (q('SELECT 1 FROM player_keys WHERE public_key = ?').get(newKey)) fail(409, 'key already used');
  tx(() => {
    q("UPDATE player_keys SET status='rotated', retired_at=? WHERE public_key=?").run(now(), user.publicKey);
    q("INSERT INTO player_keys (public_key, player_id, status, created_at) VALUES (?,?,'active',?)").run(newKey, user.id, now());
    q('DELETE FROM sessions WHERE player_id = ?').run(user.id);
  });
  audit('key.rotate', null, { playerId: user.id, oldKey: user.publicKey, newKey });
  return { token: issueSession(user.id, newKey) };
}

export function revokeKey(user, { nonce, signature }) {
  consumeChallenge(nonce);
  const msg = messages.revoke({ playerId: user.id, publicKey: user.publicKey, nonce });
  if (!verifySig(msg, signature, user.publicKey)) fail(401, 'bad signature');
  tx(() => {
    q("UPDATE player_keys SET status='revoked', retired_at=? WHERE public_key=?").run(now(), user.publicKey);
    q('DELETE FROM sessions WHERE player_id = ?').run(user.id);
  });
  audit('key.revoke', null, { playerId: user.id, publicKey: user.publicKey });
  return { revoked: true };
}

export function playerKeys(playerId) {
  return q('SELECT public_key, status, created_at, retired_at FROM player_keys WHERE player_id = ? ORDER BY created_at').all(playerId);
}

// ------------------------------------------------------------------ tournaments
export function createTournament(user, { name, size, scheme = 'pedersen', revealTimeout = 60 }) {
  name = cleanName(name || `${user.name}'s cup`);
  size = Number(size);
  if (![2, 4, 8].includes(size)) fail(400, 'size must be 2, 4 or 8');
  if (!['pedersen', 'hash'].includes(scheme)) fail(400, 'scheme must be pedersen or hash');
  revealTimeout = Math.min(600, Math.max(15, Number(revealTimeout) || 60));
  const tid = 't_' + id(5);
  q("INSERT INTO tournaments (id,name,size,scheme,reveal_timeout,status,created_by,created_at) VALUES (?,?,?,?,?,'open',?,?)")
    .run(tid, name, size, scheme, revealTimeout, user.id, now());
  audit('tournament.create', tid, { name, size, scheme, revealTimeout, createdBy: user.id });
  joinTournament(user, tid);
  return getTournament(tid);
}

export function listTournaments() {
  return q(`SELECT t.*, (SELECT COUNT(*) FROM tournament_players tp WHERE tp.tournament_id = t.id) AS joined
            FROM tournaments t ORDER BY created_at DESC LIMIT 50`).all();
}

export function joinTournament(user, tid) {
  const t = q('SELECT * FROM tournaments WHERE id = ?').get(tid) || fail(404, 'no such tournament');
  if (t.status !== 'open') fail(409, 'tournament already started');
  if (q('SELECT 1 FROM tournament_players WHERE tournament_id=? AND player_id=?').get(tid, user.id)) return getTournament(tid);
  const n = q('SELECT COUNT(*) AS n FROM tournament_players WHERE tournament_id=?').get(tid).n;
  if (n >= t.size) fail(409, 'tournament full');
  q('INSERT INTO tournament_players (tournament_id, player_id) VALUES (?,?)').run(tid, user.id);
  audit('tournament.join', tid, { playerId: user.id });
  if (n + 1 === t.size) startTournament(tid);
  emit(tid);
  return getTournament(tid);
}

export function addBots(user, tid, count = 1) {
  const t = q('SELECT * FROM tournaments WHERE id = ?').get(tid) || fail(404, 'no such tournament');
  if (t.status !== 'open') fail(409, 'tournament already started');
  const n = q('SELECT COUNT(*) AS n FROM tournament_players WHERE tournament_id=?').get(tid).n;
  count = Math.min(Number(count) || 1, t.size - n);
  for (let i = 0; i < count; i++) {
    const bot = createBot();
    joinTournament(bot, tid);
  }
  return getTournament(tid);
}

function startTournament(tid) {
  const t = q('SELECT * FROM tournaments WHERE id = ?').get(tid);
  const players = q('SELECT player_id FROM tournament_players WHERE tournament_id=?').all(tid).map((r) => r.player_id);
  // Fisher–Yates with CSPRNG → unbiased, unpredictable seeding.
  for (let i = players.length - 1; i > 0; i--) { const j = randomInt(i + 1); [players[i], players[j]] = [players[j], players[i]]; }
  tx(() => {
    players.forEach((p, i) => q('UPDATE tournament_players SET seed=? WHERE tournament_id=? AND player_id=?').run(i + 1, tid, p));
    const rounds = Math.log2(t.size);
    for (let r = 1; r <= rounds; r++) {
      const slots = t.size / 2 ** r;
      for (let s = 0; s < slots; s++) {
        const mid = 'm_' + id(5);
        const [p1, p2] = r === 1 ? [players[2 * s], players[2 * s + 1]] : [null, null];
        q('INSERT INTO matches (id,tournament_id,bracket_round,slot,p1,p2,status,deadline) VALUES (?,?,?,?,?,?,?,?)')
          .run(mid, tid, r, s, p1, p2, r === 1 ? 'commit' : 'pending', r === 1 ? now() + COMMIT_TIMEOUT : null);
      }
    }
    q("UPDATE tournaments SET status='running' WHERE id=?").run(tid);
  });
  audit('tournament.start', tid, { seeding: players });
  q("SELECT id FROM matches WHERE tournament_id=? AND status='commit'").all(tid).forEach((m) => scheduleBots(m.id));
}

const playerName = (pid) => (pid ? q('SELECT name, is_bot FROM players WHERE id=?').get(pid) : null);

export function getTournament(tid) {
  const t = q('SELECT * FROM tournaments WHERE id = ?').get(tid) || fail(404, 'no such tournament');
  const players = q(`SELECT p.id, p.name, p.is_bot, tp.seed FROM tournament_players tp JOIN players p ON p.id = tp.player_id
                     WHERE tp.tournament_id = ? ORDER BY tp.seed, p.created_at`).all(tid);
  const matches = q('SELECT * FROM matches WHERE tournament_id=? ORDER BY bracket_round, slot').all(tid).map(publicMatch);
  return { ...t, players, matches };
}

// ------------------------------------------------------------------ matches
function publicMatch(m) {
  const moves = q('SELECT * FROM moves WHERE match_id=? ORDER BY game_round, committed_at').all(m.id).map((mv) => ({
    gameRound: mv.game_round, playerId: mv.player_id, publicKey: mv.public_key, scheme: mv.scheme,
    commitment: mv.commitment, proof: mv.proof ? JSON.parse(mv.proof) : null, commitSig: mv.commit_sig,
    committedAt: mv.committed_at,
    // Openings are only ever present after the player chose to reveal them.
    move: mv.move, opening: mv.opening, revealSig: mv.reveal_sig, revealedAt: mv.revealed_at,
  }));
  return {
    id: m.id, tournamentId: m.tournament_id, bracketRound: m.bracket_round, slot: m.slot,
    p1: m.p1, p2: m.p2, p1Name: playerName(m.p1)?.name || null, p2Name: playerName(m.p2)?.name || null,
    status: m.status, gameRound: m.game_round, deadline: m.deadline, winner: m.winner, resultReason: m.result_reason,
    moves,
  };
}

export function getMatch(mid) {
  const m = q('SELECT * FROM matches WHERE id=?').get(mid) || fail(404, 'no such match');
  const t = q('SELECT scheme, reveal_timeout FROM tournaments WHERE id=?').get(m.tournament_id);
  return { ...publicMatch(m), scheme: t.scheme, revealTimeout: t.reveal_timeout };
}

function loadMatchFor(user, mid) {
  const m = q('SELECT * FROM matches WHERE id=?').get(mid) || fail(404, 'no such match');
  if (m.p1 !== user.id && m.p2 !== user.id) fail(403, 'you are not in this match');
  return m;
}

export function commit(user, mid, { commitment, proof, signature }) {
  return tx(() => {
    const m = loadMatchFor(user, mid);
    if (m.status !== 'commit') fail(409, `match is in ${m.status} phase`);
    const t = q('SELECT * FROM tournaments WHERE id=?').get(m.tournament_id);
    if (q('SELECT 1 FROM moves WHERE match_id=? AND game_round=? AND player_id=?').get(mid, m.game_round, user.id)) fail(409, 'already committed this round');
    const ctx = context({ tournamentId: m.tournament_id, matchId: mid, round: m.game_round, playerId: user.id });
    const res = checkCommit({ ctx, scheme: t.scheme, commitment, proof, signature, publicKey: user.publicKey });
    if (!res.ok) { auditAfterRollback('commit.rejected', t.id, { matchId: mid, playerId: user.id, reason: res.reason }); fail(400, `commit rejected: ${res.reason}`); }
    // Refuse an exact copy of anything already on record (cheap extra copy defence).
    if (q('SELECT 1 FROM moves WHERE commitment=?').get(commitment)) fail(400, 'commit rejected: commitment already used');
    q(`INSERT INTO moves (match_id, game_round, player_id, public_key, scheme, commitment, proof, commit_sig, committed_at)
       VALUES (?,?,?,?,?,?,?,?,?)`).run(mid, m.game_round, user.id, user.publicKey, t.scheme, commitment, proof ? JSON.stringify(proof) : null, signature, now());
    audit('commit', t.id, { matchId: mid, gameRound: m.game_round, playerId: user.id, publicKey: user.publicKey, scheme: t.scheme, commitment, proof, signature });
    const n = q('SELECT COUNT(*) AS n FROM moves WHERE match_id=? AND game_round=?').get(mid, m.game_round).n;
    if (n === 2) {
      q("UPDATE matches SET status='reveal', deadline=? WHERE id=?").run(now() + t.reveal_timeout * 1000, mid);
      audit('phase.reveal', t.id, { matchId: mid, gameRound: m.game_round });
    }
    return mid;
  }) && afterChange(mid);
}

export function reveal(user, mid, { move, opening, signature }) {
  return tx(() => {
    const m = loadMatchFor(user, mid);
    if (m.status !== 'reveal') fail(409, `match is in ${m.status} phase`);
    const row = q('SELECT * FROM moves WHERE match_id=? AND game_round=? AND player_id=?').get(mid, m.game_round, user.id) || fail(409, 'no commitment');
    if (row.move) fail(409, 'already revealed');
    if (typeof opening !== 'string' || !HEX64.test(opening)) fail(400, 'malformed opening');
    const ctx = context({ tournamentId: m.tournament_id, matchId: mid, round: m.game_round, playerId: user.id });
    const res = checkReveal({ ctx, scheme: row.scheme, commitment: row.commitment, move, opening, signature, publicKey: row.public_key });
    if (!res.ok) {
      // A signed but non-matching opening is cryptographic proof of cheating → forfeit.
      audit('reveal.invalid', m.tournament_id, { matchId: mid, playerId: user.id, move, opening, reason: res.reason });
      if (res.reason === 'opening does not match commitment') { finishMatch(m, otherPlayer(m, user.id), 'opponent revealed an opening that does not match their commitment'); return mid; }
      fail(400, `reveal rejected: ${res.reason}`);
    }
    q('UPDATE moves SET move=?, opening=?, reveal_sig=?, revealed_at=? WHERE match_id=? AND game_round=? AND player_id=?')
      .run(move, opening, signature, now(), mid, m.game_round, user.id);
    audit('reveal', m.tournament_id, { matchId: mid, gameRound: m.game_round, playerId: user.id, move, opening, signature });
    const both = q('SELECT * FROM moves WHERE match_id=? AND game_round=? AND move IS NOT NULL').all(mid, m.game_round);
    if (both.length === 2) resolveRound(m, both);
    return mid;
  }) && afterChange(mid);
}

const otherPlayer = (m, pid) => (m.p1 === pid ? m.p2 : m.p1);

function resolveRound(m, both) {
  const a = both.find((x) => x.player_id === m.p1), b = both.find((x) => x.player_id === m.p2);
  const j = judge(a.move, b.move);
  if (j === 0) {
    q("UPDATE matches SET status='commit', game_round=game_round+1, deadline=? WHERE id=?").run(now() + COMMIT_TIMEOUT, m.id);
    audit('round.tie', m.tournament_id, { matchId: m.id, gameRound: m.game_round, move: a.move });
  } else {
    finishMatch(m, j > 0 ? m.p1 : m.p2, `${j > 0 ? a.move : b.move} beats ${j > 0 ? b.move : a.move}`);
  }
}

function finishMatch(m, winner, reason) {
  q("UPDATE matches SET status='done', winner=?, result_reason=?, deadline=NULL WHERE id=?").run(winner, reason, m.id);
  audit('match.result', m.tournament_id, { matchId: m.id, winner, reason });
  const t = q('SELECT * FROM tournaments WHERE id=?').get(m.tournament_id);
  const rounds = Math.log2(t.size);
  if (m.bracket_round === rounds) {
    q("UPDATE tournaments SET status='finished', winner=? WHERE id=?").run(winner, t.id);
    audit('tournament.finish', t.id, { winner });
    return;
  }
  const next = q('SELECT * FROM matches WHERE tournament_id=? AND bracket_round=? AND slot=?').get(t.id, m.bracket_round + 1, Math.floor(m.slot / 2));
  const col = m.slot % 2 === 0 ? 'p1' : 'p2';
  q(`UPDATE matches SET ${col}=? WHERE id=?`).run(winner, next.id);
  const n2 = q('SELECT * FROM matches WHERE id=?').get(next.id);
  if (n2.p1 && n2.p2) q("UPDATE matches SET status='commit', deadline=? WHERE id=?").run(now() + COMMIT_TIMEOUT, next.id);
}

function afterChange(mid) {
  const m = q('SELECT * FROM matches WHERE id=?').get(mid);
  emit(m.tournament_id);
  scheduleBots(mid);
  // A newly opened next-round match may contain bots too.
  q("SELECT id FROM matches WHERE tournament_id=? AND status IN ('commit','reveal')").all(m.tournament_id).forEach((x) => x.id !== mid && scheduleBots(x.id));
  return getMatch(mid);
}

function emit(tid) { events.emit('tournament', tid); }

// ------------------------------------------------------------------ timeouts
export function sweepDeadlines() {
  const due = q("SELECT * FROM matches WHERE status IN ('commit','reveal') AND deadline IS NOT NULL AND deadline < ?").all(now());
  for (const m of due) {
    tx(() => {
      const rows = q('SELECT * FROM moves WHERE match_id=? AND game_round=?').all(m.id, m.game_round);
      const done = rows.filter((r) => (m.status === 'reveal' ? r.move : true)).map((r) => r.player_id);
      if (done.length === 1) {
        finishMatch(m, done[0], m.status === 'reveal' ? 'opponent did not reveal before the deadline (selective-abort defence)' : 'opponent did not commit before the deadline');
      } else {
        // Nobody acted: restart the round with fresh commitments.
        q('DELETE FROM moves WHERE match_id=? AND game_round=?').run(m.id, m.game_round);
        q("UPDATE matches SET status='commit', game_round=game_round+1, deadline=? WHERE id=?").run(now() + COMMIT_TIMEOUT, m.id);
        audit('round.timeout', m.tournament_id, { matchId: m.id, gameRound: m.game_round });
      }
    });
    afterChange(m.id);
  }
}

// ------------------------------------------------------------------ bots (honest demo opponents)
// Each bot is a normal player with its own Ed25519 key. Its secret state lives only in
// this module's memory — the referee code paths above treat it exactly like a human.
const botKeys = new Map(); // playerId → { secretKey, publicKey, pending: Map }
function createBot() {
  const names = ['Ada', 'Turing', 'Shannon', 'Diffie', 'Hellman', 'Rivest', 'Merkle', 'Schnorr', 'Pedersen', 'Okamoto', 'Chaum', 'Goldwasser'];
  const key = generateIdentity();
  const pid = 'b_' + id(6);
  const name = `${names[randomInt(names.length)]}-bot`;
  tx(() => {
    q('INSERT INTO players (id, name, is_bot, created_at) VALUES (?,?,1,?)').run(pid, name, now());
    q("INSERT INTO player_keys (public_key, player_id, status, created_at) VALUES (?,?,'active',?)").run(key.publicKey, pid, now());
  });
  botKeys.set(pid, { ...key, pending: new Map() });
  return { id: pid, name, publicKey: key.publicKey };
}

const scheduled = new Set();
function scheduleBots(mid) {
  const m = q('SELECT * FROM matches WHERE id=?').get(mid);
  if (!m || !['commit', 'reveal'].includes(m.status)) return;
  for (const pid of [m.p1, m.p2]) {
    const bot = pid && botKeys.get(pid);
    if (!bot) continue;
    const key = `${mid}:${m.game_round}:${m.status}:${pid}`;
    if (scheduled.has(key)) continue;
    scheduled.add(key);
    setTimeout(() => { try { botAct(pid, mid); } catch (e) { if (!(e instanceof ApiError)) console.error('bot error', e); } }, 700 + randomInt(1500));
  }
}
function botAct(pid, mid) {
  const bot = botKeys.get(pid);
  const m = q('SELECT * FROM matches WHERE id=?').get(mid);
  const t = q('SELECT * FROM tournaments WHERE id=?').get(m.tournament_id);
  const user = { id: pid, publicKey: bot.publicKey };
  const ctx = context({ tournamentId: m.tournament_id, matchId: mid, round: m.game_round, playerId: pid });
  const slot = `${mid}:${m.game_round}`;
  if (m.status === 'commit') {
    const move = ['rock', 'paper', 'scissors'][randomInt(3)];
    const b = buildCommit({ move, scheme: t.scheme, ctx, secretKey: bot.secretKey });
    bot.pending.set(slot, b.secret);
    commit(user, mid, b.public);
  } else if (m.status === 'reveal') {
    const secret = bot.pending.get(slot);
    if (!secret) return;
    const row = q('SELECT commitment FROM moves WHERE match_id=? AND game_round=? AND player_id=?').get(mid, m.game_round, pid);
    reveal(user, mid, buildReveal({ ctx, scheme: t.scheme, commitment: row.commitment, ...secret, secretKey: bot.secretKey }));
    bot.pending.delete(slot);
  }
}

/** Bots that existed before a restart have lost their in-memory keys; take them out of open play. */
export function retireOrphanBots() {
  const orphanMatches = q(`SELECT m.* FROM matches m JOIN players p ON (p.id = m.p1 OR p.id = m.p2)
                           WHERE p.is_bot = 1 AND m.status IN ('commit','reveal')`).all();
  for (const m of orphanMatches) {
    const bots = [m.p1, m.p2].filter((p) => p && p.startsWith('b_') && !botKeys.has(p));
    if (!bots.length) continue;
    const human = [m.p1, m.p2].find((p) => !bots.includes(p));
    tx(() => finishMatch(m, human || m.p1, 'bot opponent went offline after a server restart'));
  }
}
