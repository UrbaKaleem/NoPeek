// HTTP + WebSocket entry point.
import express from 'express';
import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as game from './game.js';
import { H, G, H_SEED, PROTOCOL } from '../shared/crypto.js';
import { attackTiming } from '../shared/attacks.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const app = express();
app.set('trust proxy', 1); // Render / Railway terminate TLS at a proxy
app.disable('x-powered-by');

// ---------------------------------------------------------------- security headers
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// ---------------------------------------------------------------- rate limiting (token bucket / IP)
const buckets = new Map();
const RL = Number(process.env.RATE_LIMIT_SCALE || 1); // tests raise this; 1 in production
function rateLimit(capacity, perSec) {
  capacity *= RL; perSec *= RL;
  return (req, res, next) => {
    const k = `${req.ip}:${capacity}`;
    const t = Date.now() / 1000;
    const b = buckets.get(k) || { tokens: capacity, t };
    b.tokens = Math.min(capacity, b.tokens + (t - b.t) * perSec); b.t = t;
    if (b.tokens < 1) { res.setHeader('Retry-After', '2'); return res.status(429).json({ error: 'slow down' }); }
    b.tokens -= 1; buckets.set(k, b); next();
  };
}
setInterval(() => { const t = Date.now() / 1000; for (const [k, b] of buckets) if (t - b.t > 600) buckets.delete(k); }, 60_000).unref();

app.use(express.json({ limit: '16kb' }));
app.use('/api', rateLimit(60, 10));

// ---------------------------------------------------------------- helpers
const wrap = (fn) => (req, res) => {
  try { const out = fn(req, res); if (out !== undefined) res.json(out); }
  catch (e) {
    if (e instanceof game.ApiError) return res.status(e.status).json({ error: e.message });
    console.error(e); res.status(500).json({ error: 'internal error' });
  }
};
function auth(req, res, next) {
  const h = req.get('authorization') || '';
  const user = game.authenticate(h.startsWith('Bearer ') ? h.slice(7) : '');
  if (!user) return res.status(401).json({ error: 'not signed in' });
  req.user = user; next();
}

// ---------------------------------------------------------------- public API
app.get('/api/health', (req, res) => res.json({ ok: true, protocol: PROTOCOL }));
app.get('/api/params', (req, res) => res.json({
  protocol: PROTOCOL, group: 'ristretto255 (RFC 9496)', G: G.toHex(), H: H.toHex(), hSeed: H_SEED,
  hashToCurve: 'RFC 9380 ristretto255_XMD:SHA-512_R255MAP_RO_', signatures: 'Ed25519 (RFC 8032)',
}));
app.get('/api/challenge', rateLimit(20, 1), wrap(() => ({ nonce: game.newChallenge() })));
app.post('/api/register', rateLimit(10, 0.2), wrap((req) => game.register(req.body)));
app.post('/api/login', rateLimit(20, 0.5), wrap((req) => game.login(req.body)));
app.get('/api/me', auth, wrap((req) => ({ id: req.user.id, name: req.user.name, publicKey: req.user.publicKey, keys: game.playerKeys(req.user.id) })));
app.post('/api/logout', auth, wrap((req) => { game.logout(req.user); return { ok: true }; }));
app.post('/api/keys/rotate', auth, wrap((req) => game.rotateKey(req.user, req.body)));
app.post('/api/keys/revoke', auth, wrap((req) => game.revokeKey(req.user, req.body)));

app.get('/api/tournaments', wrap(() => game.listTournaments()));
app.post('/api/tournaments', auth, rateLimit(10, 0.2), wrap((req) => game.createTournament(req.user, req.body)));
app.get('/api/tournaments/:id', wrap((req) => game.getTournament(req.params.id)));
app.post('/api/tournaments/:id/join', auth, wrap((req) => game.joinTournament(req.user, req.params.id)));
app.post('/api/tournaments/:id/bots', auth, wrap((req) => game.addBots(req.user, req.params.id, req.body?.count)));
app.get('/api/matches/:id', wrap((req) => game.getMatch(req.params.id)));
app.post('/api/matches/:id/commit', auth, wrap((req) => game.commit(req.user, req.params.id, req.body)));
app.post('/api/matches/:id/reveal', auth, wrap((req) => game.reveal(req.user, req.params.id, req.body)));
app.get('/api/audit', wrap((req) => game.getAudit(req.query.tournament || null)));

// Server-side timing measurement for the Attack Lab (browser clocks are too coarse).
let timingBusy = false;
app.get('/api/lab/timing', rateLimit(3, 0.05), wrap((req, res) => {
  if (timingBusy) return res.status(429).json({ error: 'busy, try again' });
  timingBusy = true;
  try { return attackTiming({ hr: () => Number(process.hrtime.bigint()) / 1e6 }); } finally { timingBusy = false; }
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'not found' }));

// ---------------------------------------------------------------- static frontend
const pub = join(__dirname, '..', 'public');
app.use(express.static(pub, { extensions: ['html'], maxAge: '5m' }));
app.get(/^\/(?!api|ws).*/, (req, res) => res.sendFile(join(pub, 'index.html')));

// ---------------------------------------------------------------- WebSocket push
const server = createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 4096 });
wss.on('connection', (ws) => {
  ws.subs = new Set();
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === 'subscribe' && typeof msg.tournamentId === 'string' && ws.subs.size < 20) ws.subs.add(msg.tournamentId);
      if (msg.type === 'unsubscribe') ws.subs.delete(msg.tournamentId);
    } catch { /* ignore junk */ }
  });
});
game.events.on('tournament', (tid) => {
  const data = JSON.stringify({ type: 'tournament.updated', tournamentId: tid });
  for (const ws of wss.clients) if (ws.readyState === 1 && (ws.subs.has(tid) || ws.subs.has('*'))) ws.send(data);
});
setInterval(() => {
  for (const ws of wss.clients) { if (!ws.isAlive) { ws.terminate(); continue; } ws.isAlive = false; ws.ping(); }
}, 30_000).unref();

// ---------------------------------------------------------------- timers
game.retireOrphanBots();
setInterval(() => { try { game.sweepDeadlines(); } catch (e) { console.error(e); } }, 1000).unref();

server.listen(PORT, () => console.log(`CommitRPS listening on http://localhost:${PORT}`));
export { server };
