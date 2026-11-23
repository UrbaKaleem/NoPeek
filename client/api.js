// REST + WebSocket client and local identity storage.
import * as C from '../shared/crypto.js';

const ID_KEY = 'commitrps.identity.v1';
export const store = {
  get identity() { try { return JSON.parse(localStorage.getItem(ID_KEY)); } catch { return null; } },
  set identity(v) { v ? localStorage.setItem(ID_KEY, JSON.stringify(v)) : localStorage.removeItem(ID_KEY); },
  secret(matchId, round) { try { return JSON.parse(localStorage.getItem(`commitrps.secret.${matchId}.${round}`)); } catch { return null; } },
  saveSecret(matchId, round, v) { localStorage.setItem(`commitrps.secret.${matchId}.${round}`, JSON.stringify(v)); },
  dropSecret(matchId, round) { localStorage.removeItem(`commitrps.secret.${matchId}.${round}`); },
};

export async function api(path, { method = 'GET', body } = {}) {
  const id = store.identity;
  const res = await fetch(path, {
    method,
    headers: { 'content-type': 'application/json', ...(id?.token ? { authorization: `Bearer ${id.token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let json = null;
  try { json = await res.json(); } catch { /* empty */ }
  if (!res.ok) {
    const err = new Error(json?.error || `HTTP ${res.status}`);
    err.status = res.status; throw err;
  }
  return json;
}

/** Create a brand-new identity: Ed25519 key generated *in the browser*; server only sees the public key. */
export async function register(name) {
  const keys = C.generateIdentity();
  const { nonce } = await api('/api/challenge');
  const clean = name.trim().replace(/[^\p{L}\p{N} _.-]/gu, '').slice(0, 24);
  const signature = C.sign(C.messages.register({ name: clean, publicKey: keys.publicKey, nonce }), keys.secretKey);
  const r = await api('/api/register', { method: 'POST', body: { name: clean, publicKey: keys.publicKey, nonce, signature } });
  store.identity = { ...keys, playerId: r.playerId, name: r.name, token: r.token, createdAt: Date.now() };
  return store.identity;
}

/** Sign in again with an existing key (e.g. after importing a backup or when the session expired). */
export async function login(identity) {
  const { nonce } = await api('/api/challenge');
  const signature = C.sign(C.messages.register({ name: identity.name, publicKey: identity.publicKey, nonce }), identity.secretKey);
  const r = await fetch('/api/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ publicKey: identity.publicKey, nonce, signature }) });
  const j = await r.json();
  if (!r.ok) throw new Error(j.error);
  store.identity = { ...identity, playerId: j.playerId, name: j.name, token: j.token };
  return store.identity;
}

export async function ensureSession() {
  const id = store.identity;
  if (!id) return null;
  try { await api('/api/me'); return id; }
  catch (e) { if (e.status === 401) { try { return await login(id); } catch { return null; } } throw e; }
}

// ---------------- live updates
let ws, wsSubs = new Set(), listeners = new Set(), backoff = 500;
export function onUpdate(fn) { listeners.add(fn); return () => listeners.delete(fn); }
export function subscribe(tid) {
  wsSubs.add(tid);
  if (ws?.readyState === 1) ws.send(JSON.stringify({ type: 'subscribe', tournamentId: tid }));
}
export function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => { backoff = 500; wsSubs.forEach((t) => ws.send(JSON.stringify({ type: 'subscribe', tournamentId: t }))); };
  ws.onmessage = (ev) => { try { const m = JSON.parse(ev.data); listeners.forEach((fn) => fn(m)); } catch { /* ignore */ } };
  ws.onclose = () => { setTimeout(connectWS, backoff); backoff = Math.min(backoff * 2, 10000); };
}
export const wsState = () => (ws?.readyState === 1 ? 'live' : 'reconnecting');
