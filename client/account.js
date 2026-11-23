// Account: key lifecycle — backup, import, rotate, revoke, sign out.
import * as C from '../shared/crypto.js';
import { api, store, login } from './api.js';
import { esc, $, hex, toast, info } from './ui.js';

export async function renderAccount(root) {
  const id = store.identity;
  let me = null;
  if (id) { try { me = await api('/api/me'); } catch { /* session may be gone */ } }
  root.innerHTML = `
    <h1>Account &amp; key lifecycle</h1>
    <div class="grid g2" style="align-items:start">
      <div class="card">
        <h2>Current identity</h2>
        ${id ? `<dl class="kv">
          <dt>Name</dt><dd>${esc(id.name)}</dd><dt>Player id</dt><dd class="mono">${esc(id.playerId)}</dd>
          <dt>Public key</dt><dd>${hex(id.publicKey)}</dd><dt>Fingerprint</dt><dd class="mono">${C.fingerprint(id.publicKey)}</dd>
          <dt>Server status</dt><dd>${me ? '<span class="badge good">active session</span>' : '<span class="badge bad">no valid session (key revoked, rotated elsewhere or expired)</span>'}</dd>
        </dl>
        <hr><div class="row">
          <button class="btn" id="backup" data-tip="Downloads your private key as a JSON file. Anyone holding this file can play as you, so keep it safe.">Download key backup</button>
          <button class="btn ghost" id="rotate" data-tip="Generates a new key. The old key signs a hand-over to the new one, and the new key proves you hold it. Old sessions are invalidated.">Rotate key</button>
          <button class="btn danger" id="revoke" data-tip="Permanently disables this key on the server (e.g. if your device was compromised). Past signatures stay verifiable.">Revoke key</button>
          <button class="btn ghost" id="logout">Forget on this device</button>
        </div>` : '<p class="muted">No key on this device yet. Create one in the <a href="#/">lobby</a>, or import a backup.</p>'}
        <hr><h3>Import a key backup</h3>
        <div class="row"><input type="file" id="import" accept="application/json,.json" /></div>
      </div>
      <div class="card">
        <h2>Key history ${info('The server keeps every public key you ever used and its status, so old signatures in the audit log remain verifiable even after rotation or revocation.')}</h2>
        ${me ? `<table><thead><tr><th>Public key</th><th>Status</th><th>Created</th></tr></thead><tbody>
          ${me.keys.map((k) => `<tr><td>${hex(k.public_key, 8)}</td><td><span class="badge ${k.status === 'active' ? 'good' : k.status === 'revoked' ? 'bad' : ''}">${k.status}</span></td><td class="small">${new Date(k.created_at).toLocaleString()}</td></tr>`).join('')}
        </tbody></table>` : '<p class="muted small">Sign in to see your key history.</p>'}
        <hr><h3>Lifecycle policy</h3>
        <ul class="small">
          <li><strong>Generation:</strong> in the browser, from the CSPRNG (<span class="mono">crypto.getRandomValues</span>).</li>
          <li><strong>Distribution:</strong> only the public key is sent. Proof of possession comes from signing a single-use server challenge.</li>
          <li><strong>Storage:</strong> private key in this browser's localStorage (a strict CSP means no third-party scripts can run). Sessions are random 256-bit bearer tokens; the server stores only their SHA-256 hash, with a 12 h lifetime.</li>
          <li><strong>Rotation:</strong> the old key signs the new key, and the new key signs too.</li>
          <li><strong>Revocation:</strong> signed request; the key and all its sessions die immediately.</li>
          <li><strong>Commitment secrets</strong> (move, r) are ephemeral: one per round, saved locally only until revealed.</li>
        </ul>
      </div>
    </div>`;

  $('#import').onchange = async (e) => {
    try {
      const data = JSON.parse(await e.target.files[0].text());
      if (!/^[0-9a-f]{64}$/.test(data.secretKey) || !/^[0-9a-f]{64}$/.test(data.publicKey)) throw new Error('not a CommitRPS key backup');
      await login(data); toast('Key imported and signed in'); renderAccount(root);
    } catch (err) { toast(err.message, true); }
  };
  if (!id) return;
  $('#backup').onclick = () => {
    const blob = new Blob([JSON.stringify({ format: 'commitrps-key-v1', name: id.name, playerId: id.playerId, publicKey: id.publicKey, secretKey: id.secretKey }, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `commitrps-key-${id.name}.json`; a.click();
  };
  $('#logout').onclick = async () => {
    if (!confirm('Remove the key from this browser? Without a backup you cannot sign in as this player again.')) return;
    try { await api('/api/logout', { method: 'POST' }); } catch { /* ignore */ }
    store.identity = null; toast('Key removed from this device'); renderAccount(root);
  };
  $('#rotate').onclick = async () => {
    try {
      const nk = C.generateIdentity();
      const { nonce } = await api('/api/challenge');
      const msg = C.messages.rotate({ playerId: id.playerId, oldKey: id.publicKey, newKey: nk.publicKey, nonce });
      const r = await api('/api/keys/rotate', { method: 'POST', body: { newKey: nk.publicKey, nonce, oldSig: C.sign(msg, id.secretKey), newSig: C.sign(msg, nk.secretKey) } });
      store.identity = { ...id, ...nk, token: r.token };
      toast('Key rotated. Download a fresh backup!'); renderAccount(root);
    } catch (err) { toast(err.message, true); }
  };
  $('#revoke').onclick = async () => {
    if (!confirm('Revoke this key permanently? You will need a new identity to keep playing.')) return;
    try {
      const { nonce } = await api('/api/challenge');
      await api('/api/keys/revoke', { method: 'POST', body: { nonce, signature: C.sign(C.messages.revoke({ playerId: id.playerId, publicKey: id.publicKey, nonce }), id.secretKey) } });
      store.identity = null; toast('Key revoked'); renderAccount(root);
    } catch (err) { toast(err.message, true); }
  };
}
