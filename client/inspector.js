// Inspector: independent, client-side verification of the transparency log.
import * as C from '../shared/crypto.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { api } from './api.js';
import { esc, $, hex, fmtTime, EMOJI } from './ui.js';

const sha256hex = (s) => C.bytesToHex(sha256(C.utf8ToBytes(s)));

/** Re-derive every entry hash, check chain continuity, and re-verify each commit/reveal. */
export function verifyLog(entries, { contiguous }) {
  const commits = new Map(); // matchId|round|player → commit payload
  const rows = [];
  let chainOk = true;
  entries.forEach((e, i) => {
    const body = JSON.stringify({ ts: e.ts, type: e.type, tournamentId: e.tournament_id, payload: e.payload });
    const hashOk = sha256hex(e.prev_hash + body) === e.hash;
    const linkOk = !contiguous || i === 0 || entries[i - 1].hash === e.prev_hash;
    if (!hashOk || !linkOk) chainOk = false;
    let crypto = null;
    const p = e.payload;
    if (e.type === 'commit') {
      const ctx = C.context({ tournamentId: e.tournament_id, matchId: p.matchId, round: p.gameRound, playerId: p.playerId });
      crypto = C.checkCommit({ ctx, scheme: p.scheme, commitment: p.commitment, proof: p.proof, signature: p.signature, publicKey: p.publicKey });
      commits.set(`${p.matchId}|${p.gameRound}|${p.playerId}`, p);
    }
    if (e.type === 'reveal') {
      const c = commits.get(`${p.matchId}|${p.gameRound}|${p.playerId}`);
      if (!c) crypto = { ok: false, reason: 'reveal without a logged commitment' };
      else {
        const ctx = C.context({ tournamentId: e.tournament_id, matchId: p.matchId, round: p.gameRound, playerId: p.playerId });
        crypto = C.checkReveal({ ctx, scheme: c.scheme, commitment: c.commitment, move: p.move, opening: p.opening, signature: p.signature, publicKey: c.publicKey });
      }
    }
    rows.push({ e, hashOk, linkOk, crypto });
  });
  return { rows, chainOk, allCryptoOk: rows.every((r) => !r.crypto || r.crypto.ok) };
}

export async function renderInspector(root, tid) {
  const tournaments = await api('/api/tournaments');
  const params = await api('/api/params');
  root.innerHTML = `
    <h1>Inspector</h1>
    <p class="muted" style="max-width:75ch">The referee keeps an append-only, hash-chained log: each entry stores <span class="mono">hash = SHA-256(prev_hash ‖ entry)</span>. This page downloads it and re-checks everything <em>in your browser</em>: the chain, every Ed25519 signature, every proof of knowledge and every opening.</p>
    <div class="grid g2" style="margin:16px 0">
      <div class="card"><h2>Public parameters</h2><dl class="kv">
        <dt>Group</dt><dd>${esc(params.group)}</dd><dt>G</dt><dd>${hex(params.G)}</dd><dt>H</dt><dd>${hex(params.H)}</dd>
        <dt>H derivation</dt><dd class="small">${esc(params.hashToCurve)} of “${esc(params.hSeed)}”</dd>
        <dt>Re-derived here</dt><dd>${C.H.toHex() === params.H ? '<span class="badge good">✓ H matches</span>' : '<span class="badge bad">✗ server H differs!</span>'}</dd></dl></div>
      <div class="card"><h2>Choose log</h2>
        <div class="row"><select id="tsel"><option value="">Entire log (latest 500, full chain check)</option>${tournaments.map((t) => `<option value="${esc(t.id)}" ${t.id === tid ? 'selected' : ''}>${esc(t.name)} · ${esc(t.id)}</option>`).join('')}</select>
        <button class="btn" id="go">Verify</button></div>
        <p class="small muted" style="margin-top:10px">Want to see detection in action? <button class="btn ghost small" id="tamper" data-tip="Changes one revealed move in the downloaded copy (as a dishonest server might) and re-runs verification">Simulate a tampered entry</button></p>
      </div>
    </div>
    <div id="result"></div>`;
  let current = null;
  const run = async (tamper = false) => {
    const t = $('#tsel').value;
    let entries;
    if (!tamper) { entries = await api(`/api/audit${t ? `?tournament=${encodeURIComponent(t)}` : ''}`); current = entries; }
    else entries = JSON.parse(JSON.stringify(current));
    if (tamper) {
      const idx = entries.findIndex((e) => e.type === 'reveal') >= 0 ? entries.findIndex((e) => e.type === 'reveal') : entries.findIndex((e) => e.type === 'commit');
      if (idx < 0) { $('#result').innerHTML = '<p class="muted">Play a match first so there is something to tamper with.</p>'; return; }
      const e = entries[idx];
      if (e.type === 'reveal') e.payload.move = e.payload.move === 'rock' ? 'paper' : 'rock';
      else e.payload.commitment = C.pedersen(1n, C.randomScalar()).toHex();
      e._tampered = true;
    }
    const v = verifyLog(entries, { contiguous: !t });
    const counts = { commit: 0, reveal: 0 };
    v.rows.forEach((r) => { if (counts[r.e.type] !== undefined) counts[r.e.type]++; });
    $('#result').innerHTML = `
      <div class="card">
        <div class="spread"><h2 style="margin:0">${entries.length} log entries</h2>
          <div class="row">${v.chainOk ? '<span class="badge good">✓ hash chain intact</span>' : '<span class="badge bad">✗ hash chain broken</span>'}
          ${v.allCryptoOk ? `<span class="badge good">✓ ${counts.commit} commits & ${counts.reveal} reveals verified</span>` : '<span class="badge bad">✗ cryptographic check failed</span>'}</div></div>
        ${tamper ? '<div class="callout bad small" style="margin-top:10px">One entry was modified in your local copy. Both the hash chain and the player\'s signature catch it (red rows).</div>' : ''}
        <div class="tablewrap" style="margin-top:10px"><table><thead><tr><th>#</th><th>Time</th><th>Event</th><th>Details</th><th>Hash</th><th>Crypto</th></tr></thead><tbody>
        ${v.rows.map(({ e, hashOk, linkOk, crypto }) => `<tr style="${!hashOk || !linkOk || (crypto && !crypto.ok) ? 'background:rgba(255,107,107,.08)' : ''}">
          <td class="mono">${e.seq}</td><td class="small">${fmtTime(e.ts)}</td><td><span class="badge ${e.type.startsWith('commit') ? 'seal' : e.type.startsWith('reveal') ? 'open' : ''}">${esc(e.type)}</span></td>
          <td class="small">${details(e)}</td>
          <td>${hashOk && linkOk ? '<span class="badge good">✓</span>' : '<span class="badge bad">✗</span>'} ${hex(e.hash, 6)}</td>
          <td>${crypto ? (crypto.ok ? '<span class="badge good">✓</span>' : `<span class="badge bad" data-tip="${esc(crypto.reason)}">✗ ${esc(crypto.reason)}</span>`) : ''}</td></tr>`).join('')}
        </tbody></table></div>
      </div>`;
  };
  $('#go').onclick = () => run(false);
  $('#tamper').onclick = async () => { if (!current) await run(false); run(true); };
  run(false);
}

function details(e) {
  const p = e.payload;
  switch (e.type) {
    case 'commit': return `${esc(p.playerId)} · C=${hex(p.commitment, 6)}`;
    case 'reveal': return `${esc(p.playerId)} · ${EMOJI[p.move] || ''} ${esc(p.move)}`;
    case 'match.result': return `winner ${esc(p.winner)} — ${esc(p.reason)}`;
    case 'player.register': return `${esc(p.name)} · ${esc(p.fingerprint)}`;
    case 'tournament.create': return `${esc(p.name)} · ${p.size} players · ${esc(p.scheme)}`;
    case 'commit.rejected': case 'reveal.invalid': return `${esc(p.playerId)} — ${esc(p.reason)}`;
    default: return esc(JSON.stringify(p).slice(0, 90));
  }
}
