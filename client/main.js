// App shell, router, lobby and the tournament / match screen.
import * as C from '../shared/crypto.js';
import { api, store, register, ensureSession, connectWS, subscribe, onUpdate } from './api.js';
import { esc, $, $$, hex, info, toast, EMOJI, countdown } from './ui.js';
import { startTour, maybeAutoTour } from './tour.js';
import { renderLab } from './lab.js';
import { renderInspector } from './inspector.js';
import { renderBench } from './bench.js';
import { renderLearn } from './learn.js';
import { renderAccount } from './account.js';

const app = $('#app');
let cleanup = [];
const onLeave = (fn) => cleanup.push(fn);

// ------------------------------------------------------------------ router
const routes = [
  [/^#?\/?$/, 'home', renderHome],
  [/^#\/t\/([\w-]+)$/, 'home', renderTournament],
  [/^#\/learn$/, 'learn', renderLearn],
  [/^#\/inspector(?:\/([\w-]+))?$/, 'inspector', renderInspector],
  [/^#\/lab$/, 'lab', renderLab],
  [/^#\/bench$/, 'bench', renderBench],
  [/^#\/account$/, 'account', renderAccount],
];
async function route() {
  cleanup.forEach((f) => f()); cleanup = [];
  const h = location.hash || '#/';
  for (const [re, nav, fn] of routes) {
    const m = h.match(re);
    if (m) {
      $$('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.nav === nav));
      window.scrollTo(0, 0);
      try { await fn(app, ...m.slice(1), { onLeave }); } catch (e) { console.error(e); app.innerHTML = `<div class="card"><h2>Something went wrong</h2><p class="muted">${esc(e.message)}</p></div>`; }
      return;
    }
  }
  app.innerHTML = '<div class="card"><h2>Not found</h2><a href="#/">Back to lobby</a></div>';
}
window.addEventListener('hashchange', route);
$('#tour-btn').addEventListener('click', () => startTour(location.hash.startsWith('#/t/') ? 'match' : 'home'));
connectWS();
ensureSession().finally(route);

// ------------------------------------------------------------------ identity panel
function identityCard() {
  const id = store.identity;
  if (!id) return `
    <div class="card" data-tour="identity">
      <h2>1 · Create your player key ${info('Your browser generates an Ed25519 key pair. The private key never leaves this device; the server only stores the public key and you prove ownership by signing a one-time challenge.')}</h2>
      <p class="muted small">No passwords. Your identity <em>is</em> a signing key generated right here in your browser.</p>
      <form id="reg" class="row">
        <input id="reg-name" placeholder="Pick a display name" maxlength="24" minlength="2" required autocomplete="nickname" />
        <button class="btn" type="submit">Generate key &amp; join</button>
      </form>
      <p class="small muted" style="margin-top:8px">Already have a key backup? <a href="#/account">Import it</a>.</p>
    </div>`;
  return `
    <div class="card" data-tour="identity">
      <div class="spread"><h2 style="margin:0">Signed in as ${esc(id.name)}</h2><span class="badge good">key active</span></div>
      <dl class="kv" style="margin-top:10px">
        <dt>Player id</dt><dd class="mono">${esc(id.playerId)}</dd>
        <dt>Public key ${info('Ed25519 public key. Every commit and reveal you send is signed with the matching private key, so nobody — not even the server — can forge or alter your moves.')}</dt><dd>${hex(id.publicKey)}</dd>
        <dt>Fingerprint</dt><dd class="mono">${esc(C.fingerprint(id.publicKey))}</dd>
      </dl>
      <p class="small muted" style="margin:10px 0 0">Manage, back up, rotate or revoke this key on the <a href="#/account">Account</a> page.</p>
    </div>`;
}
function bindIdentity(rerender) {
  const f = $('#reg');
  if (!f) return;
  f.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = f.querySelector('button'); btn.disabled = true; btn.textContent = 'Generating…';
    try { await register($('#reg-name').value); toast('Key generated and registered'); rerender(); }
    catch (err) { toast(err.message, true); btn.disabled = false; btn.textContent = 'Generate key & join'; }
  });
}

// ------------------------------------------------------------------ home / lobby
async function renderHome(root, { onLeave }) {
  let alive = true; onLeave(() => { alive = false; });
  const draw = async () => {
    const list = await api('/api/tournaments').catch(() => []);
    if (!alive) return;
    const id = store.identity;
    const demo = C.commitMove('rock');
    root.innerHTML = `
      <section class="hero">
        <div>
          <span class="badge seal">Topic 13 · Cryptographic Commitments</span>
          <h1 style="margin-top:10px">Rock · Paper · Scissors where nobody can peek — not even the server.</h1>
          <p class="lead">Each player seals their move in a <strong>Pedersen commitment</strong> <span class="mono">C = m·G + r·H</span> in their own browser. Only after both seals are on the table does anyone open theirs. The math makes it impossible to see a sealed move, or to change one after sealing.</p>
          <div class="row"><button class="btn" id="quick" data-tip="Creates a 2-player tournament against an honest bot so you can try the full commit → reveal flow in under a minute">Quick match vs bot</button>
          <button class="btn ghost" id="tour2">Take the 60-second tour</button></div>
        </div>
        <div class="envelope" data-tip="This is a real commitment to ✊ rock that was just computed in your browser. Without the blinding factor r it is indistinguishable from a commitment to paper or scissors.">
          <div class="flap"></div><div class="wax">🔒</div>
          <div class="cap">C = ${esc(demo.commitment)}</div>
        </div>
      </section>
      <div class="grid g2">
        ${identityCard()}
        <div class="card" data-tour="create">
          <h2>2 · Start a tournament ${info('Single-elimination bracket. Ties are replayed with fresh commitments. Fill empty seats with honest bots if you are demoing alone.')}</h2>
          <form id="create" class="stack">
            <div class="row">
              <label class="field" style="flex:1">Name<input id="c-name" placeholder="e.g. Friday Cup" maxlength="24" /></label>
              <label class="field">Players<select id="c-size"><option>2</option><option selected>4</option><option>8</option></select></label>
            </div>
            <div class="row">
              <label class="field" style="flex:1"><span>Commitment scheme ${info('Pedersen: perfectly hiding, computationally binding, with a zero-knowledge proof that blocks copy-cat attacks. Hash: SHA-256(ctx‖move‖256-bit salt) — the classic scheme from the brief, for comparison.')}</span>
                <select id="c-scheme"><option value="pedersen" selected>Pedersen (ristretto255) + PoK</option><option value="hash">Salted SHA-256 hash commitment</option></select></label>
              <label class="field"><span>Reveal deadline ${info('If an opponent sees your reveal and refuses to open theirs, they forfeit when this timer runs out (selective-abort defence).')}</span><select id="c-to"><option value="30">30 s</option><option value="60" selected>60 s</option><option value="120">2 min</option></select></label>
            </div>
            <button class="btn" ${id ? '' : 'disabled data-tip="Create your player key first"'}>Create tournament</button>
          </form>
        </div>
      </div>
      <div class="card" style="margin-top:18px" data-tour="lobby">
        <div class="spread"><h2 style="margin:0">Open &amp; recent tournaments</h2><button class="btn ghost small" id="refresh">Refresh</button></div>
        <div class="tablewrap" style="margin-top:10px"><table>
          <thead><tr><th>Name</th><th>Scheme</th><th>Players</th><th>Status</th><th></th></tr></thead>
          <tbody>${list.length ? list.map((t) => `
            <tr><td>${esc(t.name)}</td><td><span class="badge ${t.scheme === 'pedersen' ? 'seal' : 'violet'}">${esc(t.scheme)}</span></td>
            <td>${t.joined}/${t.size}</td><td>${statusBadge(t.status)}</td>
            <td style="text-align:right"><a class="btn ghost small" href="#/t/${esc(t.id)}">${t.status === 'open' ? 'Join' : 'View'}</a></td></tr>`).join('')
            : '<tr><td colspan="5" class="muted">No tournaments yet — create the first one.</td></tr>'}</tbody>
        </table></div>
      </div>`;
    bindIdentity(draw);
    $('#refresh').onclick = draw;
    $('#tour2').onclick = () => startTour('home');
    $('#quick').onclick = async () => {
      if (!store.identity) { toast('Create your player key first', true); $('#reg-name')?.focus(); return; }
      try {
        const t = await api('/api/tournaments', { method: 'POST', body: { name: 'Quick match', size: 2, scheme: 'pedersen', revealTimeout: 60 } });
        await api(`/api/tournaments/${t.id}/bots`, { method: 'POST', body: { count: 1 } });
        location.hash = `#/t/${t.id}`;
      } catch (e) { toast(e.message, true); }
    };
    $('#create').addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        const t = await api('/api/tournaments', { method: 'POST', body: { name: $('#c-name').value || undefined, size: +$('#c-size').value, scheme: $('#c-scheme').value, revealTimeout: +$('#c-to').value } });
        location.hash = `#/t/${t.id}`;
      } catch (err) { toast(err.message, true); }
    });
  };
  await draw();
  subscribe('*');
  onLeave(onUpdate(() => { if (!document.activeElement || !['INPUT', 'SELECT'].includes(document.activeElement.tagName)) draw(); }));
  maybeAutoTour('home');
}
const statusBadge = (s) => `<span class="badge ${{ open: 'open', running: 'seal', finished: 'good' }[s] || ''}">${esc(s)}</span>`;

// ------------------------------------------------------------------ tournament + match
const ui = { autoScheduled: new Set(), selected: null, selectedMatch: null, autoReveal: true, busy: false, lastLocal: null };

async function renderTournament(root, tid, { onLeave }) {
  ui.selected = null; ui.selectedMatch = null;
  subscribe(tid);
  let t;
  let timer;
  let alive = true; onLeave(() => { alive = false; });
  // In-flight requests and delayed auto-reveals must not repaint a page we already left.
  const load = async () => { const nt = await api(`/api/tournaments/${tid}`); if (!alive) return; t = nt; draw(); };
  const draw = () => {
    if (!alive) return;
    const me = store.identity;
    const inT = me && t.players.some((p) => p.id === me.playerId);
    const myMatch = me && t.matches.find((m) => (m.p1 === me.playerId || m.p2 === me.playerId) && ['commit', 'reveal'].includes(m.status));
    const focus = t.matches.find((m) => m.id === ui.selectedMatch) || myMatch
      || (me && [...t.matches].reverse().find((m) => m.p1 === me.playerId || m.p2 === me.playerId))
      || t.matches.find((m) => ['commit', 'reveal'].includes(m.status)) || t.matches[t.matches.length - 1];
    const champion = t.winner && t.players.find((p) => p.id === t.winner);
    root.innerHTML = `
      <div class="spread" style="margin-bottom:14px">
        <div><a href="#/" class="small">← Lobby</a><h1 style="margin:4px 0 6px">${esc(t.name)}</h1>
          <div class="row">${statusBadge(t.status)}
            <span class="badge ${t.scheme === 'pedersen' ? 'seal' : 'violet'}" data-tip="${t.scheme === 'pedersen' ? 'Moves are committed as C = m·G + r·H on ristretto255 with a context-bound proof of knowledge of (m, r).' : 'Moves are committed as SHA-256(context ‖ move ‖ 256-bit salt).'}">${t.scheme === 'pedersen' ? 'Pedersen + PoK' : 'Salted hash'}</span>
            <span class="badge">${t.players.length}/${t.size} players</span><span class="badge">reveal deadline ${t.reveal_timeout}s</span></div></div>
        <div class="row">
          <a class="btn ghost small" href="#/inspector/${esc(t.id)}" data-tip="Independently re-verify every signature, proof, opening and the hash-chained audit log for this tournament">Verify this tournament</a>
          <button class="btn ghost small" id="share" data-tip="Copy an invite link">Copy invite link</button>
        </div>
      </div>
      ${champion ? `<div class="callout open reveal-anim" style="margin-bottom:16px">🏆 <strong>${esc(champion.name)}</strong> won the tournament. Every move that led here can be re-verified in the <a href="#/inspector/${esc(t.id)}">Inspector</a>.</div>` : ''}
      ${t.status === 'open' ? openPanel(t, me, inT) : ''}
      <div class="grid g2" style="align-items:start">
        <div class="card" data-tour="match">${focus ? matchPanel(t, focus, me) : '<p class="muted">The bracket appears when all seats are filled.</p>'}</div>
        <div class="stack">
          <div class="card" data-tour="bracket"><h2>Bracket</h2>${bracket(t, me, focus)}</div>
          <div class="card"><h2>Players</h2><div class="row">${t.players.map((p) => `<span class="badge ${p.id === me?.playerId ? 'seal' : ''}">${p.is_bot ? '🤖' : '👤'} ${esc(p.name)}</span>`).join('') || '<span class="muted">none yet</span>'}</div></div>
        </div>
      </div>`;
    bind(focus);
  };

  const bind = (focus) => {
    $('#share').onclick = async () => { try { await navigator.clipboard.writeText(location.href); toast('Invite link copied'); } catch { toast(location.href); } };
    $('#join')?.addEventListener('click', async () => { try { t = await api(`/api/tournaments/${tid}/join`, { method: 'POST' }); draw(); } catch (e) { toast(e.message, true); } });
    $('#bots')?.addEventListener('click', async () => { try { t = await api(`/api/tournaments/${tid}/bots`, { method: 'POST', body: { count: t.size - t.players.length } }); draw(); } catch (e) { toast(e.message, true); } });
    $('#bot1')?.addEventListener('click', async () => { try { t = await api(`/api/tournaments/${tid}/bots`, { method: 'POST', body: { count: 1 } }); draw(); } catch (e) { toast(e.message, true); } });
    bindIdentity(load);
    $$('.mcard').forEach((el) => el.addEventListener('click', () => { ui.selectedMatch = el.dataset.id; draw(); }));
    $$('.move').forEach((el) => el.addEventListener('click', () => { ui.selected = el.dataset.move; draw(); }));
    $('#seal')?.addEventListener('click', () => doCommit(t, focus).then(load));
    $('#reveal')?.addEventListener('click', () => doReveal(t, focus).then(load));
    $('#auto')?.addEventListener('change', (e) => { ui.autoReveal = e.target.checked; });
    // Auto-reveal once the opponent's commitment has been verified locally.
    const me = store.identity;
    if (focus && me && focus.status === 'reveal' && ui.autoReveal && !ui.busy) {
      const mine = focus.moves.find((x) => x.gameRound === focus.gameRound && x.playerId === me.playerId);
      const k = `${focus.id}:${focus.gameRound}`;
      if (mine && !mine.move && store.secret(focus.id, focus.gameRound) && !ui.autoScheduled.has(k)) {
        ui.autoScheduled.add(k);
        setTimeout(() => { if (!ui.busy) doReveal(t, focus).then(load); }, 1200);
      }
    }
  };

  await load();
  onLeave(onUpdate((m) => { if (m.tournamentId === tid) load(); }));
  timer = setInterval(() => { $$('[data-deadline]').forEach((el) => (el.textContent = countdown(+el.dataset.deadline))); }, 500);
  const poll = setInterval(load, 8000); // fallback if the socket drops
  onLeave(() => { clearInterval(timer); clearInterval(poll); });
  maybeAutoTour('match');
}

function openPanel(t, me, inT) {
  return `<div class="card" style="margin-bottom:18px">
    <div class="spread"><div><h2 style="margin:0">Waiting for players (${t.players.length}/${t.size})</h2>
    <p class="muted small" style="margin:4px 0 0">Share the invite link, or fill the remaining seats with honest bots. The bracket is seeded with a CSPRNG shuffle once full.</p></div>
    <div class="row">
      ${me && !inT ? '<button class="btn" id="join">Join tournament</button>' : ''}
      ${me ? `<button class="btn ghost" id="bot1">Add 1 bot</button><button class="btn ghost" id="bots" data-tip="Bots are ordinary players with their own Ed25519 keys; they follow the same commit → reveal protocol and are verified the same way.">Fill with bots</button>` : ''}
    </div></div>
    ${!me ? `<hr>${identityCard()}` : ''}
  </div>`;
}

function bracket(t, me, focus) {
  if (!t.matches.length) return '<p class="muted small">Not started yet.</p>';
  const rounds = Math.log2(t.size);
  const label = (r) => (r === rounds ? 'Final' : r === rounds - 1 ? 'Semi-finals' : `Round ${r}`);
  const name = (pid, nm) => (pid ? esc(nm) : '<span class="muted">TBD</span>');
  let out = '<div class="bracket">';
  for (let r = 1; r <= rounds; r++) {
    out += `<div class="bcol"><h4>${label(r)}</h4>`;
    for (const m of t.matches.filter((x) => x.bracketRound === r)) {
      const mine = me && (m.p1 === me.playerId || m.p2 === me.playerId);
      const cls = (pid) => (m.winner ? (m.winner === pid ? 'win' : 'lose') : '');
      out += `<div class="mcard ${mine ? 'mine' : ''} ${focus?.id === m.id ? 'sel' : ''}" data-id="${m.id}" tabindex="0">
        <div class="pl ${cls(m.p1)}"><span>${name(m.p1, m.p1Name)}</span></div>
        <div class="pl ${cls(m.p2)}"><span>${name(m.p2, m.p2Name)}</span></div>
        <div class="small muted">${m.status === 'done' ? '✓ done' : m.status === 'pending' ? 'waiting' : `${m.status} · round ${m.gameRound}`}</div></div>`;
    }
    out += '</div>';
  }
  return out + '</div>';
}

// ------------------------------------------------------------------ match panel
function ctxFor(t, m, playerId, round = m.gameRound) {
  return C.context({ tournamentId: t.id, matchId: m.id, round, playerId });
}
function verifyMove(t, m, mv) {
  const ctx = ctxFor(t, m, mv.playerId, mv.gameRound);
  const commitOk = C.checkCommit({ ctx, scheme: mv.scheme, commitment: mv.commitment, proof: mv.proof, signature: mv.commitSig, publicKey: mv.publicKey });
  const revealOk = mv.move ? C.checkReveal({ ctx, scheme: mv.scheme, commitment: mv.commitment, move: mv.move, opening: mv.opening, signature: mv.revealSig, publicKey: mv.publicKey }) : null;
  return { commitOk, revealOk };
}

function matchPanel(t, m, me) {
  const amIn = me && (m.p1 === me.playerId || m.p2 === me.playerId);
  const oppId = amIn ? (m.p1 === me.playerId ? m.p2 : m.p1) : null;
  const names = { [m.p1]: m.p1Name, [m.p2]: m.p2Name };
  const cur = m.moves.filter((x) => x.gameRound === m.gameRound);
  const mine = amIn && cur.find((x) => x.playerId === me.playerId);
  const opp = amIn && cur.find((x) => x.playerId === oppId);
  const secret = amIn && store.secret(m.id, m.gameRound);

  let phaseIdx = 0;
  if (m.status === 'commit') phaseIdx = mine ? 2 : (ui.selected ? 1 : 0);
  if (m.status === 'reveal') phaseIdx = mine?.move ? 4 : 3;
  if (m.status === 'done') phaseIdx = 5;
  const phases = ['Choose', 'Seal', 'Wait', 'Reveal', 'Verify'];
  const phaseBar = `<div class="phases" data-tour="phases">${phases.map((p, i) => `<div class="phase ${i === phaseIdx ? 'on' : i < phaseIdx ? 'done' : ''}">${i + 1}. ${p}</div>`).join('')}</div>`;

  const head = `<div class="spread"><h2 style="margin:0">${esc(m.p1Name || 'TBD')} <span class="muted">vs</span> ${esc(m.p2Name || 'TBD')}</h2>
    <span class="badge">${m.status === 'done' ? 'finished' : `game round ${m.gameRound}`}</span></div>
    ${m.deadline && m.status !== 'done' ? `<p class="small muted" style="margin:6px 0 0">${m.status === 'reveal' ? 'Reveal' : 'Commit'} deadline in <span class="mono" data-deadline="${m.deadline}">${countdown(m.deadline)}</span></p>` : ''}`;

  let body = '';
  if (!amIn) {
    body = `<p class="muted small">You are spectating. Click any match in the bracket to inspect its commitments.</p>`;
  } else if (m.status === 'pending') {
    body = '<p class="muted">Waiting for the previous round to finish.</p>';
  } else if (m.status === 'commit' && !mine) {
    const preview = ui.selected ? C.commitMove(ui.selected) : null;
    body = `
      <p class="small muted">Pick a move. When you seal it, your browser computes the commitment, a zero-knowledge proof and a signature. The server receives only those — never your move.</p>
      <div class="moves" data-tour="moves">${['rock', 'paper', 'scissors'].map((mv) => `
        <button class="move ${ui.selected === mv ? 'sel' : ''}" data-move="${mv}" aria-pressed="${ui.selected === mv}"><span class="em">${EMOJI[mv]}</span>${mv}<small>m = ${C.MOVES[mv]}</small></button>`).join('')}</div>
      ${preview ? `<div class="formula" style="margin-top:12px" data-tour="formula">
        ${t.scheme === 'pedersen'
          ? `C = <b>m</b>·G + <i>r</i>·H &nbsp; with <b>m = ${preview.m}</b> (${preview.move}), <i>r</i> = fresh 252-bit random blinding factor`
          : `C = SHA-256( context ‖ <b>${preview.move}</b> ‖ <i>salt</i> ) &nbsp; with a fresh 256-bit <i>salt</i>`}
      </div>` : ''}
      <div class="row" style="margin-top:14px"><button class="btn" id="seal" ${ui.selected ? '' : 'disabled'} data-tour="seal" data-tip="Computes the commitment locally, proves you know its opening, signs it, and sends only the sealed value to the referee.">🔒 Seal my move</button></div>`;
  } else {
    body = sealedView(t, m, me, mine, opp, secret, names);
  }

  const history = m.moves.length ? historyView(t, m, names) : '';
  return head + (amIn ? phaseBar : '') + body + history;
}

function sealedView(t, m, me, mine, opp, secret, names) {
  const vOpp = opp ? verifyMove(t, m, opp) : null;
  const local = ui.lastLocal && ui.lastLocal.matchId === m.id && ui.lastLocal.round === m.gameRound ? ui.lastLocal : null;
  const myCard = `
    <div class="card tight" style="background:var(--panel-2)">
      <div class="spread"><strong>Your seal</strong>${mine?.move ? `<span class="badge open">opened</span>` : mine ? `<span class="badge seal">sealed</span>` : ''}</div>
      ${mine ? `<dl class="kv" style="margin-top:8px">
        <dt>Commitment C</dt><dd>${hex(mine.commitment)}</dd>
        ${mine.proof ? `<dt>Proof T ${info('Okamoto proof of knowledge: T = aG + bH, s₁ = a + c·m, s₂ = b + c·r with c = SHA-512(context, G, H, C, T). Proves you know (m, r) without revealing them, and is bound to your player id.')}</dt><dd>${hex(mine.proof.T)}</dd><dt>s₁, s₂</dt><dd>${hex(mine.proof.s1, 6)} ${hex(mine.proof.s2, 6)}</dd>` : ''}
        <dt>Signature</dt><dd>${hex(mine.commitSig)}</dd>
        <dt>Secret (kept in this browser)</dt><dd>${secret ? `${EMOJI[secret.move]} ${esc(secret.move)} · ${t.scheme === 'pedersen' ? 'r' : 'salt'} = ${hex(secret.opening, 6)}` : mine.move ? `${EMOJI[mine.move]} ${esc(mine.move)}` : '<span class="muted">not on this device</span>'}</dd>
        ${local ? `<dt>Client crypto time</dt><dd class="mono">${local.ms.toFixed(1)} ms · ${local.bytes} bytes sent</dd>` : ''}
      </dl>` : '<p class="muted small">You have not sealed a move this round.</p>'}
    </div>`;
  const oppCard = `
    <div class="card tight" style="background:var(--panel-2)" data-tour="oppcheck">
      <div class="spread"><strong>${esc(names[opp?.playerId] || 'Opponent')}'s seal</strong>${opp?.move ? `<span class="badge open">opened</span>` : opp ? `<span class="badge seal">sealed</span>` : '<span class="badge pulse">waiting…</span>'}</div>
      ${opp ? `<dl class="kv" style="margin-top:8px"><dt>Commitment C</dt><dd>${hex(opp.commitment)}</dd><dt>Signed by</dt><dd>${hex(opp.publicKey, 8)}</dd></dl>
      <p class="small" style="margin:10px 0 4px"><strong>Checked in your browser</strong> ${info('Your browser re-verifies everything itself instead of trusting the referee: the opponent\'s Ed25519 signature, the proof of knowledge (bound to their player id, so it cannot be a mauled copy of yours), and after reveal, that the opening matches.')}</p>
      <ul class="checks">
        <li class="${vOpp.commitOk.ok ? 'ok' : 'no'}">Ed25519 signature on commitment</li>
        ${t.scheme === 'pedersen' ? `<li class="${vOpp.commitOk.ok ? 'ok' : 'no'}">Proof of knowledge of opening (non-malleable)</li>` : ''}
        <li class="${opp.commitment !== mine?.commitment ? 'ok' : 'no'}">Not a copy of your commitment</li>
        <li class="${vOpp.revealOk ? (vOpp.revealOk.ok ? 'ok' : 'no') : 'wait'}">${vOpp.revealOk ? `Opening matches commitment → ${EMOJI[opp.move]} ${esc(opp.move)}` : 'Opening (after reveal)'}</li>
      </ul>` : '<p class="muted small">Their commitment will appear here. You cannot see their move until they open it — and they cannot see yours.</p>'}
    </div>`;

  let action = '';
  if (m.status === 'commit' && mine) action = `<div class="callout" style="margin-top:14px">Sealed. Waiting for your opponent to commit. Even if they could read the server's database, they would learn nothing about your move.</div>`;
  if (m.status === 'reveal' && mine && !mine.move) action = `
    <div class="callout open" style="margin-top:14px" data-tour="reveal">
      <div class="spread"><span>Both moves are sealed. Open yours by publishing <span class="mono">(move, ${t.scheme === 'pedersen' ? 'r' : 'salt'})</span>.</span>
      <div class="row"><label class="small row" style="gap:4px" data-tip="Reveal automatically after your browser has verified the opponent's commitment"><input type="checkbox" id="auto" ${ui.autoReveal ? 'checked' : ''}/> auto</label>
      <button class="btn open" id="reveal" ${secret ? '' : 'disabled'}>🔓 Reveal</button></div></div>
      ${secret ? '' : '<p class="small" style="margin:6px 0 0;color:var(--bad)">The opening for this commitment is not stored on this device, so it cannot be revealed from here.</p>'}
    </div>`;
  if (m.status === 'reveal' && mine?.move) action = `<div class="callout" style="margin-top:14px">Revealed. Waiting for the opponent to open their seal — if they refuse, they forfeit when the deadline expires.</div>`;
  if (m.status === 'done') {
    const won = m.winner === me.playerId;
    action = `<div class="callout ${won ? 'open' : 'bad'} reveal-anim" style="margin-top:14px"><strong>${won ? 'You won this match! 🎉' : 'You lost this match.'}</strong> <span class="muted">${esc(m.resultReason || '')}</span></div>`;
  }
  return `<div class="grid" style="gap:12px">${myCard}${oppCard}</div>${action}`;
}

function historyView(t, m, names) {
  const rounds = [...new Set(m.moves.map((x) => x.gameRound))];
  return `<details style="margin-top:16px" ${m.status === 'done' ? 'open' : ''}><summary>Round history &amp; local verification (${rounds.length})</summary>
    <div class="tablewrap"><table style="margin-top:8px"><thead><tr><th>Rnd</th><th>Player</th><th>Commitment</th><th>Move</th><th>Verified</th></tr></thead><tbody>
    ${m.moves.map((mv) => { const v = verifyMove(t, m, mv); const ok = v.commitOk.ok && (!v.revealOk || v.revealOk.ok);
      return `<tr><td>${mv.gameRound}</td><td>${esc(names[mv.playerId] || mv.playerId)}</td><td>${hex(mv.commitment, 8)}</td><td>${mv.move ? `${EMOJI[mv.move]} ${esc(mv.move)}` : '<span class="muted">sealed</span>'}</td><td>${ok ? '<span class="badge good">✓</span>' : `<span class="badge bad" data-tip="${esc(v.commitOk.reason || v.revealOk?.reason)}">✗</span>`}</td></tr>`; }).join('')}
    </tbody></table></div></details>`;
}

// ------------------------------------------------------------------ actions
async function doCommit(t, m) {
  const me = store.identity;
  if (!ui.selected || ui.busy) return;
  ui.busy = true;
  try {
    const ctx = ctxFor(t, m, me.playerId);
    const t0 = performance.now();
    const b = C.buildCommit({ move: ui.selected, scheme: t.scheme, ctx, secretKey: me.secretKey });
    const ms = performance.now() - t0;
    // Persist the opening BEFORE sending, so a crash/refresh can never strand a commitment.
    store.saveSecret(m.id, m.gameRound, b.secret);
    await api(`/api/matches/${m.id}/commit`, { method: 'POST', body: b.public });
    ui.lastLocal = { matchId: m.id, round: m.gameRound, ms, bytes: JSON.stringify(b.public).length };
    ui.selected = null;
    toast('Move sealed 🔒');
  } catch (e) { toast(e.message, true); }
  finally { ui.busy = false; }
}

async function doReveal(t, m) {
  const me = store.identity;
  if (ui.busy) return;
  const secret = store.secret(m.id, m.gameRound);
  const mine = m.moves.find((x) => x.gameRound === m.gameRound && x.playerId === me.playerId);
  const opp = m.moves.find((x) => x.gameRound === m.gameRound && x.playerId !== me.playerId);
  if (!secret || !mine || mine.move) return;
  // Never reveal before verifying the opponent's sealed commitment ourselves.
  if (!opp || !verifyMove(t, m, opp).commitOk.ok) { toast('Opponent commitment failed local verification — not revealing', true); return; }
  ui.busy = true;
  try {
    const ctx = ctxFor(t, m, me.playerId);
    const rv = C.buildReveal({ ctx, scheme: t.scheme, commitment: mine.commitment, ...secret, secretKey: me.secretKey });
    await api(`/api/matches/${m.id}/reveal`, { method: 'POST', body: rv });
    toast('Move revealed 🔓');
  } catch (e) { toast(e.message, true); }
  finally { ui.busy = false; }
}
