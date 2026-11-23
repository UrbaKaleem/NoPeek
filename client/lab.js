// Attack Lab: run each adversary simulation against weakened vs shipped settings.
import * as A from '../shared/attacks.js';
import { api } from './api.js';
import { esc, $, $$, hex, toast } from './ui.js';

const yes = (b) => (b ? '<span class="badge bad">attack succeeded</span>' : '<span class="badge good">attack blocked</span>');
const pct = (n, total) => (100 * n) / total;
function bars(r, total) {
  const row = (label, n, cls) => `<div class="bar"><span>${label}</span><div class="track"><div class="fill ${cls}" style="width:${pct(n, total)}%"></div></div><span class="mono">${n}</span></div>`;
  return `<div class="bars">${row('attacker wins', r.win, 'win')}${row('attacker loses', r.loss, 'loss')}${row('tie', r.tie, 'tie')}${r.rejected !== undefined ? row('rejected', r.rejected, 'rej') : ''}${r.stalled !== undefined ? row('stalled', r.stalled, '') : ''}</div>`;
}

const CARDS = [
  { id: 'A1', title: 'Brute-force a weak hash commitment', tag: 'Hiding',
    desc: 'With only 3 possible moves, SHA-256(move) can be inverted by trying all three. A short salt only multiplies the work by 2^bits.',
    controls: '<label class="field">salt bits <input type="range" min="8" max="18" value="14" id="a1-bits"/></label> <span class="mono small" id="a1-v">14</span>',
    run: () => A.attackHashBruteforce({ saltBits: +$('#a1-bits').value }),
    show: (r) => `<p class="small">Victim's secret move: <strong>${esc(r.secret)}</strong></p>
      <div class="tablewrap"><table><thead><tr><th>Configuration</th><th class="num">Guesses</th><th class="num">Time</th><th>Result</th></tr></thead><tbody>
      ${r.log.map((x) => `<tr><td>${esc(x.label)}</td><td class="num mono">${typeof x.guesses === 'number' ? x.guesses.toLocaleString() : esc(x.guesses)}</td><td class="num mono">${x.ms != null ? x.ms + ' ms' : esc(x.note)}</td><td>${yes(x.correct)}</td></tr>`).join('')}</tbody></table></div>` },
  { id: 'A2', title: 'Malleability: copy-cat C′ = C + G', tag: 'Non-malleability',
    desc: 'Pedersen commitments are additively homomorphic. Without knowing your move, the opponent publishes C′ = C + G, which opens to (m+1, r) as soon as you reveal (m, r). Paper beats rock, scissors beats paper…',
    controls: '<label class="field">rounds <select id="a2-n"><option>100</option><option selected>300</option><option>1000</option></select></label>',
    run: () => A.attackMalleability({ rounds: +$('#a2-n').value }),
    show: (r) => `<div class="grid g2"><div><h3>Vulnerable: no proof of knowledge</h3>${bars(r.vulnerable, r.rounds)}<p class="small mono">attacker win rate ${r.vulnerable.winRate}% (fair = 33.3%)</p></div>
      <div><h3>Shipped: context-bound Okamoto PoK</h3>${bars(r.mitigated, r.rounds)}<p class="small mono">${r.mitigated.rejected}/${r.rounds} mauled commitments rejected</p></div></div>` },
  { id: 'A3', title: 'Copy / replay an opponent\'s commitment', tag: 'Context binding',
    desc: 'If a hash commitment is not tied to who made it and for which match, an attacker can submit the exact same value and later replay the victim\'s opening, forcing a draw or reusing old matches.',
    run: () => A.attackReplay(),
    show: (r) => `<ul class="checks">
      <li class="${r.vulnerable.accepted ? 'no' : 'ok'}">Without context: copied opening accepted → ${r.vulnerable.accepted ? 'attack works' : 'blocked'}</li>
      <li class="${r.mitigated.contextBoundAccepted ? 'no' : 'ok'}">With (tournament, match, round, player) in the hash: copy ${r.mitigated.contextBoundAccepted ? 'accepted' : 'rejected'}</li>
      <li class="${r.mitigated.signatureAccepted ? 'no' : 'ok'}">Victim's Ed25519 signature re-used under attacker's identity: ${r.mitigated.signatureAccepted ? 'accepted' : 'rejected'}</li></ul>` },
  { id: 'A4', title: 'Trapdoor generator H = t·G', tag: 'Binding',
    desc: 'Pedersen binding relies on nobody knowing log_G(H). If the setup secretly picked H = t·G, whoever knows t can open a commitment to any move they like.',
    run: () => A.attackTrapdoor(),
    show: (r) => `<ul class="checks"><li class="${r.vulnerable.accepted ? 'no' : 'ok'}">Bad setup: committed to <strong>rock</strong>, successfully opened as <strong>scissors</strong>: ${yes(r.vulnerable.accepted)}</li>
      <li class="${r.mitigated.accepted ? 'no' : 'ok'}">CommitRPS H (hash-to-curve of "CommitRPS/v1/pedersen/H"): same trick ${yes(r.mitigated.accepted)}</li></ul>
      <p class="small muted">H = ${hex(r.mitigated.H)}</p>` },
  { id: 'A5', title: 'Weak RNG for the blinding factor', tag: 'Randomness',
    desc: 'If r comes from Math.random() scaled to a small range, the opponent can try every (m, r) pair and read your move before you reveal.',
    controls: '<label class="field">entropy bits <input type="range" min="8" max="16" value="12" id="a5-bits"/></label> <span class="mono small" id="a5-v">12</span>',
    run: () => A.attackWeakRng({ bits: +$('#a5-bits').value }),
    show: (r) => `<p class="small">Secret move: <strong>${esc(r.secret)}</strong></p><ul class="checks">
      <li class="${r.vulnerable.correct ? 'no' : 'ok'}">Weak r: recovered <strong>${esc(r.vulnerable.recovered)}</strong> after ${r.vulnerable.tries.toLocaleString()} group operations in ${r.vulnerable.ms} ms</li>
      <li class="ok">${esc(r.mitigated.note)}</li></ul>` },
  { id: 'A6', title: 'Timing side-channel on secret comparison', tag: 'Side channel', server: true,
    desc: 'An early-exit string compare returns faster when fewer leading characters match. Measured on the server with a nanosecond clock: naive compare vs the constant-time compare CommitRPS uses for session tokens.',
    run: () => api('/api/lab/timing'),
    show: (r) => {
      const max = Math.max(...r.naive.map((x) => x.nsPerCompare), ...r.ct.map((x) => x.nsPerCompare));
      const row = (x, cls) => `<div class="bar"><span>${x.matchingPrefix} chars</span><div class="track"><div class="fill ${cls}" style="width:${(100 * x.nsPerCompare) / max}%"></div></div><span class="mono">${Math.round(x.nsPerCompare)}ns</span></div>`;
      return `<div class="grid g2"><div><h3>Naive early-exit compare</h3><div class="bars">${r.naive.map((x) => row(x, 'win')).join('')}</div><p class="small mono">full-match ÷ no-match time = ${r.naiveSpread}×</p></div>
        <div><h3>Constant-time compare</h3><div class="bars">${r.ct.map((x) => row(x, 'loss')).join('')}</div><p class="small mono">full-match ÷ no-match time = ${r.ctSpread}×</p></div></div>
        <p class="small muted">Time grows with the matching prefix for the naive version, so a secret leaks one character at a time. The constant-time version stays flat (remaining variation is measurement noise / JIT).</p>`;
    } },
  { id: 'A7', title: 'Selective abort', tag: 'Fairness',
    desc: 'Commitments cannot force anyone to open them. A cheater who reveals second sees your move and simply goes silent whenever he would lose.',
    run: () => A.attackAbort({ rounds: 300 }),
    show: (r) => `<div class="grid g2"><div><h3>No deadline</h3>${bars(r.vulnerable, r.rounds)}<p class="small muted">The cheater never loses; losing matches stall forever.</p></div>
      <div><h3>Shipped: reveal deadline → forfeit</h3>${bars(r.mitigated, r.rounds)}<p class="small muted">Aborting now counts as a loss, so it gains nothing.</p></div></div>` },
  { id: 'A8', title: 'Malicious referee swaps a commitment', tag: 'Integrity',
    desc: 'What if the server itself is dishonest and swaps your stored commitment, or invents a reveal for you?',
    run: () => A.attackTamper(),
    show: (r) => `<ul class="checks"><li class="${r.mitigated.swappedCommitmentAccepted ? 'no' : 'ok'}">Swapped commitment passes the player's signature check: ${r.mitigated.swappedCommitmentAccepted ? 'yes' : 'no'}</li>
      <li class="${r.mitigated.forgedRevealAccepted ? 'no' : 'ok'}">Forged reveal passes the signature check: ${r.mitigated.forgedRevealAccepted ? 'yes' : 'no'}</li></ul>` },
];

export function renderLab(root) {
  root.innerHTML = `
    <h1>Attack Lab</h1>
    <p class="muted" style="max-width:75ch">Each attack runs <em>live in your browser</em> (A6 runs on the server, because browser clocks are deliberately coarse) against a deliberately weakened configuration and against what CommitRPS actually ships. All code is in <span class="mono">shared/attacks.js</span>.</p>
    <div class="row" style="margin:12px 0 18px"><button class="btn" id="runall">Run all attacks</button></div>
    <div class="grid g2">${CARDS.map((c) => `
      <div class="card" id="card-${c.id}">
        <div class="spread"><h2 style="margin:0"><span class="badge bad">${c.id}</span> ${esc(c.title)}</h2><span class="badge">${esc(c.tag)}</span></div>
        <p class="small muted" style="margin-top:8px">${esc(c.desc)}</p>
        <div class="row">${c.controls || ''}<button class="btn danger small" data-run="${c.id}">Run attack</button></div>
        <div class="out" style="margin-top:12px"></div>
        <div class="verdict"></div>
      </div>`).join('')}</div>`;
  const sync = (a, b) => { const el = $(a); if (el) el.oninput = () => ($(b).textContent = el.value); };
  sync('#a1-bits', '#a1-v'); sync('#a5-bits', '#a5-v');
  const run = async (id) => {
    const c = CARDS.find((x) => x.id === id);
    const card = $(`#card-${id}`);
    const btn = card.querySelector('[data-run]');
    btn.disabled = true; card.querySelector('.out').innerHTML = '<p class="muted pulse">Running…</p>';
    await new Promise((r) => setTimeout(r, 30)); // let the UI paint
    try {
      const r = await c.run();
      card.querySelector('.out').innerHTML = c.show(r);
      card.querySelector('.verdict').innerHTML = `<div class="callout open small" style="margin-top:10px">${esc(r.verdict)}</div>`;
    } catch (e) { card.querySelector('.out').innerHTML = `<p class="small" style="color:var(--bad)">${esc(e.message)}</p>`; toast(e.message, true); }
    btn.disabled = false;
  };
  $$('[data-run]').forEach((b) => b.addEventListener('click', () => run(b.dataset.run)));
  $('#runall').onclick = async () => { for (const c of CARDS) await run(c.id); };
}
