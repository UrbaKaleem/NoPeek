// Guided walkthrough: highlights [data-tour] elements one after another.
import { esc } from './ui.js';

const TOURS = {
  home: [
    { sel: null, title: 'Welcome to CommitRPS', body: 'A rock-paper-scissors tournament where moves are sealed with cryptographic commitments, so nobody can wait to see your move and then pick theirs. This tour takes about a minute.' },
    { sel: '[data-tour=identity]', title: '1. Your key is your identity', body: 'Your browser generates an Ed25519 signing key. The private half stays in this browser. Every move you send is signed, so the server can neither impersonate you nor change your moves.' },
    { sel: '[data-tour=create]', title: '2. Start a tournament', body: 'Choose 2, 4 or 8 players and a commitment scheme. Pedersen is the main scheme; the salted hash is there for comparison. Playing alone? Fill the empty seats with honest bots.' },
    { sel: '#quick', title: 'Fastest way to try it', body: '“Quick match vs bot” sets up a 2-player game in one click and takes you straight to the match screen.' },
    { sel: '[data-nav=learn]', title: 'Commit → Reveal in a nutshell', body: 'Round 1: everyone publishes C = m·G + r·H. Round 2: everyone publishes (m, r) and all browsers check that it matches C. “How it works” has the full protocol diagram.' },
    { sel: '[data-nav=lab]', title: 'Try to cheat', body: 'The Attack Lab runs eight real attacks (brute-forcing weak salts, mauling Pedersen commitments, trapdoor generators, weak RNG, timing leaks, selective abort and more) against weakened and shipped settings.' },
    { sel: '[data-nav=inspector]', title: 'Don’t trust us. Verify.', body: 'The Inspector downloads the hash-chained audit log and re-checks every signature, proof and opening in your browser.' },
  ],
  match: [
    { sel: '[data-tour=phases]', title: 'The five phases', body: 'Choose → Seal (commit) → Wait for the opponent’s seal → Reveal → Verify. The referee only moves to Reveal once both seals are in.' },
    { sel: '[data-tour=moves]', title: 'Pick a move', body: 'Each move maps to a number m: rock = 1, paper = 2, scissors = 3.' },
    { sel: '[data-tour=formula]', title: 'What sealing computes', body: 'C = m·G + r·H on the ristretto255 curve. G is the standard base point. H is derived by hashing a public string, so nobody knows log_G(H). r is a fresh random 252-bit scalar.' },
    { sel: '[data-tour=seal]', title: 'Seal it', body: 'Your browser also builds a zero-knowledge proof that you know (m, r), bound to your player id, and signs everything with your key. The opening (m, r) is saved locally until you reveal.' },
    { sel: '[data-tour=oppcheck]', title: 'Verify, don’t trust', body: 'When the opponent’s seal arrives, your browser checks their signature and proof itself. After they reveal, it checks that their opening really matches what they committed.' },
    { sel: '[data-tour=bracket]', title: 'Bracket', body: 'Winners advance automatically. A tie replays the round with fresh commitments. Click any match to inspect it.' },
  ],
};

let state = null;
export function startTour(name = 'home') {
  const steps = TOURS[name].filter((s) => !s.sel || document.querySelector(s.sel));
  if (!steps.length) return;
  endTour();
  state = { steps, i: 0, name };
  const ring = document.createElement('div'); ring.className = 'tour-ring';
  const box = document.createElement('div'); box.className = 'tour-box'; box.setAttribute('role', 'dialog'); box.setAttribute('aria-modal', 'true');
  document.body.append(ring, box);
  state.ring = ring; state.box = box;
  state.onKey = (e) => { if (e.key === 'Escape') endTour(); if (e.key === 'ArrowRight') step(1); if (e.key === 'ArrowLeft') step(-1); };
  state.onResize = () => show();
  document.addEventListener('keydown', state.onKey);
  window.addEventListener('resize', state.onResize);
  show();
}
function step(d) {
  if (!state) return;
  state.i += d;
  if (state.i >= state.steps.length) { localStorage.setItem(`commitrps.tour.${state.name}`, 'done'); return endTour(); }
  state.i = Math.max(0, state.i); show();
}
function show() {
  const s = state.steps[state.i];
  const el = s.sel && document.querySelector(s.sel);
  const { ring, box } = state;
  if (el) {
    el.scrollIntoView({ block: 'center', behavior: 'smooth' });
    setTimeout(() => {
      if (!state) return;
      const r = el.getBoundingClientRect();
      Object.assign(ring.style, { display: 'block', left: r.left - 6 + 'px', top: r.top - 6 + 'px', width: r.width + 12 + 'px', height: r.height + 12 + 'px' });
      const bw = box.offsetWidth, bh = box.offsetHeight;
      let y = r.bottom + 14; if (y + bh > innerHeight - 10) y = Math.max(10, r.top - bh - 14);
      const x = Math.min(innerWidth - bw - 12, Math.max(12, r.left));
      Object.assign(box.style, { left: x + 'px', top: y + 'px' });
    }, 260);
  } else {
    Object.assign(ring.style, { left: '50%', top: '40%', width: '0px', height: '0px' });
    Object.assign(box.style, { left: `calc(50% - ${Math.min(180, innerWidth / 2 - 12)}px)`, top: '30%' });
  }
  box.innerHTML = `<h3>${esc(s.title)}</h3><p>${esc(s.body)}</p>
    <div class="row"><span class="small muted">${state.i + 1} / ${state.steps.length}</span>
    <span class="row"><button class="btn ghost small" data-t="skip">Skip</button>${state.i ? '<button class="btn ghost small" data-t="back">Back</button>' : ''}
    <button class="btn small" data-t="next">${state.i === state.steps.length - 1 ? 'Done' : 'Next'}</button></span></div>`;
  box.querySelector('[data-t=next]').onclick = () => step(1);
  box.querySelector('[data-t=skip]').onclick = () => { localStorage.setItem(`commitrps.tour.${state.name}`, 'done'); endTour(); };
  const back = box.querySelector('[data-t=back]'); if (back) back.onclick = () => step(-1);
  box.querySelector('[data-t=next]').focus();
}
export function endTour() {
  if (!state) return;
  state.ring.remove(); state.box.remove();
  document.removeEventListener('keydown', state.onKey);
  window.removeEventListener('resize', state.onResize);
  state = null;
}
export function maybeAutoTour(name) {
  if (localStorage.getItem(`commitrps.tour.${name}`) || navigator.webdriver) return;
  setTimeout(() => startTour(name), 600);
}
