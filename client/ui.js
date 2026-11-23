// Small UI helpers: escaping, toasts, tooltips, hex chips.
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function hex(h, n = 10) {
  if (!h) return '<span class="muted">—</span>';
  const s = String(h);
  const short = s.length > n * 2 ? `${s.slice(0, n)}…${s.slice(-6)}` : s;
  return `<span class="hex" data-copy="${esc(s)}" data-tip="${esc(s)} — click to copy">${esc(short)}</span>`;
}
export const info = (text) => `<span class="info" tabindex="0" data-tip="${esc(text)}">?</span>`;
export const EMOJI = { rock: '✊', paper: '✋', scissors: '✌️' };

let toastTimer;
export function toast(msg, bad = false) {
  const el = $('#toast');
  el.textContent = msg; el.className = 'show' + (bad ? ' bad' : '');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (el.className = ''), 3200);
}

// ---------- tooltips: any element with data-tip
const tipEl = document.createElement('div');
tipEl.className = 'tip'; tipEl.setAttribute('role', 'tooltip');
if (document.body) document.body.appendChild(tipEl); else document.addEventListener('DOMContentLoaded', () => document.body.appendChild(tipEl));
function showTip(target) {
  const text = target.getAttribute('data-tip');
  if (!text) return;
  tipEl.textContent = text;
  const r = target.getBoundingClientRect();
  tipEl.classList.add('show');
  const w = tipEl.offsetWidth, h = tipEl.offsetHeight;
  let x = Math.min(window.innerWidth - w - 8, Math.max(8, r.left + r.width / 2 - w / 2));
  let y = r.top - h - 8; if (y < 8) y = r.bottom + 8;
  tipEl.style.left = x + 'px'; tipEl.style.top = y + 'px';
}
const hideTip = () => tipEl.classList.remove('show');
document.addEventListener('mouseover', (e) => { const t = e.target.closest('[data-tip]'); t ? showTip(t) : hideTip(); });
document.addEventListener('focusin', (e) => { const t = e.target.closest('[data-tip]'); if (t) showTip(t); });
document.addEventListener('focusout', hideTip);
document.addEventListener('scroll', hideTip, true);
document.addEventListener('click', async (e) => {
  const c = e.target.closest('[data-copy]');
  if (!c) return;
  try { await navigator.clipboard.writeText(c.dataset.copy); toast('Copied to clipboard'); } catch { /* ignore */ }
});

export function fmtTime(ts) { return new Date(ts).toLocaleTimeString(); }
export function countdown(deadline) {
  if (!deadline) return '';
  const s = Math.max(0, Math.round((deadline - Date.now()) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}
