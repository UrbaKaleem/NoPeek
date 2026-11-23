import { benchSuite } from './bench-core.js';
import { esc, $ } from './ui.js';

export function renderBench(root) {
  root.innerHTML = `
    <h1>Benchmarks &amp; trade-offs</h1>
    <p class="muted" style="max-width:75ch">How much does each security measure cost on <em>this</em> device? Runs every operation for ~250 ms using the same code the game uses.</p>
    <div class="row" style="margin:12px 0 18px"><button class="btn" id="run">Run benchmarks</button><span class="small muted" id="env"></span></div>
    <div id="out"></div>
    <div class="grid g2" style="margin-top:18px">
      <div class="card"><h2>Security vs usability</h2>
        <ul class="small">
          <li><strong>Pedersen + PoK vs plain hash.</strong> Several times slower per operation, but still a few milliseconds — far below a network round trip (~50–200 ms), so players never notice.</li>
          <li><strong>Bandwidth.</strong> The proof adds 96 bytes per commit (T, s₁, s₂). Negligible for a game, but matters for blockchains where every byte costs gas.</li>
          <li><strong>Reveal deadline.</strong> Shorter deadlines punish selective abort faster but can forfeit players on slow connections. Default 60 s, configurable 30 s – 2 min.</li>
          <li><strong>Two rounds of interaction.</strong> Commit-reveal needs two messages per player per round instead of one; it's the price of fairness without a trusted dealer.</li>
          <li><strong>Key in localStorage.</strong> No passwords, instant onboarding — but a stolen device or XSS exposes the key. Mitigated with a strict CSP, key backup/rotation/revocation.</li>
        </ul></div>
      <div class="card"><h2>Hiding vs binding</h2>
        <table><thead><tr><th></th><th>Pedersen</th><th>Salted SHA-256</th></tr></thead><tbody>
          <tr><td>Hiding</td><td><span class="badge good">perfect</span></td><td><span class="badge seal">computational</span></td></tr>
          <tr><td>Binding</td><td><span class="badge seal">computational (DLog)</span></td><td><span class="badge seal">computational (collisions)</span></td></tr>
          <tr><td>Homomorphic</td><td>yes (feature &amp; risk)</td><td>no</td></tr>
          <tr><td>Malleable</td><td>yes → needs PoK</td><td>no</td></tr>
          <tr><td>Quantum attacker</td><td>binding breaks, hiding holds</td><td>both hold (Grover only)</td></tr>
        </tbody></table></div>
    </div>`;
  $('#env').textContent = navigator.userAgent.split(') ')[0].replace('Mozilla/5.0 (', '');
  $('#run').onclick = async () => {
    $('#out').innerHTML = '<p class="muted pulse">Measuring… (about 3 s)</p>';
    await new Promise((r) => setTimeout(r, 30));
    const t0 = performance.now(); await fetch('/api/health'); const rtt = performance.now() - t0;
    const { rows, sizes } = benchSuite();
    const max = Math.max(...rows.map((r) => r.msPerOp));
    $('#out').innerHTML = `<div class="grid g2" style="align-items:start">
      <div class="card"><h2>Operation cost</h2><div class="tablewrap"><table><thead><tr><th>Operation</th><th class="num">ops/s</th><th class="num">ms/op</th><th style="width:30%"></th></tr></thead><tbody>
      ${rows.map((r) => `<tr><td>${esc(r.name)}</td><td class="num mono">${r.opsPerSec.toLocaleString()}</td><td class="num mono">${r.msPerOp.toFixed(3)}</td><td><div class="track" style="height:8px;background:var(--panel-2);border-radius:9px"><div class="fill ${r.scheme === 'pedersen' ? 'win' : r.scheme === 'hash' ? 'tie' : 'rej'}" style="height:8px;border-radius:9px;width:${Math.max(1, (100 * r.msPerOp) / max)}%"></div></div></td></tr>`).join('')}
      </tbody></table></div><p class="small muted">Network round trip to this server just now: <strong class="mono">${rtt.toFixed(1)} ms</strong></p></div>
      <div class="card"><h2>Bytes on the wire</h2><table><thead><tr><th></th><th class="num">Pedersen</th><th class="num">Hash</th></tr></thead><tbody>
      ${['commitment', 'proof', 'signature', 'opening', 'commitMsg'].map((k) => `<tr><td>${k === 'commitMsg' ? 'commit request (JSON)' : k}</td><td class="num mono">${sizes.pedersen[k]} B</td><td class="num mono">${sizes.hash[k]} B</td></tr>`).join('')}
      </tbody></table></div></div>`;
  };
}
