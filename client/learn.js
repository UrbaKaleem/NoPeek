// "How it works": protocol explanation with diagrams.
import * as C from '../shared/crypto.js';
import { hex, info } from './ui.js';

export function renderLearn(root) {
  root.innerHTML = `
    <h1>How CommitRPS works</h1>
    <p class="muted" style="max-width:78ch">In a normal online rock-paper-scissors game, whoever moves second can just look at the first move. A <strong>commitment scheme</strong> fixes this. It works like a sealed envelope: you can't see inside (<em>hiding</em>), and once it's sealed you can't swap the contents (<em>binding</em>).</p>

    <div class="grid g3" style="margin:18px 0">
      <div class="card"><h2><span class="badge seal">1</span> Commit</h2><p class="small">Pick a move <span class="mono">m ∈ {1,2,3}</span> and a fresh random scalar <span class="mono">r</span>. Publish</p>
        <div class="formula">C = <b>m</b>·G + <i>r</i>·H</div>
        <p class="small muted" style="margin-top:8px">plus a zero-knowledge proof that you know (m, r), and an Ed25519 signature.</p></div>
      <div class="card"><h2><span class="badge">2</span> Wait</h2><p class="small">The referee moves to the reveal phase only after <em>both</em> commitments are recorded. Each browser checks the opponent's signature and proof itself.</p></div>
      <div class="card"><h2><span class="badge open">3</span> Reveal &amp; verify</h2><p class="small">Publish <span class="mono">(m, r)</span>. Everyone recomputes <span class="mono">m·G + r·H</span> and checks that it equals C. A mismatch is signed proof of cheating, so the cheater forfeits.</p></div>
    </div>

    <div class="card" style="margin-bottom:18px"><h2>Protocol sequence</h2>
      <img class="seq" src="/img/sequence.svg" alt="Sequence diagram of the commit-reveal protocol between Alice, the referee and Bob" />
    </div>

    <div class="grid g2">
      <div class="card"><h2>Why Pedersen is the right envelope</h2>
        <ul class="small">
          <li><strong>Perfectly hiding.</strong> For a uniformly random r, C is a uniformly random group element whatever m is. Even an attacker with unlimited computing power learns nothing about your move.</li>
          <li><strong>Computationally binding.</strong> Opening C to two different moves would reveal <span class="mono">log_G(H)</span>, which means solving the discrete-log problem on ristretto255 (~2¹²⁶ work).</li>
          <li><strong>Nothing up our sleeve.</strong> H = hash_to_curve("${C.H_SEED}") ${info('RFC 9380 hash-to-curve maps a string to a curve point in a way that nobody can choose. So nobody, including us, knows a t with H = t·G. If someone did, they could open any commitment to any move.')}<br>H = ${hex(C.H.toHex())}</li>
          <li><strong>Prime-order group.</strong> ristretto255 avoids the cofactor pitfalls of raw Ed25519 points, so every 32-byte encoding is a unique, valid group element.</li>
        </ul></div>
      <div class="card"><h2>What we added on top</h2>
        <ul class="small">
          <li><strong>Proof of knowledge of opening</strong> (Okamoto Σ-protocol + Fiat–Shamir) bound to (tournament, match, round, player). This stops the copy-cat attack C′ = C + G that plain Pedersen allows. Try it in the <a href="#/lab">Attack Lab</a>.</li>
          <li><strong>Ed25519 signatures</strong> on every commit and reveal, so the referee can't alter or invent moves.</li>
          <li><strong>Reveal deadline.</strong> Refusing to open your commitment after seeing the opponent's means you forfeit.</li>
          <li><strong>Hash-chained audit log</strong> that anyone can re-verify in the <a href="#/inspector">Inspector</a>.</li>
          <li><strong>Salted hash mode</strong>, SHA-256(ctx ‖ move ‖ 256-bit salt): the scheme described in the project brief, kept for comparison.</li>
        </ul></div>
    </div>

    <div class="card" style="margin-top:18px"><h2>System architecture &amp; trust boundaries</h2>
      <img class="seq" src="/img/architecture.svg" alt="Architecture diagram showing browser clients, the untrusted referee server, database and audit log" />
    </div>`;
}
