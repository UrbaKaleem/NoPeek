// Parameter sweeps for the report: attacker cost vs entropy (salt bits / blinding bits).
import { writeFileSync } from 'node:fs';
import { attackHashBruteforce, attackWeakRng } from '../shared/attacks.js';
const salt = [], rng = [];
for (let b = 4; b <= 16; b += 2) {
  const runs = [1, 2, 3].map(() => attackHashBruteforce({ saltBits: b }).log[1]);
  salt.push({ bits: b, guesses: Math.round(runs.reduce((s, x) => s + x.guesses, 0) / 3), ms: +(runs.reduce((s, x) => s + x.ms, 0) / 3).toFixed(2) });
}
for (let b = 4; b <= 14; b += 2) {
  const runs = [1, 2, 3].map(() => attackWeakRng({ bits: b }).vulnerable);
  rng.push({ bits: b, tries: Math.round(runs.reduce((s, x) => s + x.tries, 0) / 3), ms: +(runs.reduce((s, x) => s + x.ms, 0) / 3).toFixed(2) });
}
writeFileSync('docs/results/sweep.json', JSON.stringify({ salt, rng }, null, 2));
console.log(salt, rng);
