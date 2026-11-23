// Runs every adversary simulation from shared/attacks.js and saves the results.
import { writeFileSync, mkdirSync } from 'node:fs';
import * as A from '../shared/attacks.js';
const hr = () => Number(process.hrtime.bigint()) / 1e6;
const out = {
  A1: A.attackHashBruteforce({ saltBits: 16 }),
  A2: A.attackMalleability({ rounds: 1000 }),
  A3: A.attackReplay(),
  A4: A.attackTrapdoor(),
  A5: A.attackWeakRng({ bits: 16 }),
  A6: A.attackTiming({ hr }),
  A7: A.attackAbort({ rounds: 1000 }),
  A8: A.attackTamper(),
};
mkdirSync('docs/results', { recursive: true });
writeFileSync('docs/results/attacks.json', JSON.stringify(out, null, 2));
for (const [k, v] of Object.entries(out)) console.log(`${k} ${v.title}\n   ${v.verdict}`);
