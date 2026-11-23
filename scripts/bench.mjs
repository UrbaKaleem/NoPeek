// Node benchmark of every crypto operation + payload sizes (same code as the browser).
import { writeFileSync, mkdirSync } from 'node:fs';
import { benchSuite } from '../client/bench-core.js';
const r = benchSuite(1000);
mkdirSync('docs/results', { recursive: true });
writeFileSync('docs/results/bench.json', JSON.stringify({ node: process.version, ...r }, null, 2));
console.table(r.rows.map((x) => ({ op: x.name, 'ops/s': x.opsPerSec, 'ms/op': +x.msPerOp.toFixed(3) })));
console.log(r.sizes);
