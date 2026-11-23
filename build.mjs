// Bundles the browser client (with @noble crypto) into public/.
import { build } from 'esbuild';
import { cpSync, mkdirSync } from 'node:fs';
mkdirSync('public/img', { recursive: true });
await build({ entryPoints: ['client/main.js'], bundle: true, format: 'esm', minify: true, sourcemap: true, target: ['es2022'], outfile: 'public/app.js', logLevel: 'info' });
cpSync('client/index.html', 'public/index.html');
cpSync('client/styles.css', 'public/styles.css');
cpSync('docs/diagrams/sequence.svg', 'public/img/sequence.svg');
cpSync('docs/diagrams/architecture.svg', 'public/img/architecture.svg');
