// Persistence layer: SQLite via Node's built-in node:sqlite (no native build step).
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const DB_PATH = process.env.DB_PATH || './data/commitrps.db';
if (DB_PATH !== ':memory:') mkdirSync(dirname(DB_PATH), { recursive: true });

export const db = new DatabaseSync(DB_PATH);
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS players (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  is_bot INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
-- Key lifecycle: every key a player ever used, with its status.
CREATE TABLE IF NOT EXISTS player_keys (
  public_key TEXT PRIMARY KEY,
  player_id TEXT NOT NULL REFERENCES players(id),
  status TEXT NOT NULL CHECK (status IN ('active','rotated','revoked')),
  created_at INTEGER NOT NULL,
  retired_at INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,           -- SHA-256 of the bearer token; raw token never stored
  player_id TEXT NOT NULL REFERENCES players(id),
  public_key TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
  nonce TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tournaments (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  size INTEGER NOT NULL,
  scheme TEXT NOT NULL,
  reveal_timeout INTEGER NOT NULL,
  status TEXT NOT NULL,                  -- open | running | finished
  created_by TEXT,
  winner TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tournament_players (
  tournament_id TEXT NOT NULL REFERENCES tournaments(id),
  player_id TEXT NOT NULL REFERENCES players(id),
  seed INTEGER,
  PRIMARY KEY (tournament_id, player_id)
);
CREATE TABLE IF NOT EXISTS matches (
  id TEXT PRIMARY KEY,
  tournament_id TEXT NOT NULL REFERENCES tournaments(id),
  bracket_round INTEGER NOT NULL,
  slot INTEGER NOT NULL,
  p1 TEXT, p2 TEXT,
  status TEXT NOT NULL,                  -- pending | commit | reveal | done
  game_round INTEGER NOT NULL DEFAULT 1, -- increments on ties
  deadline INTEGER,
  winner TEXT,
  result_reason TEXT
);
CREATE TABLE IF NOT EXISTS moves (
  match_id TEXT NOT NULL REFERENCES matches(id),
  game_round INTEGER NOT NULL,
  player_id TEXT NOT NULL,
  public_key TEXT NOT NULL,              -- key that signed (survives later rotation)
  scheme TEXT NOT NULL,
  commitment TEXT NOT NULL,
  proof TEXT,
  commit_sig TEXT NOT NULL,
  committed_at INTEGER NOT NULL,
  move TEXT, opening TEXT, reveal_sig TEXT, revealed_at INTEGER,
  PRIMARY KEY (match_id, game_round, player_id)
);
-- Append-only, hash-chained transparency log.
CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  type TEXT NOT NULL,
  tournament_id TEXT,
  payload TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_t ON audit_log(tournament_id);
`);

export const q = (sql) => db.prepare(sql);
let depth = 0;
const afterRollback = [];
export const onRollback = (fn) => afterRollback.push(fn);
export function tx(fn) {
  if (depth > 0) return fn(); // nested call: join the outer transaction
  depth++;
  db.exec('BEGIN IMMEDIATE');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
  finally { depth--; while (afterRollback.length) afterRollback.shift()(); }
}
