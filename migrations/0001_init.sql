PRAGMA foreign_keys = ON;
CREATE TABLE admins (id INTEGER PRIMARY KEY CHECK(id = 1), pass_hash TEXT NOT NULL);
CREATE TABLE sources (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 owner TEXT NOT NULL,
 gist_id TEXT NOT NULL,
 filename TEXT NOT NULL,
 version INTEGER NOT NULL DEFAULT 1,
 last_ok INTEGER,
 last_error TEXT
);
CREATE TABLE shares (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE RESTRICT,
 label TEXT NOT NULL,
 slug TEXT NOT NULL UNIQUE,
 filename TEXT NOT NULL,
 token_hash BLOB NOT NULL,
 token_ciphertext TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1,
 expires_at INTEGER,
 last_access INTEGER,
 access_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE sessions (
 token_hash BLOB PRIMARY KEY,
 csrf TEXT NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE settings (id INTEGER PRIMARY KEY CHECK(id = 1), base_url TEXT NOT NULL, cache_ttl_secs INTEGER NOT NULL DEFAULT 60);
