PRAGMA foreign_keys = ON;
CREATE TABLE share_fetches (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
 fetched_at INTEGER NOT NULL,
 ip TEXT
);
CREATE INDEX share_fetches_share_id_id ON share_fetches(share_id, id DESC);
