CREATE TABLE IF NOT EXISTS programs (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  date TEXT,
  updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS archive (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  date TEXT,
  updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS signups (
  id TEXT PRIMARY KEY,
  program_id TEXT NOT NULL,
  emp_no TEXT NOT NULL,
  org TEXT NOT NULL,
  name TEXT NOT NULL,
  answers TEXT,
  token_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER,
  UNIQUE (program_id, emp_no)
);
CREATE INDEX IF NOT EXISTS signups_program ON signups (program_id, created_at);
CREATE TABLE IF NOT EXISTS stories (
  id TEXT PRIMARY KEY,
  author TEXT,
  text TEXT NOT NULL,
  archive_id TEXT,
  photos TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL,
  ip_hash TEXT
);
CREATE INDEX IF NOT EXISTS stories_status ON stories (status, created_at);
CREATE TABLE IF NOT EXISTS ideas (
  id TEXT PRIMARY KEY,
  author TEXT,
  title TEXT NOT NULL,
  description TEXT,
  category TEXT,
  status TEXT NOT NULL DEFAULT 'new',
  created_at INTEGER NOT NULL,
  ip_hash TEXT
);
CREATE TABLE IF NOT EXISTS votes (
  idea_id TEXT NOT NULL,
  voter TEXT NOT NULL,
  created_at INTEGER,
  PRIMARY KEY (idea_id, voter)
);
CREATE TABLE IF NOT EXISTS photos (
  key TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  ip_hash TEXT
);
CREATE TABLE IF NOT EXISTS config (
  k TEXT PRIMARY KEY,
  v TEXT
);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER,
  action TEXT,
  target TEXT,
  ip_hash TEXT
);
CREATE TABLE IF NOT EXISTS rl (
  k TEXT NOT NULL,
  ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS rl_k ON rl (k, ts);
