PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY NOT NULL,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY NOT NULL,
  csrf_token TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY NOT NULL,
  title TEXT NOT NULL,
  program TEXT NOT NULL DEFAULT '',
  asset TEXT NOT NULL DEFAULT '',
  cvss_version TEXT NOT NULL DEFAULT '3.1',
  cvss_score TEXT NOT NULL DEFAULT '',
  cvss_vector TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Draft',
  submitted_at TEXT NOT NULL DEFAULT '',
  next_action_at TEXT NOT NULL DEFAULT '',
  reward_status TEXT NOT NULL DEFAULT 'Unknown',
  reward_amount TEXT NOT NULL DEFAULT '',
  reward_currency TEXT NOT NULL DEFAULT '',
  reward_paid_at TEXT NOT NULL DEFAULT '',
  reward_note TEXT NOT NULL DEFAULT '',
  memo TEXT NOT NULL DEFAULT '',
  report_url TEXT NOT NULL DEFAULT '',
  tags_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS conversation_logs (
  id TEXT PRIMARY KEY NOT NULL,
  report_id TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  sort_order INTEGER NOT NULL,
  from_participant TEXT NOT NULL,
  to_participant TEXT NOT NULL,
  communicated_at TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS poc_files (
  id TEXT PRIMARY KEY NOT NULL,
  report_id TEXT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  content_type TEXT NOT NULL DEFAULT '',
  size INTEGER NOT NULL DEFAULT 0,
  content BLOB NOT NULL,
  legacy_path TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS saved_prompts (
  id TEXT PRIMARY KEY NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_deleted ON reports(deleted_at);
CREATE INDEX IF NOT EXISTS idx_reports_updated ON reports(updated_at);
CREATE INDEX IF NOT EXISTS idx_saved_prompts_updated ON saved_prompts(updated_at);
