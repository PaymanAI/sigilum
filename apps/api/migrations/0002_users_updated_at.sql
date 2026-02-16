-- Add updated_at column to users table.
ALTER TABLE users ADD COLUMN updated_at TEXT;

-- Backfill existing rows with their created_at value.
UPDATE users SET updated_at = created_at WHERE updated_at IS NULL;
