package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *Store) CreateSession(ctx context.Context, id, csrf, expiresAt, lastSeenAt string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions(id, csrf_token, expires_at, last_seen_at) VALUES (?,?,?,?)
	`, id, csrf, expiresAt, lastSeenAt)
	return err
}

func (s *Store) GetSession(ctx context.Context, id string) (csrf string, expiresAt string, lastSeenAt string, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT csrf_token, expires_at, last_seen_at FROM sessions WHERE id = ?
	`, id).Scan(&csrf, &expiresAt, &lastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", errors.New("session not found")
	}
	return csrf, expiresAt, lastSeenAt, err
}

func (s *Store) UpdateSessionActivity(ctx context.Context, id, expiresAt, lastSeenAt string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET expires_at = ?, last_seen_at = ? WHERE id = ?
	`, expiresAt, lastSeenAt, id)
	return err
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteAllSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions`)
	return err
}

func ParseRFC3339(value string) (time.Time, error) {
	return time.Parse(time.RFC3339, value)
}
