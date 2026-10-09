package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"VulnDock/internal/domain"
)

func (s *Store) ListSavedPrompts(ctx context.Context) ([]domain.SavedPrompt, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, title, body, created_at, updated_at
		FROM saved_prompts
		ORDER BY updated_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var prompts []domain.SavedPrompt
	for rows.Next() {
		var p domain.SavedPrompt
		if err := rows.Scan(&p.ID, &p.Title, &p.Body, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		prompts = append(prompts, p)
	}
	return prompts, rows.Err()
}

func (s *Store) GetSavedPrompt(ctx context.Context, id string) (domain.SavedPrompt, error) {
	var p domain.SavedPrompt
	err := s.db.QueryRowContext(ctx, `
		SELECT id, title, body, created_at, updated_at FROM saved_prompts WHERE id = ?
	`, id).Scan(&p.ID, &p.Title, &p.Body, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.SavedPrompt{}, errors.New("prompt not found")
	}
	return p, err
}

func (s *Store) SaveSavedPrompt(ctx context.Context, prompt domain.SavedPrompt) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO saved_prompts(id, title, body, created_at, updated_at)
		VALUES (?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			title = excluded.title,
			body = excluded.body,
			updated_at = excluded.updated_at
	`, prompt.ID, prompt.Title, prompt.Body, prompt.CreatedAt, prompt.UpdatedAt)
	return err
}

func (s *Store) DeleteSavedPrompt(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM saved_prompts WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("prompt not found")
	}
	return nil
}
