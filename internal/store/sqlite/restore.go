package sqlite

import (
	"context"
	"strings"

	"VulnDock/internal/domain"
)

func (s *Store) RestoreFromBackup(ctx context.Context, reports []domain.Report, attachments map[string][]byte, prompts []domain.SavedPrompt) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM reports`); err != nil {
		return err
	}
	for _, report := range reports {
		blobs := map[string][]byte{}
		for _, file := range report.PocFiles {
			relPath := strings.TrimSpace(file.Path)
			if relPath == "" {
				continue
			}
			if content, ok := attachments[relPath]; ok {
				blobs[file.ID] = content
				blobs[relPath] = content
			}
		}
		report.DeletedAt = ""
		if err := s.saveReportInTx(ctx, tx, report); err != nil {
			return err
		}
		for _, file := range report.PocFiles {
			content := blobs[file.ID]
			if content == nil && file.Path != "" {
				content = blobs[file.Path]
			}
			if content == nil {
				continue
			}
			if err := s.upsertPocBlob(ctx, tx, report.ID, file, content); err != nil {
				return err
			}
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM saved_prompts`); err != nil {
		return err
	}
	for _, prompt := range prompts {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO saved_prompts(id, title, body, created_at, updated_at)
			VALUES (?,?,?,?,?)
		`, prompt.ID, prompt.Title, prompt.Body, prompt.CreatedAt, prompt.UpdatedAt); err != nil {
			return err
		}
	}

	return tx.Commit()
}
