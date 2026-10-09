package sqlite

import (
	"context"
	"strings"

	"VulnDock/internal/domain"
)

func (s *Store) RestoreFromBackup(ctx context.Context, reports []domain.Report, attachments map[string][]byte) error {
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
	return tx.Commit()
}
