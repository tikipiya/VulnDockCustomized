package service

import (
	"context"
	"fmt"
	"sync"

	"VulnDock/internal/backup"
	"VulnDock/internal/domain"
	"VulnDock/internal/store/sqlite"
)

type Backup struct {
	Store     *sqlite.Store
	restoreMu sync.Mutex
}

func (s *Backup) Export(ctx context.Context, password string) (backup.Result, error) {
	reports, err := s.Store.ListReports(ctx, false)
	if err != nil {
		return backup.Result{}, err
	}
	reportByFileID := map[string]string{}
	for _, report := range reports {
		for _, file := range report.PocFiles {
			if file.ID != "" {
				reportByFileID[file.ID] = report.ID
			}
		}
	}
	prompts, err := s.Store.ListSavedPrompts(ctx)
	if err != nil {
		return backup.Result{}, err
	}
	return backup.ExportZip(reports, prompts, func(file domain.PocFile) ([]byte, error) {
		reportID := reportByFileID[file.ID]
		if reportID == "" {
			return nil, domainError("attachment report not found")
		}
		content, _, _, err := s.Store.PocContent(ctx, reportID, file.ID)
		return content, err
	}, password)
}

func (s *Backup) Restore(ctx context.Context, archive []byte, password string) ([]domain.Report, error) {
	s.restoreMu.Lock()
	defer s.restoreMu.Unlock()

	imported, err := backup.ImportZip(archive, password)
	if err != nil {
		return nil, err
	}
	reports := imported.Reports
	attachments := imported.Attachments
	for _, report := range reports {
		if err := domain.ValidatePocFileMetadata(report.PocFiles); err != nil {
			return nil, err
		}
	}
	if err := validateRestoreAttachments(reports, attachments); err != nil {
		return nil, err
	}
	if err := validateRestorePrompts(imported.Prompts); err != nil {
		return nil, err
	}
	if err := s.Store.RestoreFromBackup(ctx, reports, attachments, imported.Prompts); err != nil {
		return nil, err
	}
	return s.Store.ListReports(ctx, false)
}

func validateRestoreAttachments(reports []domain.Report, attachments map[string][]byte) error {
	for _, report := range reports {
		for _, file := range report.PocFiles {
			content := attachments[file.ID]
			if content == nil && file.Path != "" {
				content = attachments[file.Path]
			}
			if content == nil {
				continue
			}
			if len(content) > domain.MaxPocFileBytes {
				return fmt.Errorf("attachment %q exceeds %d byte limit", file.Name, domain.MaxPocFileBytes)
			}
		}
	}
	return nil
}

func validateRestorePrompts(prompts []domain.SavedPrompt) error {
	for _, prompt := range prompts {
		if len(prompt.Body) > domain.MaxSavedPromptBytes {
			return fmt.Errorf("prompt %q exceeds %d byte limit", prompt.Title, domain.MaxSavedPromptBytes)
		}
	}
	return nil
}
