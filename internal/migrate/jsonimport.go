package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"VulnDock/internal/domain"
	"VulnDock/internal/store/sqlite"
)

func DefaultLegacyJSONPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil || configDir == "" {
		return "", errors.New("user config dir unavailable")
	}
	return filepath.Join(configDir, "VulnDock", "reports.json"), nil
}

func ImportJSON(ctx context.Context, store *sqlite.Store, jsonPath string, force bool) error {
	count, err := store.ReportCount(ctx)
	if err != nil {
		return err
	}
	if count > 0 && !force {
		return errors.New("database already contains reports; use --force to replace import")
	}
	if count > 0 && force {
		if err := store.ClearAllReports(ctx); err != nil {
			return err
		}
	}

	content, err := os.ReadFile(jsonPath)
	if err != nil {
		return err
	}
	var stored []domain.StoredReport
	if err := json.Unmarshal(content, &stored); err != nil {
		return err
	}
	reports, _ := domain.MigrateReports(stored)

	baseDir := filepath.Dir(jsonPath)

	for _, report := range reports {
		blobs := map[string][]byte{}
		nextFiles := make([]domain.PocFile, 0, len(report.PocFiles))
		for _, file := range report.PocFiles {
			if strings.TrimSpace(file.Data) != "" {
				_, content, err := domain.DecodeDataURL(file.Data)
				if err != nil {
					return err
				}
				id := file.ID
				if id == "" {
					id = domain.NewAttachmentID()
				}
				file.ID = id
				file.Name = domain.SanitizeAttachmentName(file.Name)
				file.Path = domain.LegacyDisplayPath(id, file.Name)
				file.Size = int64(len(content))
				file.Data = ""
				blobs[id] = content
				nextFiles = append(nextFiles, file)
				continue
			}
			if file.Path == "" {
				continue
			}
			abs, err := domain.LegacyAttachmentAbsPath(baseDir, file.Path)
			if err != nil {
				return err
			}
			content, err := os.ReadFile(abs)
			if err != nil {
				return err
			}
			if file.ID == "" {
				file.ID = domain.NewAttachmentID()
			}
			file.Size = int64(len(content))
			blobs[file.ID] = content
			nextFiles = append(nextFiles, file)
		}
		report.PocFiles = nextFiles
		if err := store.InsertReportImport(ctx, report, blobs); err != nil {
			return err
		}
	}
	return nil
}
