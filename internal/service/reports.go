package service

import (
	"context"
	"strings"
	"time"

	"VulnDock/internal/domain"
	"VulnDock/internal/store/sqlite"
)

type Reports struct {
	Store *sqlite.Store
}

func (s *Reports) List(ctx context.Context) ([]domain.Report, error) {
	return s.Store.ListReports(ctx, false)
}

func (s *Reports) ListTrash(ctx context.Context) ([]domain.Report, error) {
	all, err := s.Store.ListReports(ctx, true)
	if err != nil {
		return nil, err
	}
	trash := make([]domain.Report, 0)
	for _, report := range all {
		if strings.TrimSpace(report.DeletedAt) != "" {
			trash = append(trash, report)
		}
	}
	return trash, nil
}

func (s *Reports) Restore(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errReportIDRequired
	}
	return s.Store.RestoreReport(ctx, id)
}

func (s *Reports) Save(ctx context.Context, draft domain.ReportDraft) (domain.Report, error) {
	if err := domain.ValidateIncomingPocFiles(draft.PocFiles); err != nil {
		return domain.Report{}, err
	}
	now := time.Now().Format(time.RFC3339)
	report := domain.NormalizeDraft(draft)
	report.UpdatedAt = now

	existing, err := s.findExisting(ctx, report.ID)
	if err != nil {
		return domain.Report{}, err
	}
	if existing != nil {
		if strings.TrimSpace(existing.DeletedAt) != "" {
			return domain.Report{}, errReportInTrash
		}
		report.CreatedAt = existing.CreatedAt
		if report.CreatedAt == "" {
			report.CreatedAt = now
		}
		report.DeletedAt = existing.DeletedAt
	} else {
		if report.ID == "" {
			report.ID = domain.NewReportID()
		}
		report.CreatedAt = now
	}

	for i := range report.PocFiles {
		file := &report.PocFiles[i]
		data := strings.TrimSpace(file.Data)
		if data == "" {
			continue
		}
		contentType, content, err := domain.DecodeDataURL(data)
		if err != nil {
			return domain.Report{}, err
		}
		name := domain.SanitizeAttachmentName(file.Name)
		if file.ID == "" {
			file.ID = domain.NewAttachmentID()
		}
		file.Name = name
		if strings.TrimSpace(file.Type) == "" {
			file.Type = contentType
		}
		file.Size = int64(len(content))
		file.Path = domain.LegacyDisplayPath(file.ID, name)
		if err := s.Store.UpsertPocBlob(ctx, report.ID, *file, content); err != nil {
			return domain.Report{}, err
		}
		file.Data = ""
	}

	if err := domain.ValidatePocFileMetadata(report.PocFiles); err != nil {
		return domain.Report{}, err
	}
	if err := s.Store.SaveReport(ctx, report); err != nil {
		return domain.Report{}, err
	}
	domain.EnsureReportSlices(&report)
	return report, nil
}

func (s *Reports) findExisting(ctx context.Context, id string) (*domain.Report, error) {
	if strings.TrimSpace(id) == "" {
		return nil, nil
	}
	reports, err := s.Store.ListReports(ctx, true)
	if err != nil {
		return nil, err
	}
	for _, r := range reports {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, nil
}

func (s *Reports) Delete(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errReportIDRequired
	}
	now := time.Now().Format(time.RFC3339)
	return s.Store.SoftDeleteReport(ctx, id, now)
}

func (s *Reports) PurgeExpired(ctx context.Context) error {
	cutoff := time.Now().AddDate(0, 0, -domain.SoftDeleteRetentionDays)
	return s.Store.PurgeDeletedBefore(ctx, cutoff)
}

var errReportIDRequired = domainError("report id is required")
var errReportInTrash = domainError("report is in trash; restore it before editing")

type domainError string

func (e domainError) Error() string { return string(e) }
