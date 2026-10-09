package sqlite

import (
	"context"
	"testing"
	"time"

	"VulnDock/internal/domain"
)

func TestRestoreFromBackupRollsBackOnFailure(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	seed := domain.Report{
		ID:        "keep-me",
		Title:     "seed",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := store.InsertReportImport(ctx, seed, nil); err != nil {
		t.Fatal(err)
	}

	oversized := make([]byte, domain.MaxPocFileBytes+1)
	bad := []domain.Report{{
		ID:        "bad",
		Title:     "bad",
		CreatedAt: seed.CreatedAt,
		UpdatedAt: seed.UpdatedAt,
		PocFiles: []domain.PocFile{{
			ID:   "f1",
			Name: "big.bin",
			Path: domain.LegacyDisplayPath("f1", "big.bin"),
		}},
	}}
	attachments := map[string][]byte{
		domain.LegacyDisplayPath("f1", "big.bin"): oversized,
		"f1": oversized,
	}

	if err := store.RestoreFromBackup(ctx, bad, attachments, nil); err == nil {
		t.Fatal("expected restore to fail on oversized attachment")
	}

	count, err := store.ReportCount(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected seed report to remain, count=%d", count)
	}
}
