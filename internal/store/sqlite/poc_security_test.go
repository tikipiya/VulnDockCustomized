package sqlite

import (
	"context"
	"testing"

	"VulnDock/internal/domain"
)

func TestUpsertPocBlobRejectsCrossReportIDReuse(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	reportA := domain.Report{ID: domain.NewReportID(), Title: "A", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"}
	reportB := domain.Report{ID: domain.NewReportID(), Title: "B", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"}
	domain.EnsureReportSlices(&reportA)
	domain.EnsureReportSlices(&reportB)
	if err := store.SaveReport(ctx, reportA); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveReport(ctx, reportB); err != nil {
		t.Fatal(err)
	}

	fileID := domain.NewAttachmentID()
	if err := store.UpsertPocBlob(ctx, reportA.ID, domain.PocFile{ID: fileID, Name: "a.txt", Type: "text/plain"}, []byte("original")); err != nil {
		t.Fatal(err)
	}

	err = store.UpsertPocBlob(ctx, reportB.ID, domain.PocFile{ID: fileID, Name: "evil.txt", Type: "text/plain"}, []byte("tampered"))
	if err == nil {
		t.Fatal("expected cross-report attachment reuse to fail")
	}

	content, name, _, err := store.PocContent(ctx, reportA.ID, fileID)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "original" || name != "a.txt" {
		t.Fatalf("report A attachment was modified: %q %q", name, content)
	}
}
