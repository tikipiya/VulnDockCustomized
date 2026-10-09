package domain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyAttachmentAbsPathRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "outside.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LegacyAttachmentAbsPath(dir, "attachments/id/../../outside.txt")
	if err == nil {
		t.Fatal("expected traversal path to be rejected")
	}
}
