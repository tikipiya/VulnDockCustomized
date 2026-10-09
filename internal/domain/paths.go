package domain

import (
	"errors"
	"path/filepath"
	"strings"
)

func ValidateLegacyAttachmentPath(relPath string) error {
	if relPath == "" {
		return errors.New("backup attachment path is required")
	}
	if filepath.IsAbs(relPath) {
		return errors.New("backup attachment path must be relative")
	}
	if relPath == "attachments" || !strings.HasPrefix(relPath, "attachments/") {
		return errors.New("backup attachment path must be under attachments")
	}
	_, err := stagedAttachmentPath("", relPath)
	return err
}

func stagedAttachmentPath(stageDir string, relPath string) (string, error) {
	relPath = filepath.ToSlash(strings.TrimSpace(relPath))
	candidate, err := filepath.Abs(filepath.Join(stageDir, filepath.FromSlash(relPath)))
	if err != nil {
		return "", err
	}
	base, err := filepath.Abs(filepath.Join(stageDir, "attachments"))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(base, candidate)
	if err != nil {
		return "", err
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("backup attachment path escapes the attachments directory")
	}
	return candidate, nil
}

// LegacyAttachmentAbsPath resolves a validated legacy attachment path under baseDir.
func LegacyAttachmentAbsPath(baseDir, relPath string) (string, error) {
	if err := ValidateLegacyAttachmentPath(relPath); err != nil {
		return "", err
	}
	return stagedAttachmentPath(baseDir, relPath)
}

// LegacyDisplayPath builds the virtual path stored in JSON for desktop compatibility.
func LegacyDisplayPath(attachmentID string, name string) string {
	return filepath.ToSlash(filepath.Join("attachments", attachmentID, name))
}
