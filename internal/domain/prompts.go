package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const MaxSavedPromptBytes = 512 * 1024

type SavedPrompt struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type SavedPromptDraft struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

func NormalizeSavedPrompt(draft SavedPromptDraft, now string) SavedPrompt {
	title := strings.TrimSpace(draft.Title)
	if title == "" {
		title = "無題のプロンプト"
	}
	id := strings.TrimSpace(draft.ID)
	if id == "" {
		id = NewPromptID()
	}
	return SavedPrompt{
		ID:        id,
		Title:     title,
		Body:      draft.Body,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func NewPromptID() string {
	return "prompt_" + time.Now().UTC().Format("20060102150405.000000000")
}

func ValidateSavedPromptBody(body string) error {
	if len(body) > MaxSavedPromptBytes {
		return fmt.Errorf("prompt body exceeds %d byte limit", MaxSavedPromptBytes)
	}
	return nil
}

// EnsureSavedPromptsList returns a non-nil slice for JSON encoding.
func EnsureSavedPromptsList(prompts []SavedPrompt) []SavedPrompt {
	if prompts == nil {
		return []SavedPrompt{}
	}
	return prompts
}

// NormalizeRestoredPrompt sanitizes prompts loaded from backup import.
func NormalizeRestoredPrompt(prompt SavedPrompt) SavedPrompt {
	title := strings.TrimSpace(prompt.Title)
	if title == "" {
		title = "無題のプロンプト"
	}
	id := strings.TrimSpace(prompt.ID)
	if id == "" {
		id = NewPromptID()
	}
	createdAt := strings.TrimSpace(prompt.CreatedAt)
	updatedAt := strings.TrimSpace(prompt.UpdatedAt)
	if updatedAt == "" {
		updatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if createdAt == "" {
		createdAt = updatedAt
	}
	return SavedPrompt{
		ID:        id,
		Title:     title,
		Body:      prompt.Body,
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}
}

func ValidateRestoredPrompts(prompts []SavedPrompt) error {
	for _, prompt := range prompts {
		if strings.TrimSpace(prompt.ID) == "" {
			return errors.New("backup prompt id is required")
		}
		if err := ValidateSavedPromptBody(prompt.Body); err != nil {
			return fmt.Errorf("prompt %q: %w", prompt.Title, err)
		}
	}
	return nil
}
