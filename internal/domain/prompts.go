package domain

import (
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
