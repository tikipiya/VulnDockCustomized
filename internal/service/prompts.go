package service

import (
	"context"
	"strings"
	"time"

	"VulnDock/internal/domain"
	"VulnDock/internal/store/sqlite"
)

type Prompts struct {
	Store *sqlite.Store
}

func (s *Prompts) List(ctx context.Context) ([]domain.SavedPrompt, error) {
	return s.Store.ListSavedPrompts(ctx)
}

func (s *Prompts) Save(ctx context.Context, draft domain.SavedPromptDraft) (domain.SavedPrompt, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	prompt := domain.NormalizeSavedPrompt(draft, now)

	if strings.TrimSpace(draft.ID) != "" {
		existing, err := s.Store.GetSavedPrompt(ctx, draft.ID)
		if err == nil {
			prompt.CreatedAt = existing.CreatedAt
		}
	}

	if err := s.Store.SaveSavedPrompt(ctx, prompt); err != nil {
		return domain.SavedPrompt{}, err
	}
	return prompt, nil
}

func (s *Prompts) Delete(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errPromptIDRequired
	}
	return s.Store.DeleteSavedPrompt(ctx, id)
}

var errPromptIDRequired = domainError("prompt id is required")
