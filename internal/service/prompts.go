package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"VulnDock/internal/domain"
	"VulnDock/internal/store/sqlite"
)

type Prompts struct {
	Store *sqlite.Store
}

func (s *Prompts) List(ctx context.Context) ([]domain.SavedPrompt, error) {
	prompts, err := s.Store.ListSavedPrompts(ctx)
	if err != nil {
		return nil, err
	}
	return domain.EnsureSavedPromptsList(prompts), nil
}

func (s *Prompts) Create(ctx context.Context, draft domain.SavedPromptDraft) (domain.SavedPrompt, error) {
	draft.ID = ""
	return s.save(ctx, draft, false)
}

func (s *Prompts) Update(ctx context.Context, id string, draft domain.SavedPromptDraft) (domain.SavedPrompt, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return domain.SavedPrompt{}, errPromptIDRequired
	}
	draft.ID = id
	return s.save(ctx, draft, true)
}

func (s *Prompts) save(ctx context.Context, draft domain.SavedPromptDraft, requireExisting bool) (domain.SavedPrompt, error) {
	if err := domain.ValidateSavedPromptBody(draft.Body); err != nil {
		return domain.SavedPrompt{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	prompt := domain.NormalizeSavedPrompt(draft, now)

	if requireExisting {
		existing, err := s.Store.GetSavedPrompt(ctx, prompt.ID)
		if err != nil {
			return domain.SavedPrompt{}, errors.New("prompt not found")
		}
		prompt.CreatedAt = existing.CreatedAt
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
