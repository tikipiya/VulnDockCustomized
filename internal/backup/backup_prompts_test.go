package backup

import (
	"testing"

	"VulnDock/internal/domain"
)

func TestBackupPayloadRoundTripsPrompts(t *testing.T) {
	reports := []domain.Report{{ID: "r1", Title: "t", CreatedAt: "2020-01-01T00:00:00Z", UpdatedAt: "2020-01-01T00:00:00Z"}}
	prompts := []domain.SavedPrompt{{
		ID:        "prompt_1",
		Title:     "template",
		Body:      "hello {{name}}",
		CreatedAt: "2020-01-01T00:00:00Z",
		UpdatedAt: "2020-01-01T00:00:00Z",
	}}
	payload, err := BuildPayload(reports, prompts, func(file domain.PocFile) ([]byte, error) {
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := NormalizePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Prompts) != 1 || result.Prompts[0].Body != "hello {{name}}" {
		t.Fatalf("prompts mismatch: %#v", result.Prompts)
	}
}
