package domain

import "testing"

func TestValidateSavedPromptBodyRejectsOversized(t *testing.T) {
	body := make([]byte, MaxSavedPromptBytes+1)
	if err := ValidateSavedPromptBody(string(body)); err == nil {
		t.Fatal("expected size error")
	}
}

func TestNormalizeRestoredPromptFillsEmptyTitle(t *testing.T) {
	p := NormalizeRestoredPrompt(SavedPrompt{ID: "prompt_1", Body: "x"})
	if p.Title != "無題のプロンプト" {
		t.Fatalf("title=%q", p.Title)
	}
}
