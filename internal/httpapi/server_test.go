package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"VulnDock/internal/auth"
	"VulnDock/internal/service"
	"VulnDock/internal/store/sqlite"
)

func TestSetupRequiresTokenByDefault(t *testing.T) {
	dir := t.TempDir()
	store, err := sqlite.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	srv := New(
		&auth.Service{Store: store},
		&service.Reports{Store: store},
		&service.Prompts{Store: store},
		&service.Backup{Store: store},
		nil,
		dir,
		"secret-setup-token",
		false,
		false,
	)

	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", bytes.NewBufferString(`{"password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.10:12345"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", rec.Code, rec.Body.String())
	}

	body := bytes.NewBufferString(`{"password":"password123","setupToken":"secret-setup-token"}`)
	req2 := httptest.NewRequest(http.MethodPost, "/api/auth/setup", body)
	req2.Header.Set("Content-Type", "application/json")
	req2.RemoteAddr = "203.0.113.10:12345"
	rec2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec2.Code, rec2.Body.String())
	}
}

func TestHealthDoesNotExposeDataDir(t *testing.T) {
	dir := t.TempDir()
	store, err := sqlite.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	srv := New(&auth.Service{Store: store}, &service.Reports{Store: store}, nil, nil, nil, filepath.Join(dir, "data"), "tok", false, false)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health status %d", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["dataDir"]; ok {
		t.Fatal("dataDir must not be public")
	}
}
