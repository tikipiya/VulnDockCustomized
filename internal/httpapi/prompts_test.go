package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"VulnDock/internal/auth"
	"VulnDock/internal/service"
	"VulnDock/internal/store/sqlite"
)

func TestPromptsListEmptyIsJSONArray(t *testing.T) {
	dir := t.TempDir()
	store, err := sqlite.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	srv := newTestServer(store)
	token := setupSession(t, srv)

	req := httptest.NewRequest(http.MethodGet, "/api/prompts", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token.sessionID})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var payload []interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("expected json array, got %s", rec.Body.String())
	}
}

func TestPromptPostIgnoresClientID(t *testing.T) {
	dir := t.TempDir()
	store, err := sqlite.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	srv := newTestServer(store)
	token := setupSession(t, srv)

	body := bytes.NewBufferString(`{"id":"prompt_hijack","title":"a","body":"b"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/prompts", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token.csrf)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token.sessionID})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var created map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created["id"] == "prompt_hijack" {
		t.Fatal("POST must not honor client-supplied id")
	}
}

type testSession struct {
	sessionID string
	csrf      string
}

func newTestServer(store *sqlite.Store) *Server {
	return New(
		&auth.Service{Store: store},
		&service.Reports{Store: store},
		&service.Prompts{Store: store},
		&service.Backup{Store: store},
		nil,
		dirOr(store),
		"setup-token",
		true,
		false,
		false,
	)
}

func dirOr(store *sqlite.Store) string {
	return store.DBPath() // unused by prompts tests
}

func setupSession(t *testing.T, srv *Server) testSession {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", bytes.NewBufferString(`{"password":"password123"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	var sid string
	for _, c := range cookies {
		if c.Name == auth.SessionCookieName {
			sid = c.Value
		}
	}
	return testSession{sessionID: sid, csrf: body["csrfToken"]}
}
