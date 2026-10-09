package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAllowInitialSetupRejectsLoopbackTrustBehindProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	if allowInitialSetup(req, "secret", "", true) {
		t.Fatal("loopback trust must not apply when proxy headers are present")
	}
	if !allowInitialSetup(req, "secret", "secret", false) {
		t.Fatal("valid setup token should still work behind proxy")
	}
}

func TestClientIPForRateLimitTrustsProxyWhenEnabled(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	if clientIPForRateLimit(req, false) != "127.0.0.1" {
		t.Fatal("expected direct client IP")
	}
	if clientIPForRateLimit(req, true) != "203.0.113.9" {
		t.Fatal("expected forwarded client IP for rate limit")
	}
}

func TestAllowInitialSetupLoopbackTrustDirect(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/setup", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	if !allowInitialSetup(req, "secret", "", true) {
		t.Fatal("direct loopback should allow trusted setup without token")
	}
}
