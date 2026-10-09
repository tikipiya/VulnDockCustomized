package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"VulnDock/internal/auth"
	"VulnDock/internal/domain"
	"VulnDock/internal/service"

	"golang.org/x/time/rate"
)

const version = "1.1.0"

type Server struct {
	Auth               *auth.Service
	Reports            *service.Reports
	Prompts            *service.Prompts
	Backup             *service.Backup
	Static             http.Handler
	DataDir            string
	SetupToken         string
	TrustLoopbackSetup bool
	SecureCookies      bool
	loginLim           *loginLimiter
	backupLim          *loginLimiter
	authStatusLim      *loginLimiter
}

type loginLimiter struct {
	mu       sync.Mutex
	clients  map[string]*rate.Limiter
	interval time.Duration
	burst    int
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		clients:  map[string]*rate.Limiter{},
		interval: 3 * time.Second,
		burst:    3,
	}
}

func newAuthStatusLimiter() *loginLimiter {
	return &loginLimiter{
		clients:  map[string]*rate.Limiter{},
		interval: 200 * time.Millisecond,
		burst:    30,
	}
}

func newBackupLimiter() *loginLimiter {
	return &loginLimiter{
		clients:  map[string]*rate.Limiter{},
		interval: 30 * time.Second,
		burst:    2,
	}
}

func (l *loginLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for len(l.clients) > 2048 {
		for key := range l.clients {
			delete(l.clients, key)
			break
		}
	}
	lim, ok := l.clients[ip]
	if !ok {
		lim = rate.NewLimiter(rate.Every(l.interval), l.burst)
		l.clients[ip] = lim
	}
	return lim.Allow()
}

func New(authSvc *auth.Service, reports *service.Reports, prompts *service.Prompts, backupSvc *service.Backup, static http.Handler, dataDir string, setupToken string, trustLoopbackSetup bool, secureCookies bool) *Server {
	return &Server{
		Auth:               authSvc,
		Reports:            reports,
		Prompts:            prompts,
		Backup:             backupSvc,
		Static:             static,
		DataDir:            dataDir,
		SetupToken:         setupToken,
		TrustLoopbackSetup: trustLoopbackSetup,
		SecureCookies:      secureCookies,
		loginLim:           newLoginLimiter(),
		backupLim:          newBackupLimiter(),
		authStatusLim:      newAuthStatusLimiter(),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("/api/auth/setup", s.handleSetup)
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/logout", s.withAuth(s.handleLogout))
	mux.HandleFunc("/api/auth/change-password", s.withAuth(s.handleChangePassword))
	mux.HandleFunc("/api/reports/trash", s.withAuth(s.handleReportsTrash))
	mux.HandleFunc("/api/reports", s.withAuth(s.handleReports))
	mux.HandleFunc("/api/reports/", s.withAuth(s.handleReportSubroutes))
	mux.HandleFunc("/api/server/info", s.withAuth(s.handleServerInfo))
	s.registerBackupRoutes(mux)
	s.registerPromptRoutes(mux)
	mux.Handle("/", s.spaFallback())
	return withSecurityHeaders(mux)
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) spaFallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		if s.Static != nil {
			s.Static.ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"version": version,
	})
}

func (s *Server) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	var dbBytes int64
	if info, err := os.Stat(filepath.Join(s.DataDir, "vulndock-customized.db")); err == nil {
		dbBytes = info.Size()
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"dataDir": redactDataDir(s.DataDir),
		"dbBytes": dbBytes,
	})
}

func redactDataDir(path string) string {
	home, err := os.UserHomeDir()
	if err == nil && home != "" && strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if !s.authStatusLim.allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many requests"))
		return
	}
	needs, err := s.Auth.NeedsSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	authed := false
	csrfToken := ""
	if !needs {
		csrf, _, err := s.sessionFromRequest(r)
		if err == nil {
			authed = true
			csrfToken = csrf
		}
	}
	setupTokenRequired := false
	if needs {
		setupTokenRequired = !s.TrustLoopbackSetup || !isLoopbackIP(clientIP(r))
	}
	payload := map[string]interface{}{
		"needsSetup":         needs,
		"authenticated":      authed,
		"setupTokenRequired": setupTokenRequired,
	}
	if authed {
		payload["csrfToken"] = csrfToken
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	ip := clientIP(r)
	if !s.loginLim.allow(ip) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many setup attempts"))
		return
	}
	var body struct {
		Password   string `json:"password"`
		SetupToken string `json:"setupToken"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	token := body.SetupToken
	if token == "" {
		token = r.Header.Get("X-VulnDock-Setup-Token")
	}
	if !allowInitialSetup(r, s.SetupToken, token, s.TrustLoopbackSetup) {
		writeError(w, http.StatusForbidden, errors.New("valid setup token is required"))
		return
	}
	if err := s.Auth.Setup(r.Context(), body.Password); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sid, csrf, exp, err := s.Auth.Login(r.Context(), body.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.setSessionCookie(w, sid, exp)
	writeJSON(w, http.StatusOK, map[string]string{"csrfToken": csrf})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	ip := clientIP(r)
	if !s.loginLim.allow(ip) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many login attempts"))
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sid, csrf, exp, err := s.Auth.Login(r.Context(), body.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	s.setSessionCookie(w, sid, exp)
	writeJSON(w, http.StatusOK, map[string]string{"csrfToken": csrf})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	sid, _ := r.Cookie(auth.SessionCookieName)
	if sid != nil {
		_ = s.Auth.Logout(r.Context(), sid.Value)
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	ip := clientIP(r)
	if !s.loginLim.allow(ip) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many password change attempts"))
		return
	}
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.Auth.ChangePassword(r.Context(), body.CurrentPassword, body.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	sid, csrf, exp, err := s.Auth.Login(r.Context(), body.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.setSessionCookie(w, sid, exp)
	writeJSON(w, http.StatusOK, map[string]string{"csrfToken": csrf})
}

func (s *Server) handleReportsTrash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	reports, err := s.Reports.ListTrash(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, reports)
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		reports, err := s.Reports.List(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, reports)
	case http.MethodPost:
		var draft domain.ReportDraft
		if err := decodeJSON(w, r, &draft); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		report, err := s.Reports.Save(r.Context(), draft)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, report)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleReportSubroutes(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/reports/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodPut:
			var draft domain.ReportDraft
			if err := decodeJSON(w, r, &draft); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			draft.ID = id
			report, err := s.Reports.Save(r.Context(), draft)
			if err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, report)
		case http.MethodDelete:
			if err := s.Reports.Delete(r.Context(), id); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		default:
			methodNotAllowed(w)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "restore" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		if err := s.Reports.Restore(r.Context(), id); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if len(parts) == 3 && parts[1] == "attachments" {
		fileID := parts[2]
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		content, name, _, err := s.Reports.Store.PocContent(r.Context(), id, fileID)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeAttachmentResponse(w, name, content)
		return
	}
	http.NotFound(w, r)
}

type authedHandler func(http.ResponseWriter, *http.Request)

func (s *Server) withAuth(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csrf, _, err := s.sessionFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		if needsCSRF(r) && r.Header.Get("X-CSRF-Token") != csrf {
			writeError(w, http.StatusForbidden, errors.New("invalid csrf token"))
			return
		}
		next(w, r)
	}
}

func needsCSRF(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	default:
		return false
	}
}

func (s *Server) sessionFromRequest(r *http.Request) (csrf string, expires time.Time, err error) {
	c, err := r.Cookie(auth.SessionCookieName)
	if err != nil {
		return "", time.Time{}, err
	}
	return s.Auth.ValidateSession(r.Context(), c.Value)
}

func (s *Server) setSessionCookie(w http.ResponseWriter, sid string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookies,
		MaxAge:   -1,
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}

func (s *Server) RunBackgroundMaintenance(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.Reports.PurgeExpired(ctx)
		}
	}
}
