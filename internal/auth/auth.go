package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"VulnDock/internal/store/sqlite"

	"golang.org/x/crypto/bcrypt"
)

const (
	SettingPasswordHash = "password_hash"
	SettingSetupDone    = "setup_completed_at"
	SessionCookieName   = "vdc_session"
	SessionDuration     = 72 * time.Hour
)

type Service struct {
	Store *sqlite.Store
}

func (s *Service) NeedsSetup(ctx context.Context) (bool, error) {
	hash, err := s.Store.Setting(ctx, SettingPasswordHash)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(hash) == "", nil
}

func (s *Service) Setup(ctx context.Context, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	needs, err := s.NeedsSetup(ctx)
	if err != nil {
		return err
	}
	if !needs {
		return errors.New("setup already completed")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := s.Store.SetSetting(ctx, SettingPasswordHash, string(hash)); err != nil {
		return err
	}
	return s.Store.SetSetting(ctx, SettingSetupDone, time.Now().UTC().Format(time.RFC3339))
}

func (s *Service) Login(ctx context.Context, password string) (sessionID string, csrf string, expires time.Time, err error) {
	hash, err := s.Store.Setting(ctx, SettingPasswordHash)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if strings.TrimSpace(hash) == "" {
		return "", "", time.Time{}, errors.New("setup required")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return "", "", time.Time{}, errors.New("invalid credentials")
	}
	return s.createSession(ctx)
}

func (s *Service) ChangePassword(ctx context.Context, current, newPassword string) error {
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	hash, err := s.Store.Setting(ctx, SettingPasswordHash)
	if err != nil {
		return err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(current)); err != nil {
		return errors.New("current password is invalid")
	}
	next, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := s.Store.SetSetting(ctx, SettingPasswordHash, string(next)); err != nil {
		return err
	}
	return s.Store.DeleteAllSessions(ctx)
}

func (s *Service) ValidateSession(ctx context.Context, sessionID string) (csrf string, expires time.Time, err error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return "", time.Time{}, errors.New("unauthorized")
	}
	csrfToken, expiresAt, _, err := s.Store.GetSession(ctx, sessionID)
	if err != nil {
		return "", time.Time{}, errors.New("unauthorized")
	}
	expires, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil || time.Now().After(expires) {
		_ = s.Store.DeleteSession(ctx, sessionID)
		return "", time.Time{}, errors.New("unauthorized")
	}
	newExpires := time.Now().Add(SessionDuration)
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.Store.UpdateSessionActivity(ctx, sessionID, newExpires.UTC().Format(time.RFC3339), now); err != nil {
		return "", time.Time{}, err
	}
	return csrfToken, newExpires, nil
}

func (s *Service) Logout(ctx context.Context, sessionID string) error {
	return s.Store.DeleteSession(ctx, sessionID)
}

func (s *Service) createSession(ctx context.Context) (string, string, time.Time, error) {
	id, err := randomToken(32)
	if err != nil {
		return "", "", time.Time{}, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return "", "", time.Time{}, err
	}
	expires := time.Now().Add(SessionDuration)
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.Store.CreateSession(ctx, id, csrf, expires.UTC().Format(time.RFC3339), now); err != nil {
		return "", "", time.Time{}, err
	}
	return id, csrf, expires, nil
}

func validatePassword(password string) error {
	if strings.TrimSpace(password) == "" {
		return errors.New("password is required")
	}
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	return nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func RandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
