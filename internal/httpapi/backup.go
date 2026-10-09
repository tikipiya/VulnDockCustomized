package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"VulnDock/internal/backup"
	"VulnDock/internal/domain"
)

func (s *Server) registerBackupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/backup/export", s.withAuth(s.handleBackupExport))
	mux.HandleFunc("/api/backup/restore", s.withAuth(s.handleBackupRestore))
}

func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.backupLim.allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many backup requests"))
		return
	}
	if s.Backup == nil {
		writeError(w, http.StatusNotImplemented, errNotConfigured("backup"))
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.Backup.Export(r.Context(), body.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"fileName": result.FileName,
		"data":     base64.StdEncoding.EncodeToString(result.Data),
	})
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !s.backupLim.allow(clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, errors.New("too many backup requests"))
		return
	}
	if s.Backup == nil {
		writeError(w, http.StatusNotImplemented, errNotConfigured("backup"))
		return
	}

	var password string
	var archive []byte

	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(backup.MaxEncryptedBytes + 1024); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		password = r.FormValue("password")
		file, _, err := r.FormFile("archive")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		defer file.Close()
		archive, err = io.ReadAll(io.LimitReader(file, backup.MaxEncryptedBytes+1))
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if len(archive) > backup.MaxEncryptedBytes {
			writeError(w, http.StatusBadRequest, errArchiveTooLarge())
			return
		}
	} else {
		var body struct {
			Password string `json:"password"`
			Data     string `json:"data"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, backup.MaxEncryptedBytes+1024*1024)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		password = body.Password
		decoded, err := backup.DecodeArchiveData(body.Data)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if len(decoded) > backup.MaxEncryptedBytes {
			writeError(w, http.StatusBadRequest, errArchiveTooLarge())
			return
		}
		archive = decoded
	}

	reports, err := s.Backup.Restore(r.Context(), archive, password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	domain.EnsureReportsList(reports)
	writeJSON(w, http.StatusOK, reports)
}

type simpleError string

func (e simpleError) Error() string { return string(e) }

func errNotConfigured(feature string) error {
	return simpleError(feature + " is not configured")
}

func errArchiveTooLarge() error {
	return simpleError("backup archive is too large")
}
