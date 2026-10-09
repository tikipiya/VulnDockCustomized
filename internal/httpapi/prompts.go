package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"VulnDock/internal/domain"
)

func (s *Server) registerPromptRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/prompts", s.withAuth(s.handlePrompts))
	mux.HandleFunc("/api/prompts/", s.withAuth(s.handlePromptSubroutes))
}

func (s *Server) handlePrompts(w http.ResponseWriter, r *http.Request) {
	if s.Prompts == nil {
		writeError(w, http.StatusNotImplemented, errNotConfigured("prompts"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		prompts, err := s.Prompts.List(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, prompts)
	case http.MethodPost:
		var draft domain.SavedPromptDraft
		if err := json.NewDecoder(r.Body).Decode(&draft); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		prompt, err := s.Prompts.Create(r.Context(), draft)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, prompt)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handlePromptSubroutes(w http.ResponseWriter, r *http.Request) {
	if s.Prompts == nil {
		writeError(w, http.StatusNotImplemented, errNotConfigured("prompts"))
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/prompts/"), "/")
	if id == "" {
		if r.Method == http.MethodGet {
			s.handlePrompts(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	if strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		var draft domain.SavedPromptDraft
		if err := json.NewDecoder(r.Body).Decode(&draft); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		prompt, err := s.Prompts.Update(r.Context(), id, draft)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, prompt)
	case http.MethodDelete:
		if err := s.Prompts.Delete(r.Context(), id); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		methodNotAllowed(w)
	}
}
