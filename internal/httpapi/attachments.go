package httpapi

import (
	"mime"
	"net/http"

	"VulnDock/internal/domain"
)

func writeAttachmentResponse(w http.ResponseWriter, name string, content []byte) {
	safeName := domain.SanitizeAttachmentName(name)
	w.Header().Set("Content-Type", "application/octet-stream")
	if disp := mime.FormatMediaType("attachment", map[string]string{"filename": safeName}); disp != "" {
		w.Header().Set("Content-Disposition", disp)
	}
	_, _ = w.Write(content)
}
