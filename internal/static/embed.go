package static

import (
	"embed"
	"io/fs"
	"net/http"

	"VulnDock/internal/httpapi"
)

// Dist is populated by `make sync-frontend-dist` before release builds.
//
//go:embed all:dist
var dist embed.FS

func SPAHandler() (http.Handler, error) {
	root, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, err
	}
	return httpapi.SPAFromFS(root), nil
}
