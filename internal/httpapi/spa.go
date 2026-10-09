package httpapi

import (
	"net/http"
	"os"
)

func SPAFileServer(dir string) http.Handler {
	return SPAFromFS(os.DirFS(dir))
}
