package httpapi

import (
	"encoding/json"
	"net/http"
)

const maxJSONBodyBytes = 64 << 20

func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	return json.NewDecoder(r.Body).Decode(dst)
}
