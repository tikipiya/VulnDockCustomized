package httpapi

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
)

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func isLoopbackIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.IsLoopback()
}

func requestBehindReverseProxy(r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("X-Forwarded-For")) != "" {
		return true
	}
	if strings.TrimSpace(r.Header.Get("X-Real-IP")) != "" {
		return true
	}
	if strings.TrimSpace(r.Header.Get("Forwarded")) != "" {
		return true
	}
	return false
}

func allowInitialSetup(r *http.Request, setupToken string, tokenFromRequest string, trustLoopback bool) bool {
	if trustLoopback && isLoopbackIP(clientIP(r)) && !requestBehindReverseProxy(r) {
		return true
	}
	if setupToken == "" {
		return false
	}
	req := strings.TrimSpace(tokenFromRequest)
	if req == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(req), []byte(setupToken)) == 1
}
