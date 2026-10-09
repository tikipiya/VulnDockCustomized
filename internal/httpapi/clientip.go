package httpapi

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
)

func directClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func clientIPForRateLimit(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if ip := forwardedClientIP(r); ip != "" {
			return ip
		}
	}
	return directClientIP(r)
}

func forwardedClientIP(r *http.Request) string {
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if host, _, err := net.SplitHostPort(xri); err == nil {
			xri = host
		}
		if ip := net.ParseIP(xri); ip != nil {
			return xri
		}
	}
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff == "" {
		return ""
	}
	first := strings.TrimSpace(strings.Split(xff, ",")[0])
	if host, _, err := net.SplitHostPort(first); err == nil {
		first = host
	}
	if ip := net.ParseIP(first); ip != nil {
		return first
	}
	return ""
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
	if trustLoopback && isLoopbackIP(directClientIP(r)) && !requestBehindReverseProxy(r) {
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
