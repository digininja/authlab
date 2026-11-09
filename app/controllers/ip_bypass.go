package controllers

import (
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// RegisterIPBypassRoutes mounts routes for the IP Bypass challenge.
func RegisterIPBypassRoutes(r chi.Router, renderFn RenderFunc, flashFn FlashFunc) {
	r.Get("/Bypass", func(w http.ResponseWriter, r *http.Request) {
		handleIPBypass(w, r, renderFn, flashFn)
	})
}

func handleIPBypass(w http.ResponseWriter, r *http.Request, render RenderFunc, setFlash FlashFunc) {
	clientIP := getClientIP(r)
	loggedIn := clientIP == "192.168.0.14"

	render(w, r, "App/Bypass.html", map[string]any{
		"forwarded": clientIP,
		"logged_in": loggedIn,
	})
}

func getClientIP(r *http.Request) string {
	// 1. Check X-Forwarded-For first
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		firstIP := strings.TrimSpace(ips[0])
		if firstIP != "" {
			return firstIP
		}
	}

	// 2. Cloudflare-specific header
	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
		return cfIP
	}

	// 3. Alternative proxy headers
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		return xri
	}
	if tci := strings.TrimSpace(r.Header.Get("True-Client-IP")); tci != "" {
		return tci
	}

	// 4. Socket address fallback
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return strings.TrimSpace(host)
	}

	return strings.TrimSpace(r.RemoteAddr)
}
