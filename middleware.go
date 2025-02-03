package abuseip

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyhttp"
)

// Middleware struct holds the blocklist path and data
type Middleware struct {
	BlocklistFile string `json:"blocklist_file,omitempty"`
	blockedIPs    map[string]bool
	mu            sync.RWMutex
}

// LoadBlocklist reads IPs from the file into memory
func (m *Middleware) LoadBlocklist() error {
	file, err := os.Open(m.BlocklistFile)
	if err != nil {
		return err
	}
	defer file.Close()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.blockedIPs = make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			m.blockedIPs[ip] = true
		}
	}
	return scanner.Err()
}

// ServeHTTP intercepts requests and blocks abusive IPs
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := r.Header.Get("CF-Connecting-IP")
	if clientIP == "" {
		clientIP = strings.Split(r.RemoteAddr, ":")[0] // Fallback to remote IP
	}

	m.mu.RLock()
	isBlocked := m.blockedIPs[clientIP]
	m.mu.RUnlock()

	if isBlocked {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden - Your IP is blocked"))
		fmt.Println("Blocked IP:", clientIP)
		return nil
	}

	// Continue processing the request
	return next.ServeHTTP(w, r)
}

// CaddyModule registers the middleware in Caddy
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.abuseip_blocker",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Init registers the module with Caddy
func init() {
	caddy.RegisterModule(Middleware{})
}
