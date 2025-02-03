package abuseip

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Middleware struct
type Middleware struct {
	BlocklistFile string `json:"blocklist_file,omitempty"`
	blockedIPs    map[string]bool
	mu            sync.RWMutex
}

// LoadBlocklist reads IPs into memory
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

// ServeHTTP intercepts and blocks requests from abusive IPs
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := r.Header.Get("CF-Connecting-IP")
	if clientIP == "" {
		clientIP = strings.Split(r.RemoteAddr, ":")[0] // Extract remote IP
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

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.NextArg() {
			return d.ArgErr()
		}
		m.BlocklistFile = d.Val()

		if d.NextArg() {
			return d.ArgErr() // Only one argument is allowed
		}
	}
	return nil
}

// Register module
func init() {
	caddy.RegisterModule(Middleware{})
}

// CaddyModule definition
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.abuseip_blocker",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Ensure the interface is implemented
var (
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)

// go mod tidy
// go build
