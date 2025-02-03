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
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	// Register the module with Caddy
	caddy.RegisterModule(Middleware{})
	// Register the Caddyfile directive
	httpcaddyfile.RegisterHandlerDirective("abuseip_blocker", parseCaddyfile)
}

// Middleware implements an HTTP handler that blocks requests from abusive IPs.
type Middleware struct {
	BlocklistFile string `json:"blocklist_file,omitempty"` // Path to the blocklist file
	blockedIPs    map[string]bool                         // In-memory map of blocked IPs
	mu            sync.RWMutex                            // Mutex for thread-safe access to blockedIPs
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.abuseip_blocker",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision loads the blocklist file into memory.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Initialize the blocked IPs map
	m.blockedIPs = make(map[string]bool)

	// Open the blocklist file
	file, err := os.Open(m.BlocklistFile)
	if err != nil {
		return fmt.Errorf("failed to open blocklist file: %v", err)
	}
	defer file.Close()

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			m.blockedIPs[ip] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read blocklist file: %v", err)
	}

	fmt.Printf("Loaded %d IPs into the blocklist\n", len(m.blockedIPs))
	return nil
}

// Validate ensures the blocklist file was loaded correctly.
func (m *Middleware) Validate() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.blockedIPs) == 0 {
		return fmt.Errorf("blocklist is empty")
	}
	return nil
}

// ServeHTTP blocks requests from abusive IPs.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Extract the client IP address
	clientIP := r.Header.Get("CF-Connecting-IP") // Use Cloudflare's header if available
	if clientIP == "" {
		clientIP = strings.Split(r.RemoteAddr, ":")[0] // Fallback to the remote address
	}

	// Check if the IP is blocked
	m.mu.RLock()
	isBlocked := m.blockedIPs[clientIP]
	m.mu.RUnlock()

	if isBlocked {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden - Your IP is blocked"))
		fmt.Printf("Blocked IP: %s\n", clientIP)
		return nil
	}

	// Continue to the next handler
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile parses the Caddyfile directive.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
    for d.Next() { // Advance to next token
        if d.NextArg() {
            m.BlocklistFile = d.Val() // Single argument case
        } else {
            for d.NextBlock(0) { // Block syntax case
                switch d.Val() {
                case "blocklist_file":
                    if !d.NextArg() {
                        return d.ArgErr()
                    }
                    m.BlocklistFile = d.Val()
                default:
                    return d.ArgErr() // Unknown directive
                }
            }
        }
    }
    fmt.Println("Blocklist file set to:", m.BlocklistFile)
    return nil
}

// parseCaddyfile unmarshals the Caddyfile directive into a Middleware instance.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)

// go mod tidy
// go build
