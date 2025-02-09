package abuseip

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Initialize module in Caddy
func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("abuseip_blocker", parseCaddyfile)
}

// Middleware struct
type Middleware struct {
	BlocklistFile string `json:"blocklist_file,omitempty"`
	blockedIPs    map[string]bool
	mu            sync.RWMutex
}

// CaddyModule returns module information
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.abuseip_blocker",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// LoadBlocklist loads IPs from the file
func (m *Middleware) LoadBlocklist() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	file, err := os.Open(m.BlocklistFile)
	if err != nil {
		return fmt.Errorf("failed to open blocklist file: %v", err)
	}
	defer file.Close()

	m.blockedIPs = make(map[string]bool)
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

	fmt.Printf("Blocklist loaded: %d IPs\n", len(m.blockedIPs))
	return nil
}

// WatchBlocklist watches for file updates and reloads automatically
func (m *Middleware) WatchBlocklist() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("Error creating file watcher:", err)
		return
	}
	defer watcher.Close()

	err = watcher.Add(m.BlocklistFile)
	if err != nil {
		fmt.Println("Error watching file:", err)
		return
	}

	fmt.Println("Watching file for changes:", m.BlocklistFile)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				fmt.Println("Blocklist file updated. Reloading...")
				m.LoadBlocklist()
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			fmt.Println("File watcher error:", err)
		}
	}
}

// Provision initializes the middleware
func (m *Middleware) Provision(ctx caddy.Context) error {
	if err := m.LoadBlocklist(); err != nil {
		return err
	}

	// Start watching for file changes in a separate goroutine
	go m.WatchBlocklist()

	return nil
}

// ServeHTTP blocks requests from abusive IPs
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := r.Header.Get("CF-Connecting-IP")
	if clientIP == "" {
		clientIP = strings.Split(r.RemoteAddr, ":")[0]
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

	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile parses the Caddyfile directive
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// Single argument case: `abuseip_blocker /path/to/blocklist.txt`
		if d.NextArg() {
			m.BlocklistFile = d.Val()
			if d.NextArg() {
				return d.ArgErr() // Only one argument allowed
			}
			return nil
		}

		// Block-style case: `abuseip_blocker { blocklist_file /path/to/blocklist.txt }`
		for d.NextBlock(0) {
			switch d.Val() {
			case "blocklist_file":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.BlocklistFile = d.Val()
			default:
				return d.ArgErr()
			}
		}
	}
	return nil
}

// parseCaddyfile parses the Caddyfile directive
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)


// go mod tidy
// go build
