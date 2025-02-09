package fraudip

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Initialize Caddy Module
func init() {
	caddy.RegisterModule(FraudMiddleware{})
	httpcaddyfile.RegisterHandlerDirective("fraudip_blocker", parseCaddyfile)
}

// FraudMiddleware struct
type FraudMiddleware struct {
	BlocklistFile string `json:"blocklist_file,omitempty"`
	IPQualityKey  string `json:"ipqualityscore_api_key,omitempty"`
	blockedIPs    map[string]bool
	mu            sync.RWMutex
}

// CaddyModule returns module info
func (FraudMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.fraudip_blocker",
		New: func() caddy.Module { return new(FraudMiddleware) },
	}
}

// Load local blocklist
func (m *FraudMiddleware) LoadBlocklist() error {
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

// Watch for changes in blocklist file
func (m *FraudMiddleware) WatchBlocklist() {
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
func (m *FraudMiddleware) Provision(ctx caddy.Context) error {
	if err := m.LoadBlocklist(); err != nil {
		return err
	}

	go m.WatchBlocklist()

	return nil
}

// Detect Fraud using IPQualityScore API
func (m *FraudMiddleware) CheckFraudIP(ip string) (bool, error) {
	if m.IPQualityKey == "" {
		return false, fmt.Errorf("IPQualityScore API key is missing")
	}

	apiURL := fmt.Sprintf("https://www.ipqualityscore.com/api/json/ip/%s/%s", m.IPQualityKey, ip)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return false, fmt.Errorf("failed to fetch IP reputation: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %v", err)
	}

	var result struct {
		Proxy       bool  `json:"proxy"`
		VPN         bool  `json:"vpn"`
		Tor         bool  `json:"tor"`
		FraudScore  int   `json:"fraud_score"`
		BotStatus   bool  `json:"bot_status"`
		RecentAbuse bool  `json:"recent_abuse"`
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return false, fmt.Errorf("failed to parse API response: %v", err)
	}

	// Block if fraud score is high or detected as proxy/VPN
	if result.FraudScore > 85 || result.Proxy || result.VPN || result.Tor {
		return true, nil
	}

	return false, nil
}

// ServeHTTP blocks requests from fraudulent IPs
func (m *FraudMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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

	// Check IP reputation in real-time
	fraudulent, err := m.CheckFraudIP(clientIP)
	if err == nil && fraudulent {
		fmt.Println("Adding", clientIP, "to local blocklist")
		m.mu.Lock()
		m.blockedIPs[clientIP] = true
		m.mu.Unlock()

		// Append to blocklist file
		file, err := os.OpenFile(m.BlocklistFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			file.WriteString(clientIP + "\n")
			file.Close()
		}

		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden - Your IP is blocked"))
		return nil
	}

	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile parses the Caddyfile directive
func (m *FraudMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			m.BlocklistFile = d.Val()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "blocklist_file":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.BlocklistFile = d.Val()
			case "ipqualityscore_api_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.IPQualityKey = d.Val()
			default:
				return d.ArgErr()
			}
		}
	}
	return nil
}

// parseCaddyfile parses the Caddyfile directive
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m FraudMiddleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*FraudMiddleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*FraudMiddleware)(nil)
	_ caddyfile.Unmarshaler       = (*FraudMiddleware)(nil)
)


// fraudip_blocker {
//     blocklist_file /etc/caddy/fraud_blocklist.txt
//     ipqualityscore_api_key {env.IPQUALITYSCORE_API_KEY}
// }