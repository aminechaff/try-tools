// tcp_probe — plugin externe Try_Tools (Go).
//
// Découverte de ports par connexion TCP simple : on tente d'ouvrir la
// connexion puis on la ferme immédiatement, sans envoyer de donnée. C'est un
// contrôle « actif-sûr », non intrusif. La cible doit déjà être validée par le
// périmètre côté orchestrateur.
//
// Usage : tcp_probe <cible> [ports=22,80,443,...] [timeout_ms=800]
// Sortie : JSON {"plugin","version","findings":[...]} sur stdout.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Target      string `json:"target"`
	ScopeProfile string `json:"scope_profile"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	State       string `json:"state"`
	RiskLevel   string `json:"risk_level"`
	Description string `json:"description"`
	Remediation string `json:"remediation,omitempty"`
	ToolName    string `json:"tool_name"`
	ToolVersion string `json:"tool_version"`
}

type output struct {
	Plugin   string    `json:"plugin"`
	Version  string    `json:"version"`
	Findings []finding `json:"findings"`
}

const (
	toolName    = "go.tcp_probe"
	toolVersion = "0.0.1"
)

var defaultPorts = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443}

func parseArgs() (string, map[string]string) {
	params := map[string]string{}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tcp_probe <cible> [clé=valeur ...]")
		os.Exit(2)
	}
	target := os.Args[1]
	for _, a := range os.Args[2:] {
		if i := strings.IndexByte(a, '='); i > 0 {
			params[a[:i]] = a[i+1:]
		}
	}
	return target, params
}

func portsFrom(params map[string]string) []int {
	raw, ok := params["ports"]
	if !ok || strings.TrimSpace(raw) == "" {
		return defaultPorts
	}
	var ports []int
	for _, p := range strings.Split(raw, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 && n < 65536 {
			ports = append(ports, n)
		}
	}
	if len(ports) == 0 {
		return defaultPorts
	}
	return ports
}

// hostOnly retire un éventuel port de la cible (host:port).
func hostOnly(target string) string {
	if h, _, err := net.SplitHostPort(target); err == nil {
		return h
	}
	return target
}

func main() {
	target, params := parseArgs()
	host := hostOnly(target)

	timeout := 800 * time.Millisecond
	if v, ok := params["timeout_ms"]; ok {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 && ms <= 10000 {
			timeout = time.Duration(ms) * time.Millisecond
		}
	}

	out := output{Plugin: toolName, Version: toolVersion}
	var open []int
	for _, port := range portsFrom(params) {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			_ = conn.Close()
			open = append(open, port)
		}
	}

	if len(open) == 0 {
		out.Findings = append(out.Findings, finding{
			ID:           "net-tcp-000",
			Title:        "Aucun port TCP ouvert détecté",
			Target:       target,
			ScopeProfile: "lab-actif-sur",
			Severity:     "informationnelle",
			Confidence:   "elevee",
			State:        "nouveau",
			RiskLevel:    "actif-sur",
			Description:  "Aucun des ports testés n'a accepté de connexion TCP.",
			ToolName:     toolName,
			ToolVersion:  toolVersion,
		})
	}
	for _, port := range open {
		out.Findings = append(out.Findings, finding{
			ID:           fmt.Sprintf("net-tcp-%d", port),
			Title:        fmt.Sprintf("Port TCP %d ouvert", port),
			Target:       target,
			ScopeProfile: "lab-actif-sur",
			Severity:     "informationnelle",
			Confidence:   "elevee",
			State:        "nouveau",
			RiskLevel:    "actif-sur",
			Description:  fmt.Sprintf("Le port %d accepte les connexions TCP.", port),
			Remediation:  "Vérifier que ce service doit être exposé ; sinon le filtrer ou le restreindre.",
			ToolName:     toolName,
			ToolVersion:  toolVersion,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "encodage JSON:", err)
		os.Exit(1)
	}
}
