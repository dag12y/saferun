package analyzer

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/dag12y/saferun/internal/risk"
)

type NetworkConnection struct {
	Process     string
	Destination string
	Port        int
}

func CollectNetworkConnections(containerID string) ([]NetworkConnection, error) {
	cmd := exec.Command(
		"docker",
		"exec",
		containerID,
		"sh",
		"-c",
		`cat /tmp/saferun-network.log 2>/dev/null || true`,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("collect sandbox network events: %w", err)
	}

	return ParseNetworkConnections(string(output)), nil
}

func ParseNetworkConnections(raw string) []NetworkConnection {
	var connections []NetworkConnection
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "sl") || strings.HasPrefix(line, "  sl") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		remoteAddr := fields[2]
		if remoteAddr == "00000000:0000" || remoteAddr == "00000000000000000000000000000000:0000" {
			continue
		}

		host, port, ok := parseRemoteSocket(remoteAddr)
		if !ok || host == "" {
			continue
		}

		connections = append(connections, NetworkConnection{
			Process:     "node",
			Destination: host,
			Port:        port,
		})
	}
	return connections
}

func parseRemoteSocket(value string) (string, int, bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, false
	}

	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, false
	}

	ip, ok := parseHexIPv4(parts[0])
	if !ok {
		return "", 0, false
	}

	return ip, int(port), true
}

func parseHexIPv4(value string) (string, bool) {
	if len(value) != 8 {
		return "", false
	}

	parts := []int64{0, 0, 0, 0}
	var errs []error
	for i, chunk := range []string{value[6:8], value[4:6], value[2:4], value[0:2]} {
		v, err := strconv.ParseInt(chunk, 16, 32)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		parts[i] = v
	}
	if len(errs) > 0 {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.%d", parts[0], parts[1], parts[2], parts[3]), true
}

func DeduplicateNetworkConnections(connections []NetworkConnection) []NetworkConnection {
	seen := map[string]struct{}{}
	unique := make([]NetworkConnection, 0, len(connections))
	for _, connection := range connections {
		identity := connectionIdentity(connection)
		if _, ok := seen[identity]; ok {
			continue
		}
		seen[identity] = struct{}{}
		unique = append(unique, connection)
	}
	return unique
}

func connectionIdentity(connection NetworkConnection) string {
	host, port := normalizeConnection(connection)
	process := strings.TrimSpace(connection.Process)
	if process == "" {
		process = "unknown"
	}
	return strings.ToLower(fmt.Sprintf("%s:%d:%s", host, port, process))
}

func AnalyzeNetworkConnections(connections []NetworkConnection) []risk.Finding {
	var findings []risk.Finding
	for _, connection := range DeduplicateNetworkConnections(connections) {
		host, port := normalizeConnection(connection)
		if host == "" || isLocalHost(host) {
			continue
		}
		if isExpectedNetworkHost(host) || isExpectedNPMRegistryIP(host, port) {
			continue
		}

		findings = append(findings, risk.Finding{
			Name:        fmt.Sprintf("%s:%d", host, port),
			Description: "Unexpected external network connection",
			Severity:    risk.Medium,
		})
	}

	return findings
}

func ExpectedRegistryConnections(connections []NetworkConnection) []string {
	seen := map[string]struct{}{}
	var result []string

	for _, connection := range DeduplicateNetworkConnections(connections) {
		host, port := normalizeConnection(connection)
		if host == "" || isLocalHost(host) {
			continue
		}
		if isExpectedNetworkHost(host) || isExpectedNPMRegistryIP(host, port) {
			canonical := "registry.npmjs.org"
			identity := strings.ToLower(fmt.Sprintf("%s:%d:%s", canonical, port, strings.TrimSpace(connection.Process)))
			if _, ok := seen[identity]; ok {
				continue
			}
			seen[identity] = struct{}{}
			result = append(result, fmt.Sprintf("%s:%d", canonical, port))
		}
	}

	return result
}

func normalizeConnection(connection NetworkConnection) (string, int) {
	host := strings.TrimSpace(connection.Destination)
	if host == "" {
		return "", connection.Port
	}

	if connection.Port != 0 {
		return host, connection.Port
	}

	if ip := net.ParseIP(host); ip != nil {
		if addrs, err := net.LookupAddr(host); err == nil && len(addrs) > 0 {
			return strings.TrimSuffix(addrs[0], "."), 0
		}
		return host, 0
	}

	return host, 0
}

func isLocalHost(host string) bool {
	lower := strings.ToLower(host)
	return lower == "localhost" || lower == "127.0.0.1" || lower == "::1" || lower == "0.0.0.0"
}

func isExpectedNetworkHost(host string) bool {
	lower := strings.ToLower(host)
	return lower == "registry.npmjs.org" ||
		strings.HasSuffix(lower, ".npmjs.org") ||
		strings.HasSuffix(lower, ".registry.npmjs.org") ||
		lower == "npmjs.org"
}

func isExpectedNPMRegistryIP(host string, port int) bool {
	if port != 443 {
		return false
	}

	if net.ParseIP(host) == nil {
		return false
	}

	for _, ip := range registryIPAddresses() {
		if strings.EqualFold(ip, host) {
			return true
		}
	}

	return false
}

func registryIPAddresses() []string {
	ips, err := net.LookupIP("registry.npmjs.org")
	if err != nil || len(ips) == 0 {
		return nil
	}

	resolved := make([]string, 0, len(ips))
	for _, ip := range ips {
		resolved = append(resolved, ip.String())
	}
	return resolved
}
