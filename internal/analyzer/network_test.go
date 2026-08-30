package analyzer

import (
	"net"
	"testing"

	"github.com/dag12y/saferun/internal/risk"
)

func TestAnalyzeNetworkConnectionsNoConnections(t *testing.T) {
	findings := AnalyzeNetworkConnections(nil)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestAnalyzeNetworkConnectionsExpectedRegistry(t *testing.T) {
	findings := AnalyzeNetworkConnections([]NetworkConnection{{Process: "npm", Destination: "registry.npmjs.org", Port: 443}})
	if len(findings) != 0 {
		t.Fatalf("expected registry.npmjs.org to be ignored, got %#v", findings)
	}
}

func TestAnalyzeNetworkConnectionsUnexpectedExternalDestination(t *testing.T) {
	findings := AnalyzeNetworkConnections([]NetworkConnection{{Process: "node", Destination: "example.com", Port: 443}})
	if len(findings) != 1 {
		t.Fatalf("expected 1 unexpected connection, got %#v", findings)
	}
	if findings[0].Description != "Unexpected external network connection" {
		t.Fatalf("unexpected description: %s", findings[0].Description)
	}
}

func TestAnalyzeNetworkConnectionsDeduplicatesRegistryEvents(t *testing.T) {
	connections := []NetworkConnection{
		{Process: "node", Destination: "registry.npmjs.org", Port: 443},
		{Process: "node", Destination: "registry.npmjs.org", Port: 443},
		{Process: "node", Destination: "registry.npmjs.org", Port: 443},
	}
	if findings := AnalyzeNetworkConnections(connections); len(findings) != 0 {
		t.Fatalf("expected duplicate registry events to be ignored, got %#v", findings)
	}
	registryConnections := ExpectedRegistryConnections(connections)
	if len(registryConnections) != 1 {
		t.Fatalf("expected one displayed registry connection, got %#v", registryConnections)
	}
	if registryConnections[0] != "registry.npmjs.org:443" {
		t.Fatalf("expected registry.npmjs.org:443, got %q", registryConnections[0])
	}
}

func TestAnalyzeNetworkConnectionsDeduplicatesSuspiciousEvents(t *testing.T) {
	connections := []NetworkConnection{
		{Process: "node", Destination: "example.com", Port: 443},
		{Process: "node", Destination: "example.com", Port: 443},
		{Process: "node", Destination: "example.com", Port: 443},
	}
	findings := AnalyzeNetworkConnections(connections)
	if len(findings) != 1 {
		t.Fatalf("expected one suspicious finding, got %#v", findings)
	}
	if findings[0].Name != "example.com:443" {
		t.Fatalf("expected example.com:443, got %q", findings[0].Name)
	}
}

func TestAnalyzeNetworkConnectionsPreservesDistinctDestinations(t *testing.T) {
	connections := []NetworkConnection{
		{Process: "node", Destination: "registry.npmjs.org", Port: 443},
		{Process: "node", Destination: "example.com", Port: 443},
		{Process: "node", Destination: "example.org", Port: 443},
	}
	findings := AnalyzeNetworkConnections(connections)
	if len(findings) != 2 {
		t.Fatalf("expected two distinct suspicious destinations, got %#v", findings)
	}
	if findings[0].Name != "example.com:443" && findings[1].Name != "example.com:443" {
		t.Fatalf("expected example.com:443 to remain as a suspicious destination, got %#v", findings)
	}
	if findings[0].Name != "example.org:443" && findings[1].Name != "example.org:443" {
		t.Fatalf("expected example.org:443 to remain as a suspicious destination, got %#v", findings)
	}
}

func TestAnalyzeNetworkConnectionsDoesNotInflateRiskWithDuplicates(t *testing.T) {
	connections := []NetworkConnection{
		{Process: "node", Destination: "example.com", Port: 443},
		{Process: "node", Destination: "example.com", Port: 443},
		{Process: "node", Destination: "example.com", Port: 443},
	}
	findings := AnalyzeNetworkConnections(connections)
	report := risk.Analyze(findings)
	if len(findings) != 1 {
		t.Fatalf("expected one unique finding, got %#v", findings)
	}
	if report.Level != risk.Medium {
		t.Fatalf("expected report level MEDIUM, got %s", report.Level)
	}
}

func TestAnalyzeNetworkConnectionsExpectedRegistryIP(t *testing.T) {
	addresses, err := net.LookupIP("registry.npmjs.org")
	if err != nil {
		t.Fatalf("failed to resolve registry.npmjs.org: %v", err)
	}
	if len(addresses) == 0 {
		t.Fatal("expected at least one registry.npmjs.org address")
	}

	for _, addr := range addresses {
		findings := AnalyzeNetworkConnections([]NetworkConnection{{Process: "node", Destination: addr.String(), Port: 443}})
		if len(findings) != 0 {
			t.Fatalf("expected %s to be treated as an allowed registry IP, got %#v", addr, findings)
		}
	}

	expected := ExpectedRegistryConnections([]NetworkConnection{{Process: "node", Destination: addresses[0].String(), Port: 443}})
	if len(expected) == 0 {
		t.Fatal("expected registry.npmjs.org to be included in expected connections")
	}
	if expected[0] != "registry.npmjs.org:443" {
		t.Fatalf("expected registry.npmjs.org:443, got %q", expected[0])
	}
}

func TestAnalyzeNetworkConnectionsMultipleConnections(t *testing.T) {
	connections := []NetworkConnection{
		{Process: "node", Destination: "registry.npmjs.org", Port: 443},
		{Process: "node", Destination: "example.com", Port: 443},
		{Process: "node", Destination: "127.0.0.1", Port: 80},
	}
	findings := AnalyzeNetworkConnections(connections)
	if len(findings) != 1 {
		t.Fatalf("expected only one suspicious connection, got %#v", findings)
	}
	if findings[0].Name != "example.com:443" {
		t.Fatalf("expected example.com:443, got %s", findings[0].Name)
	}
}

func TestParseNetworkConnections(t *testing.T) {
	raw := `sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0100007F:1F90 0100007F:1F90 01 00000000:00000000 00:00000000 00000000 1000        0 1234
1: 0100007F:1F90 0100007F:1F90 01 00000000:00000000 00:00000000 00000000 1000        0 1234
2: 0100007F:1F90 0100007F:1F90 01 00000000:00000000 00:00000000 00000000 1000        0 1234
3: 0100007F:1F90 0100007F:00000000 01 00000000:00000000 00:00000000 00000000 1000        0 1234`
	connections := ParseNetworkConnections(raw)
	if len(connections) != 4 {
		t.Fatalf("expected loopback socket entries to be parsed, got %#v", connections)
	}
	for _, connection := range connections {
		if connection.Destination != "127.0.0.1" {
			t.Fatalf("expected loopback destination, got %#v", connection)
		}
	}
}
