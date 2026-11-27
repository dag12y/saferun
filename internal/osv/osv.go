package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dag12y/saferun/internal/risk"
)

const DefaultEndpoint = "https://api.osv.dev/v1/query"

// Client queries the OSV API for known npm package vulnerabilities.
type Client struct {
	Endpoint   string
	HTTPClient *http.Client
}

// Vulnerability represents a single OSV advisory returned for a package.
type Vulnerability struct {
	ID               string `json:"id"`
	Summary          string `json:"summary"`
	Details          string `json:"details"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// DefaultClient returns an OSV client with a 5-second timeout.
func DefaultClient() Client {
	return Client{
		Endpoint:   DefaultEndpoint,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (c Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 5 * time.Second}
}

func (c Client) endpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	return DefaultEndpoint
}

// QueryPackage checks OSV for vulnerabilities affecting name@version in the npm ecosystem.
func (c Client) QueryPackage(name, version string) ([]Vulnerability, error) {
	if name == "" || version == "" {
		return nil, nil
	}

	payload := struct {
		Version string `json:"version"`
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
	}{
		Version: version,
	}
	payload.Package.Name = name
	payload.Package.Ecosystem = "npm"

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode OSV query: %w", err)
	}

	resp, err := c.httpClient().Post(c.endpoint(), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("query OSV API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV API returned status %d", resp.StatusCode)
	}

	var result struct {
		Vulns []Vulnerability `json:"vulns"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode OSV response: %w", err)
	}

	return result.Vulns, nil
}

// ToRiskFindings converts OSV advisories into SafeRun risk findings.
func ToRiskFindings(pkgName, version string, vulns []Vulnerability) []risk.Finding {
	findings := make([]risk.Finding, 0, len(vulns))
	for _, v := range vulns {
		desc := strings.TrimSpace(v.Summary)
		if desc == "" {
			desc = "Known vulnerability reported in OSV database"
		}
		findings = append(findings, risk.Finding{
			Name:        fmt.Sprintf("%s@%s (%s)", pkgName, version, v.ID),
			Description: desc,
			Severity:    mapSeverity(v.DatabaseSpecific.Severity),
		})
	}
	return findings
}

func mapSeverity(raw string) risk.Level {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		return risk.Critical
	case "HIGH":
		return risk.High
	case "MODERATE", "MEDIUM":
		return risk.Medium
	case "LOW":
		return risk.Low
	default:
		return risk.High
	}
}
