package osv

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dag12y/saferun/internal/risk"
)

func TestQueryPackageReturnsVulnerabilities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"vulns": [
				{
					"id": "GHSA-jf85-cpcp-j695",
					"summary": "Prototype Pollution in lodash",
					"database_specific": {"severity": "HIGH"}
				},
				{
					"id": "GHSA-35jh-r3h4-6jhm",
					"summary": "Command Injection in lodash",
					"database_specific": {"severity": "CRITICAL"}
				}
			]
		}`)
	}))
	defer server.Close()

	client := Client{Endpoint: server.URL, HTTPClient: server.Client()}
	vulns, err := client.QueryPackage("lodash", "4.17.15")
	if err != nil {
		t.Fatalf("QueryPackage returned error: %v", err)
	}
	if len(vulns) != 2 {
		t.Fatalf("expected 2 vulns, got %d", len(vulns))
	}

	findings := ToRiskFindings("lodash", "4.17.15", vulns)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].Severity != risk.High || findings[1].Severity != risk.Critical {
		t.Fatalf("unexpected severities: %#v", findings)
	}
}

func TestQueryPackageEmptySpecSkipsRequest(t *testing.T) {
	client := Client{Endpoint: "http://127.0.0.1:0/invalid"}
	vulns, err := client.QueryPackage("", "")
	if err != nil || len(vulns) != 0 {
		t.Fatalf("expected nil, nil for empty spec; got %v, %v", vulns, err)
	}
}
