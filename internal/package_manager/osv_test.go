package package_manager

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dag12y/saferun/internal/analyzer"
	"github.com/dag12y/saferun/internal/osv"
	"github.com/dag12y/saferun/internal/registry"
	"github.com/dag12y/saferun/internal/report"
	"github.com/dag12y/saferun/internal/sandbox"
)

func TestProjectInstallChecksOSVForTransitiveDependencies(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		name := "advisory"
		if unavailable {
			name = "service outage"
		}
		t.Run(name, func(t *testing.T) {
			projectDir := t.TempDir()
			configPath := filepath.Join(projectDir, ".saferunrc")
			writeProjectJSON(t, configPath, map[string]any{})
			t.Setenv("SAFERUN_CONFIG", configPath)
			dependencies := map[string]string{"direct-pkg": "1.0.0"}
			writeProjectJSON(t, filepath.Join(projectDir, "package.json"), map[string]any{
				"name": "fixture-app", "dependencies": dependencies,
			})
			writeProjectJSON(t, filepath.Join(projectDir, "package-lock.json"), map[string]any{
				"lockfileVersion": 3,
				"packages": map[string]any{
					"": map[string]any{"dependencies": dependencies},
					"node_modules/direct-pkg": map[string]any{
						"version": "1.0.0", "integrity": testIntegrity(),
						"resolved":     "https://registry.npmjs.org/direct-pkg/-/direct-pkg-1.0.0.tgz",
						"dependencies": map[string]string{"transitive-pkg": "2.0.0"},
					},
					"node_modules/direct-pkg/node_modules/transitive-pkg": map[string]any{
						"version": "2.0.0", "integrity": testIntegrity(),
						"resolved": "https://registry.npmjs.org/transitive-pkg/-/transitive-pkg-2.0.0.tgz",
					},
				},
			})

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var query struct {
					Version string
					Package struct{ Name, Ecosystem string }
				}
				if err := json.NewDecoder(r.Body).Decode(&query); err != nil || r.Method != http.MethodPost || query.Package.Ecosystem != "npm" {
					http.Error(w, "invalid OSV request", http.StatusBadRequest)
					return
				}
				switch query.Package.Name + "@" + query.Version {
				case "direct-pkg@1.0.0":
					_, _ = io.WriteString(w, `{}`)
				case "transitive-pkg@2.0.0":
					if unavailable {
						http.Error(w, "OSV unavailable", http.StatusServiceUnavailable)
						return
					}
					_, _ = io.WriteString(w, `{"vulns":[{"id":"TEST-OSV-001","summary":"Fixture advisory","database_specific":{"severity":"HIGH"}}]}`)
				default:
					http.Error(w, "unexpected package version", http.StatusBadRequest)
				}
			}))
			defer server.Close()

			client := osv.Client{Endpoint: server.URL, HTTPClient: server.Client()}
			manager := NPM{
				preparePlan:    unplannedFixtureInstall,
				ProjectDir:     projectDir,
				Format:         "sarif",
				CheckVulnsFunc: client.CheckPackage,
				DownloadFunc: func(pkg registry.PackageInfo) (string, error) {
					source := t.TempDir()
					writeProjectJSON(t, filepath.Join(source, "package.json"), map[string]string{
						"name": pkg.Name, "version": pkg.Version,
					})
					return source, nil
				},
				SandboxRunner: func(sandbox.Config, ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error) {
					if unavailable {
						t.Fatal("sandbox should not run when vulnerability data is unavailable")
					}
					return analyzer.FileChanges{}, nil, nil, nil
				},
			}

			output, err := os.CreateTemp(t.TempDir(), "sarif-")
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			originalStdout := os.Stdout
			defer func() { os.Stdout = originalStdout }()
			os.Stdout = output
			installErr := manager.Install(nil)
			os.Stdout = originalStdout

			if unavailable {
				if installErr == nil || !strings.Contains(installErr.Error(), "OSV vulnerability data unavailable for transitive-pkg@2.0.0: OSV API returned status 503") {
					t.Fatalf("expected an operational OSV error, got %v", installErr)
				}
				if info, err := output.Stat(); err != nil || info.Size() != 0 {
					t.Fatalf("expected no SARIF report for the incomplete scan: %v, %v", info, err)
				}
				return
			}
			if installErr == nil || !strings.Contains(installErr.Error(), "security policy blocks installation") {
				t.Fatalf("expected a policy block for the transitive advisory, got %v", installErr)
			}
			if _, err := output.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			var sarif report.SARIFReport
			if err := json.NewDecoder(output).Decode(&sarif); err != nil {
				t.Fatal(err)
			}
			if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != 1 ||
				!strings.Contains(sarif.Runs[0].Results[0].Message.Text, "transitive-pkg@2.0.0 (TEST-OSV-001)") {
				t.Fatalf("expected the transitive advisory in the SARIF report, got %#v", sarif)
			}
		})
	}
}
