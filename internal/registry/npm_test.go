package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dag12y/saferun/internal/analyzer"
)

func TestExtractNPMPackageFindsPackageJSON(t *testing.T) {
	destination := t.TempDir()
	archive := npmTarball(t, map[string]string{
		"package/package.json": `{"name":"test-package","version":"1.0.0"}`,
		"package/index.js":     "module.exports = true;\n",
	})

	if err := extractFixture(t, archive, destination); err != nil {
		t.Fatalf("extractNPMPackage: %v", err)
	}
	manifest := filepath.Join(destination, "package.json")
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatalf("read extracted package.json: %v", err)
	}
	if string(data) != `{"name":"test-package","version":"1.0.0"}` {
		t.Fatalf("unexpected package.json: %s", data)
	}
	if _, err := os.Stat(filepath.Join(destination, "index.js")); err != nil {
		t.Fatalf("read extracted index.js: %v", err)
	}
	if _, err := analyzer.AnalyzePackageJSON(manifest); err != nil {
		t.Fatalf("analyze extracted package.json: %v", err)
	}
}

func TestVerifyIntegrity(t *testing.T) {
	digest := sha512.Sum512([]byte("package tarball"))
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(digest[:])
	if err := verifyIntegrity(integrity, digest[:]); err != nil {
		t.Fatalf("verifyIntegrity returned error: %v", err)
	}
	if err := verifyIntegrity(integrity, []byte("wrong")); err == nil {
		t.Fatal("expected integrity mismatch")
	}
}

func TestExtractNPMPackageMissingPackageJSON(t *testing.T) {
	destination := t.TempDir()
	archive := npmTarball(t, map[string]string{"package/index.js": "module.exports = true;\n"})
	if err := extractFixture(t, archive, destination); err != nil {
		t.Fatalf("extractNPMPackage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destination, "package.json")); !os.IsNotExist(err) {
		t.Fatalf("expected package.json to be missing, got %v", err)
	}
	if _, err := analyzer.AnalyzePackageJSON(filepath.Join(destination, "package.json")); err == nil {
		t.Fatal("expected metadata analysis to fail without package.json")
	}
}

func TestExtractNPMPackageRejectsUnsafePaths(t *testing.T) {
	for _, name := range []string{"../outside.txt", "/absolute.txt", "package/../../outside.txt", `package\\escape.txt`} {
		t.Run(name, func(t *testing.T) {
			destination := t.TempDir()
			err := extractFixture(t, npmTarball(t, map[string]string{name: "unsafe"}), destination)
			if err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
				t.Fatalf("expected unsafe path error, got %v", err)
			}
		})
	}
}

func TestExtractNPMPackageRejectsInvalidLayoutAndSymlink(t *testing.T) {
	for _, name := range []string{"index.js", "package/index.js"} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{name: "invalid"}
			if name == "package/index.js" {
				files["other/package.json"] = "mixed roots"
			}
			err := extractFixture(t, npmTarball(t, files), t.TempDir())
			if err == nil || !strings.Contains(err.Error(), "invalid npm archive path") {
				t.Fatalf("expected invalid layout error, got %v", err)
			}
		})
	}

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "package/link", Typeflag: tar.TypeSymlink, Linkname: "../../outside"}); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	err := extractFixture(t, buffer.Bytes(), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "unsupported archive entry type") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func extractFixture(t *testing.T, archive []byte, destination string) error {
	t.Helper()
	gzipReader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	defer gzipReader.Close()
	return extractNPMPackage(gzipReader, destination)
}

func npmTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, content := range files {
		header := &tar.Header{Name: name, Mode: 0644, Size: int64(len(content))}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tarWriter, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestNPMRegistryResolveSpecifiers(t *testing.T) {
	var requestedPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.EscapedPath())
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.EscapedPath() {
		case "/lodash":
			_, _ = io.WriteString(w, `{
				"dist-tags": {"latest": "4.17.21", "next": "5.0.0-alpha.1"},
				"versions": {
					"4.17.20": {"dist": {"tarball": "https://example.test/lodash-4.17.20.tgz", "integrity": "sha512-a"}},
					"4.17.21": {"dist": {"tarball": "https://example.test/lodash-4.17.21.tgz", "integrity": "sha512-b"}},
					"5.0.0-alpha.1": {"dist": {"tarball": "https://example.test/lodash-5.0.0-alpha.1.tgz", "integrity": "sha512-c"}}
				}
			}`)
		case "/@types%2Fnode":
			_, _ = io.WriteString(w, `{
				"dist-tags": {"latest": "22.0.0"},
				"versions": {
					"20.14.0": {"dist": {"tarball": "https://example.test/node-20.14.0.tgz", "integrity": "sha512-d"}},
					"22.0.0": {"dist": {"tarball": "https://example.test/node-22.0.0.tgz", "integrity": "sha512-e"}}
				}
			}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	reg := NPMRegistry{BaseURL: server.URL, HTTPClient: server.Client()}

	cases := []struct {
		spec        string
		wantName    string
		wantVersion string
	}{
		{"lodash", "lodash", "4.17.21"},
		{"lodash@4.17.20", "lodash", "4.17.20"},
		{"lodash@^4.17.0", "lodash", "4.17.21"},
		{"lodash@next", "lodash", "5.0.0-alpha.1"},
		{"@types/node", "@types/node", "22.0.0"},
		{"@types/node@20.14.0", "@types/node", "20.14.0"},
	}

	for _, tc := range cases {
		info, err := reg.Resolve(tc.spec)
		if err != nil {
			t.Fatalf("Resolve(%q) unexpected error: %v", tc.spec, err)
		}
		if info.Name != tc.wantName || info.Version != tc.wantVersion {
			t.Fatalf("Resolve(%q) = %s@%s, want %s@%s", tc.spec, info.Name, info.Version, tc.wantName, tc.wantVersion)
		}
	}

	if _, err := reg.Resolve("lodash@9.9.9"); err == nil {
		t.Fatal("expected error for missing version")
	}
	if _, err := reg.Resolve("nonexistent"); err == nil {
		t.Fatal("expected error for missing package")
	}
	if _, err := reg.Resolve("@invalid"); err == nil {
		t.Fatal("expected error for invalid scoped specifier")
	}
}
