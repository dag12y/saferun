package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
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
	for _, name := range []string{"index.js", "other/package.json"} {
		t.Run(name, func(t *testing.T) {
			err := extractFixture(t, npmTarball(t, map[string]string{name: "invalid"}), t.TempDir())
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
