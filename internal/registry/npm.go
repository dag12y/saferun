package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/dag12y/saferun/internal/semver"
)

const defaultHTTPTimeout = 30 * time.Second

type NPMRegistry struct {
	BaseURL    string
	HTTPClient *http.Client
}

type PackageInfo struct {
	Name       string
	Version    string
	TarballURL string
	Integrity  string
}

func (r NPMRegistry) client() *http.Client {
	if r.HTTPClient != nil {
		return r.HTTPClient
	}
	return &http.Client{Timeout: defaultHTTPTimeout}
}

func (r NPMRegistry) Resolve(spec string) (PackageInfo, error) {
	name, requested, err := ParsePackageSpec(spec)
	if err != nil {
		return PackageInfo{}, err
	}

	baseURL := strings.TrimRight(r.BaseURL, "/")
	packageURL := baseURL + "/" + escapeRegistryPackageName(name)

	resp, err := r.client().Get(packageURL)
	if err != nil {
		return PackageInfo{}, fmt.Errorf("fetch package metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PackageInfo{}, fmt.Errorf(
			"npm registry returned status %d",
			resp.StatusCode,
		)
	}

	var metadata struct {
		DistTags map[string]string `json:"dist-tags"`

		Versions map[string]struct {
			Dist struct {
				Tarball   string `json:"tarball"`
				Integrity string `json:"integrity"`
			} `json:"dist"`
		} `json:"versions"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return PackageInfo{}, fmt.Errorf("decode package metadata: %w", err)
	}

	if requested == "" {
		requested = "latest"
	}

	version := ""
	if tagVersion, ok := metadata.DistTags[requested]; ok {
		version = tagVersion
	} else if _, ok := metadata.Versions[requested]; ok {
		version = requested
	} else if semver.IsRangeOrVersion(requested) {
		available := make([]string, 0, len(metadata.Versions))
		for v := range metadata.Versions {
			available = append(available, v)
		}
		matched, matchErr := semver.MaxSatisfying(available, requested)
		if matchErr != nil {
			return PackageInfo{}, fmt.Errorf("version %s for %s not found: %w", requested, name, matchErr)
		}
		version = matched
	} else {
		return PackageInfo{}, fmt.Errorf("version or tag %s not found for %s", requested, name)
	}

	versionInfo, exists := metadata.Versions[version]
	if !exists {
		return PackageInfo{}, fmt.Errorf(
			"version %s not found for %s",
			version,
			name,
		)
	}

	return PackageInfo{
		Name:       name,
		Version:    version,
		TarballURL: versionInfo.Dist.Tarball,
		Integrity:  versionInfo.Dist.Integrity,
	}, nil
}

// ParsePackageSpec separates a registry name from its optional version, range, or tag.
func ParsePackageSpec(spec string) (string, string, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return "", "", fmt.Errorf("empty package specifier")
	}

	if strings.HasPrefix(trimmed, "@") {
		slash := strings.IndexByte(trimmed, '/')
		if slash <= 1 || slash == len(trimmed)-1 {
			return "", "", fmt.Errorf("invalid scoped package specifier %q", spec)
		}
		at := strings.LastIndexByte(trimmed, '@')
		if at > slash {
			name := trimmed[:at]
			req := trimmed[at+1:]
			if req == "" {
				return "", "", fmt.Errorf("invalid package specifier %q", spec)
			}
			return name, req, nil
		}
		return trimmed, "", nil
	}

	at := strings.LastIndexByte(trimmed, '@')
	if at == 0 {
		return "", "", fmt.Errorf("invalid package specifier %q", spec)
	}
	if at > 0 {
		name := trimmed[:at]
		req := trimmed[at+1:]
		if req == "" {
			return "", "", fmt.Errorf("invalid package specifier %q", spec)
		}
		return name, req, nil
	}
	return trimmed, "", nil
}

func escapeRegistryPackageName(name string) string {
	if strings.HasPrefix(name, "@") {
		return "@" + url.PathEscape(name[1:])
	}
	return url.PathEscape(name)
}

func (r NPMRegistry) Download(pkg PackageInfo) (string, error) {
	resp, err := r.client().Get(pkg.TarballURL)
	if err != nil {
		return "", fmt.Errorf("download package: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf(
			"package download returned status %d",
			resp.StatusCode,
		)
	}

	dir, err := os.MkdirTemp("", "saferun-package-*")
	if err != nil {
		return "", fmt.Errorf("create temporary directory: %w", err)
	}

	hash := sha512.New()
	compressed := io.TeeReader(resp.Body, hash)
	gzipReader, err := gzip.NewReader(compressed)
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("open gzip archive: %w", err)
	}
	defer gzipReader.Close()

	if err := extractNPMPackage(gzipReader, dir); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if _, err := io.Copy(io.Discard, gzipReader); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("read gzip archive: %w", err)
	}
	if _, err := io.Copy(io.Discard, compressed); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("read package archive: %w", err)
	}
	if err := verifyIntegrity(pkg.Integrity, hash.Sum(nil)); err != nil {
		os.RemoveAll(dir)
		return "", err
	}

	return dir, nil
}

func verifyIntegrity(integrity string, digest []byte) error {
	if integrity == "" {
		return fmt.Errorf("package integrity is missing")
	}
	parts := strings.SplitN(integrity, "-", 2)
	if len(parts) != 2 || parts[0] != "sha512" {
		return fmt.Errorf("unsupported package integrity algorithm")
	}
	expected, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode package integrity: %w", err)
	}
	if !bytes.Equal(expected, digest) {
		return fmt.Errorf("package integrity verification failed")
	}
	return nil
}

func extractNPMPackage(source io.Reader, destination string) error {
	tarReader := tar.NewReader(source)
	root := filepath.Clean(destination)
	var archiveRoot string

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}

		archiveName := header.Name
		if strings.Contains(archiveName, `\`) {
			return fmt.Errorf("unsafe archive path: %s", archiveName)
		}
		cleanName := path.Clean(archiveName)
		if cleanName == "." || path.IsAbs(cleanName) || cleanName == ".." || strings.HasPrefix(cleanName, "../") {
			return fmt.Errorf("unsafe archive path: %s", archiveName)
		}
		parts := strings.Split(cleanName, "/")
		if archiveRoot == "" {
			if len(parts) == 1 {
				if header.Typeflag != tar.TypeDir {
					return fmt.Errorf("invalid npm archive path: %s", archiveName)
				}
				archiveRoot = parts[0]
			} else {
				archiveRoot = parts[0]
			}
			if archiveRoot == "" {
				return fmt.Errorf("invalid npm archive path: %s", archiveName)
			}
		}
		if cleanName != archiveRoot && !strings.HasPrefix(cleanName, archiveRoot+"/") {
			return fmt.Errorf("invalid npm archive path: %s", archiveName)
		}

		name := strings.TrimPrefix(cleanName, archiveRoot+"/")
		if cleanName == archiveRoot {
			name = ""
		}
		if name == "" {
			continue
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		relative, err := filepath.Rel(root, target)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(relative) {
			return fmt.Errorf("unsafe archive path: %s", archiveName)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("create parent directory: %w", err)
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return fmt.Errorf("create file: %w", err)
			}
			_, copyErr := io.Copy(file, tarReader)
			closeErr := file.Close()
			if copyErr != nil {
				return fmt.Errorf("extract file: %w", copyErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close file: %w", closeErr)
			}
		default:
			return fmt.Errorf("unsupported archive entry type for %s", archiveName)
		}
	}
}
