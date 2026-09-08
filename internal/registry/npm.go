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
)

type NPMRegistry struct {
	BaseURL string
}

type PackageInfo struct {
	Name       string
	Version    string
	TarballURL string
	Integrity  string
}

func (r NPMRegistry) Resolve(name string) (PackageInfo, error) {
	packageURL := r.BaseURL + "/" + url.PathEscape(name)

	resp, err := http.Get(packageURL)
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
		DistTags struct {
			Latest string `json:"latest"`
		} `json:"dist-tags"`

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

	version := metadata.DistTags.Latest

	versionInfo, exists := metadata.Versions[version]
	if !exists {
		return PackageInfo{}, fmt.Errorf(
			"latest version %s not found",
			version,
		)
	}

	return PackageInfo{
		Name:       name,
		Version:    version,
		TarballURL: versionInfo.Dist.Tarball,
		Integrity:  versionInfo.Dist.Integrity,
	}, nil
}

func (r NPMRegistry) Download(pkg PackageInfo) (string, error) {
	resp, err := http.Get(pkg.TarballURL)
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
	gzipReader, err := gzip.NewReader(io.TeeReader(resp.Body, hash))
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("open gzip archive: %w", err)
	}
	defer gzipReader.Close()

	if err := extractNPMPackage(gzipReader, dir); err != nil {
		os.RemoveAll(dir)
		return "", err
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
