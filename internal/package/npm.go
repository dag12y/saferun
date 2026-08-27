package packagex

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type NPMPackage struct {
	Name        string
	Version     string
	TarballURL  string
	Integrity   string
	ExtractPath string
}

func Resolve(name string) (NPMPackage, error) {
	url := "https://registry.npmjs.org/" + name

	resp, err := http.Get(url)
	if err != nil {
		return NPMPackage{}, fmt.Errorf("fetch npm metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return NPMPackage{}, fmt.Errorf(
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
		return NPMPackage{}, fmt.Errorf("decode npm metadata: %w", err)
	}

	version := metadata.DistTags.Latest
	versionInfo, ok := metadata.Versions[version]

	if !ok {
		return NPMPackage{}, fmt.Errorf("latest version %s not found", version)
	}

	return NPMPackage{
		Name:       name,
		Version:    version,
		TarballURL: versionInfo.Dist.Tarball,
		Integrity:  versionInfo.Dist.Integrity,
	}, nil
}

func DownloadAndExtract(pkg NPMPackage) (NPMPackage, error) {
	resp, err := http.Get(pkg.TarballURL)
	if err != nil {
		return pkg, fmt.Errorf("download package: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return pkg, fmt.Errorf(
			"package download returned status %d",
			resp.StatusCode,
		)
	}

	dir, err := os.MkdirTemp("", "saferun-package-*")
	if err != nil {
		return pkg, fmt.Errorf("create temporary directory: %w", err)
	}

	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		os.RemoveAll(dir)
		return pkg, fmt.Errorf("open gzip archive: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			os.RemoveAll(dir)
			return pkg, fmt.Errorf("read tar archive: %w", err)
		}

		name := filepath.Clean(header.Name)

		// npm tarballs normally contain a "package/" prefix.
		name = strings.TrimPrefix(name, "package/")
		if name == "" {
			continue
		}

		target := filepath.Join(dir, name)

		// Prevent path traversal.
		if !strings.HasPrefix(target, filepath.Clean(dir)+string(os.PathSeparator)) {
			os.RemoveAll(dir)
			return pkg, fmt.Errorf("unsafe archive path: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				os.RemoveAll(dir)
				return pkg, fmt.Errorf("create directory: %w", err)
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				os.RemoveAll(dir)
				return pkg, fmt.Errorf("create parent directory: %w", err)
			}

			file, err := os.OpenFile(
				target,
				os.O_CREATE|os.O_WRONLY|os.O_TRUNC,
				0644,
			)
			if err != nil {
				os.RemoveAll(dir)
				return pkg, fmt.Errorf("create file: %w", err)
			}

			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				os.RemoveAll(dir)
				return pkg, fmt.Errorf("extract file: %w", err)
			}

			file.Close()
		}
	}

	pkg.ExtractPath = dir

	return pkg, nil
}
