package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
