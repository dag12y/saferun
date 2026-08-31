package package_manager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PackageVerification captures the status of a single package after the real npm
// install finishes.
type PackageVerification struct {
	Name             string
	RequestedVersion string
	ExpectedVersion  string
	InstalledVersion string
	Installed        bool
	VersionMatch     bool
	RecordedIn       string
	RecordMatch      bool
}

// VerificationResult is returned by the read-only installation verifier.
type VerificationResult struct {
	Success          bool
	Packages         []PackageVerification
	LockfileVerified bool
	Errors           []string
}

// InstallationVerifier inspects the project after npm install has completed and
// confirms that the requested packages are actually present in the expected form.
type InstallationVerifier struct {
	ProjectDir string
}

func (v InstallationVerifier) Verify(requestedPackages []string, flags []string) (VerificationResult, error) {
	result := VerificationResult{
		Packages: make([]PackageVerification, 0, len(requestedPackages)),
		Errors:   make([]string, 0),
	}

	projectDir := v.ProjectDir
	if projectDir == "" {
		projectDir = "."
	}

	manifestPath := filepath.Join(projectDir, "package.json")
	manifest, err := loadProjectManifest(manifestPath)
	if err != nil {
		if !os.IsNotExist(err) {
			result.Errors = append(result.Errors, err.Error())
			result.Success = false
			return result, fmt.Errorf("installation verification failed: %s", err)
		}
		manifest = projectManifest{}
	}

	if lockfileVerified, lockErr := verifyLockfile(projectDir); lockErr != nil {
		result.Errors = append(result.Errors, lockErr.Error())
		result.LockfileVerified = false
	} else {
		result.LockfileVerified = lockfileVerified
	}

	installSection := dependencySectionForFlags(flags)
	for _, spec := range requestedPackages {
		if spec == "" {
			continue
		}

		pkgName, expectedVersion, err := resolveRequestedPackage(spec, projectDir)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", spec, err))
			continue
		}

		verification := PackageVerification{
			Name:             pkgName,
			RequestedVersion: expectedVersion,
			ExpectedVersion:  expectedVersion,
			Installed:        false,
			VersionMatch:     false,
			RecordedIn:       installSection,
			RecordMatch:      false,
		}

		pkgPath := filepath.Join(projectDir, "node_modules", pkgName)
		installedPackage, err := readPackageJSON(pkgPath)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s was not found in node_modules: %v", pkgName, err))
			result.Packages = append(result.Packages, verification)
			continue
		}

		verification.Installed = true
		verification.InstalledVersion = installedPackage.Version
		if expectedVersion != "" {
			verification.VersionMatch = installedPackage.Version == expectedVersion
			if !verification.VersionMatch {
				result.Errors = append(result.Errors, fmt.Sprintf("%s version mismatch: expected %s, installed %s", pkgName, expectedVersion, installedPackage.Version))
			}
		} else {
			verification.VersionMatch = installedPackage.Version != ""
		}

		verification.RecordMatch, verification.RecordedIn = packageRecordedIn(manifest, pkgName, installSection)
		if !verification.RecordMatch {
			result.Errors = append(result.Errors, fmt.Sprintf("%s was not recorded in %s", pkgName, verification.RecordedIn))
		}

		result.Packages = append(result.Packages, verification)
	}

	result.Success = len(result.Errors) == 0
	if !result.Success {
		return result, fmt.Errorf("installation verification failed: %s", strings.Join(result.Errors, "; "))
	}
	return result, nil
}

func resolveRequestedPackage(spec string, projectDir string) (string, string, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return "", "", fmt.Errorf("empty package specifier")
	}

	if isLocalPackagePath(trimmed) {
		pathToResolve := trimmed
		if !filepath.IsAbs(pathToResolve) {
			pathToResolve = filepath.Join(projectDir, pathToResolve)
		}
		localPath, err := filepath.Abs(pathToResolve)
		if err != nil {
			return "", "", fmt.Errorf("resolve local package: %w", err)
		}
		pkg, err := readPackageJSON(localPath)
		if err != nil {
			return "", "", err
		}
		return pkg.Name, pkg.Version, nil
	}

	if strings.HasPrefix(trimmed, "@") {
		lastAt := strings.LastIndex(trimmed, "@")
		if lastAt > 0 {
			return trimmed[:lastAt], trimmed[lastAt+1:], nil
		}
		return trimmed, "", nil
	}

	lastAt := strings.LastIndex(trimmed, "@")
	if lastAt > 0 {
		return trimmed[:lastAt], trimmed[lastAt+1:], nil
	}

	return trimmed, "", nil
}

func dependencySectionForFlags(flags []string) string {
	for _, flag := range flags {
		switch flag {
		case "-D", "--save-dev":
			return "devDependencies"
		case "-O", "--save-optional", "--optional":
			return "optionalDependencies"
		case "-P", "--save-prod":
			return "dependencies"
		case "--save":
			return "dependencies"
		}
	}
	return "dependencies"
}

func packageRecordedIn(manifest projectManifest, pkgName, expectedSection string) (bool, string) {
	if manifest.isEmpty() {
		return true, expectedSection
	}
	if manifest.HasDependency(expectedSection, pkgName) {
		return true, expectedSection
	}
	return false, expectedSection
}

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type projectManifest struct {
	Dependencies         map[string]string
	DevDependencies      map[string]string
	OptionalDependencies map[string]string
}

func loadProjectManifest(path string) (projectManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return projectManifest{}, fmt.Errorf("read package.json: %w", err)
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return projectManifest{}, fmt.Errorf("parse package.json: %w", err)
	}

	return projectManifest{
		Dependencies:         pkg.Dependencies,
		DevDependencies:      pkg.DevDependencies,
		OptionalDependencies: pkg.OptionalDependencies,
	}, nil
}

func (m projectManifest) HasDependency(section, name string) bool {
	switch section {
	case "dependencies":
		_, ok := m.Dependencies[name]
		return ok
	case "devDependencies":
		_, ok := m.DevDependencies[name]
		return ok
	case "optionalDependencies":
		_, ok := m.OptionalDependencies[name]
		return ok
	default:
		return false
	}
}

func (m projectManifest) isEmpty() bool {
	return len(m.Dependencies) == 0 && len(m.DevDependencies) == 0 && len(m.OptionalDependencies) == 0
}

func readPackageJSON(path string) (packageJSON, error) {
	manifestPath := filepath.Join(path, "package.json")
	if _, err := os.Stat(manifestPath); err != nil {
		return packageJSON{}, fmt.Errorf("package.json missing: %w", err)
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return packageJSON{}, fmt.Errorf("read package.json: %w", err)
	}
	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return packageJSON{}, fmt.Errorf("parse package.json: %w", err)
	}
	if pkg.Name == "" {
		return packageJSON{}, fmt.Errorf("package.json missing name")
	}
	if pkg.Version == "" {
		return packageJSON{}, fmt.Errorf("package.json missing version")
	}
	return pkg, nil
}

func verifyLockfile(projectDir string) (bool, error) {
	path := filepath.Join(projectDir, "package-lock.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, fmt.Errorf("read package-lock.json: %w", err)
	}
	if !json.Valid(data) {
		return false, fmt.Errorf("package-lock.json is invalid JSON")
	}
	return true, nil
}
