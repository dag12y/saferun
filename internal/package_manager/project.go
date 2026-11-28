package package_manager

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/dag12y/saferun/internal/registry"
)

type projectDependency struct {
	Name string
	Spec string
}

type projectResolution struct {
	Dependencies []projectDependency
	Packages     []registry.PackageInfo
}

type lockfile struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]lockPackage `json:"packages"`
}

type lockPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Optional             bool              `json:"optional"`
	Dev                  bool              `json:"dev"`
	DevOptional          bool              `json:"devOptional"`
	Peer                 bool              `json:"peer"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

func resolveProject(projectDir string, flags []string) (projectResolution, error) {
	manifest, err := loadProjectManifest(filepath.Join(projectDir, "package.json"))
	if err != nil {
		return projectResolution{}, err
	}
	dependencies := manifest.dependencies()
	if len(dependencies) == 0 {
		return projectResolution{Dependencies: dependencies}, nil
	}
	for _, dependency := range dependencies {
		if err := validateDependencySpec(dependency.Spec); err != nil {
			return projectResolution{}, fmt.Errorf("unsupported dependency %s@%s: %w", dependency.Name, dependency.Spec, err)
		}
	}

	lockPath := filepath.Join(projectDir, "package-lock.json")
	var packages []registry.PackageInfo
	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		packages, err = resolveProjectPackages(projectDir, flags)
		if err != nil {
			return projectResolution{}, err
		}
	} else if err != nil {
		return projectResolution{}, fmt.Errorf("inspect package-lock.json: %w", err)
	} else {
		if err := validateProjectLockfile(lockPath, manifest); err != nil {
			return projectResolution{}, err
		}
		packages, err = readLockfile(lockPath)
		if err != nil {
			return projectResolution{}, err
		}
	}
	return projectResolution{Dependencies: dependencies, Packages: packages}, nil
}

func validateProjectLockfile(path string, manifest projectManifest) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read package-lock.json: %w", err)
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("parse package-lock.json: %w", err)
	}
	if lock.LockfileVersion != 2 && lock.LockfileVersion != 3 || lock.Packages == nil {
		return fmt.Errorf("unsupported package-lock.json format; expected lockfileVersion 2 or 3")
	}
	root, ok := lock.Packages[""]
	if !ok {
		return fmt.Errorf("package-lock.json is missing its root project entry")
	}
	if root.Name != "" && root.Name != manifest.Name {
		return fmt.Errorf("package.json and package-lock.json disagree for project name")
	}
	if root.Version != "" && root.Version != manifest.Version {
		return fmt.Errorf("package.json and package-lock.json disagree for project version")
	}
	sections := []struct {
		kind     string
		expected map[string]string
		actual   map[string]string
	}{
		{"dependency", manifest.Dependencies, root.Dependencies},
		{"devDependency", manifest.DevDependencies, root.DevDependencies},
		{"optionalDependency", manifest.OptionalDependencies, root.OptionalDependencies},
		{"peerDependency", manifest.PeerDependencies, root.PeerDependencies},
	}
	for _, section := range sections {
		if len(section.expected) != len(section.actual) {
			return fmt.Errorf("package.json and package-lock.json disagree for %s set", section.kind)
		}
		for name, spec := range section.expected {
			if section.actual[name] != spec {
				return fmt.Errorf("package.json and package-lock.json disagree for %s %s", section.kind, name)
			}
		}
	}
	for key, entry := range lock.Packages {
		if key == "" {
			continue
		}
		if err := validateLockPackageEntry(key, entry); err != nil {
			return err
		}
	}
	for _, dependency := range manifest.dependencies() {
		if !lockContainsPackage(lock.Packages, dependency.Name) {
			return fmt.Errorf("package-lock.json has no package entry for %s", dependency.Name)
		}
	}
	return nil
}

func (m projectManifest) dependencies() []projectDependency {
	sections := []map[string]string{m.Dependencies, m.DevDependencies, m.OptionalDependencies, m.PeerDependencies}
	seen := map[string]struct{}{}
	result := make([]projectDependency, 0)
	for _, section := range sections {
		for name, spec := range section {
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			result = append(result, projectDependency{Name: name, Spec: spec})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func validateDependencySpec(spec string) error {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return fmt.Errorf("empty version specification")
	}
	lower := strings.ToLower(trimmed)
	for _, prefix := range []string{"file:", "link:", "workspace:", "git:", "git+", "http:", "https:", "github:", "npm:"} {
		if strings.HasPrefix(lower, prefix) {
			return fmt.Errorf("dependency source %q is not supported", trimmed)
		}
	}
	return nil
}

func resolveProjectPackages(projectDir string, flags []string) ([]registry.PackageInfo, error) {
	tempDir, err := os.MkdirTemp("", "saferun-project-resolution-")
	if err != nil {
		return nil, fmt.Errorf("create project resolution directory: %w", err)
	}
	defer os.RemoveAll(tempDir)
	if err := copyProjectInputs(projectDir, tempDir); err != nil {
		return nil, fmt.Errorf("stage project for dependency resolution: %w", err)
	}
	args := []string{"install", "--ignore-scripts", "--package-lock-only"}
	args = append(args, supportedProjectFlags(flags)...)
	cmd := exec.Command("npm", args...)
	cmd.Dir = tempDir
	cmd.Stdout = nil
	cmd.Stderr = nil
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("resolve project dependencies: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return readLockfile(filepath.Join(tempDir, "package-lock.json"))
}

func supportedProjectFlags(flags []string) []string {
	allowed := map[string]bool{
		"--production": true, "--legacy-peer-deps": true, "--strict-peer-deps": true,
		"--include=dev": true, "--include=optional": true, "--include=peer": true,
		"--omit=dev": true, "--omit=optional": true, "--omit=peer": true,
	}
	result := make([]string, 0, len(flags))
	for _, flag := range flags {
		if allowed[flag] {
			result = append(result, flag)
		}
	}
	return result
}

func validateProjectFlags(flags []string) error {
	allowed := map[string]bool{
		"--production": true, "--legacy-peer-deps": true, "--strict-peer-deps": true,
		"--include=dev": true, "--include=optional": true, "--include=peer": true,
		"--omit=dev": true, "--omit=optional": true, "--omit=peer": true,
		"--ignore-scripts": true,
	}
	for _, flag := range flags {
		if !allowed[flag] {
			return fmt.Errorf("unsupported project install option %q", flag)
		}
	}
	return nil
}

func readLockfile(path string) ([]registry.PackageInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read package-lock.json: %w", err)
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	if lock.LockfileVersion != 2 && lock.LockfileVersion != 3 || lock.Packages == nil {
		return nil, fmt.Errorf("unsupported package-lock.json format; expected lockfileVersion 2 or 3")
	}
	if _, ok := lock.Packages[""]; !ok {
		return nil, fmt.Errorf("package-lock.json is missing its root project entry")
	}
	for key, entry := range lock.Packages {
		if key != "" {
			if err := validateLockPackageEntry(key, entry); err != nil {
				return nil, err
			}
		}
	}
	keys := make([]string, 0, len(lock.Packages))
	for key := range lock.Packages {
		if key != "" && strings.HasPrefix(key, "node_modules/") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	result := make([]registry.PackageInfo, 0, len(keys))
	for _, key := range keys {
		entry := lock.Packages[key]
		if err := validateLockPackageEntry(key, entry); err != nil {
			return nil, err
		}
		result = append(result, registry.PackageInfo{
			Name: packageNameFromLockKey(key), Version: entry.Version,
			TarballURL: entry.Resolved, Integrity: entry.Integrity,
		})
	}
	return result, nil
}

func packageNameFromLockKey(key string) string {
	trimmed := strings.TrimPrefix(key, "node_modules/")
	parts := strings.Split(trimmed, "/node_modules/")
	name := parts[len(parts)-1]
	if strings.HasPrefix(name, "@") {
		return name
	}
	return strings.TrimPrefix(name, "node_modules/")
}

func validateLockPackageEntry(key string, entry lockPackage) error {
	if !strings.HasPrefix(key, "node_modules/") || strings.Contains(key, `\`) || strings.Contains(key, "//") {
		return fmt.Errorf("unsupported package-lock.json package path %q", key)
	}
	packages := strings.Split(strings.TrimPrefix(key, "node_modules/"), "/node_modules/")
	for _, name := range packages {
		if !validPackageName(name) {
			return fmt.Errorf("invalid package name in package-lock.json path %q", key)
		}
	}
	name := packages[len(packages)-1]
	if entry.Name != "" && entry.Name != name {
		return fmt.Errorf("package-lock.json path %q disagrees with package name %q", key, entry.Name)
	}
	if entry.Link || entry.Version == "" || entry.Resolved == "" || entry.Integrity == "" {
		return fmt.Errorf("package %s has no verifiable registry tarball and cannot be safely analyzed", name)
	}
	if err := validateResolvedURL(entry.Resolved); err != nil {
		return fmt.Errorf("package %s has unsafe resolved URL: %w", name, err)
	}
	if err := validateIntegrity(entry.Integrity); err != nil {
		return fmt.Errorf("package %s has invalid integrity: %w", name, err)
	}
	return nil
}

func lockContainsPackage(packages map[string]lockPackage, name string) bool {
	_, found := packages["node_modules/"+name]
	return found
}

func validateResolvedURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "registry.npmjs.org" || parsed.User != nil {
		return fmt.Errorf("only https://registry.npmjs.org tarballs are supported")
	}
	return nil
}

func validateIntegrity(value string) error {
	parts := strings.SplitN(value, "-", 2)
	if len(parts) != 2 || parts[0] != "sha512" {
		return fmt.Errorf("expected sha512 integrity")
	}
	digest, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(digest) != sha512.Size {
		return fmt.Errorf("invalid sha512 digest")
	}
	return nil
}

var npmNamePattern = regexp.MustCompile(`^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$`)

func validPackageName(name string) bool {
	return !strings.HasPrefix(name, "-") && npmNamePattern.MatchString(name)
}

func packageSpec(name, version string) string {
	return name + "@" + version
}

func copyProjectInputs(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dst, 0o755)
		}
		if rel == "node_modules" || strings.HasPrefix(rel, "node_modules"+string(os.PathSeparator)) || rel == ".git" || strings.HasPrefix(rel, ".git"+string(os.PathSeparator)) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == publicationLockName || strings.HasPrefix(rel, hostStagePrefix) || isSensitiveProjectInput(rel) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink %q is not supported in project inputs", rel)
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported project input %q", rel)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

func isSensitiveProjectInput(path string) bool {
	base := filepath.Base(path)
	return base == ".npmrc" || base == ".yarnrc" || base == ".yarnrc.yml" || base == ".env" || strings.HasPrefix(base, ".env.")
}
