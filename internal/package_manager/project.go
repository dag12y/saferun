package package_manager

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
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
	root, ok := lock.Packages[""]
	if !ok {
		return fmt.Errorf("package-lock.json is missing its root project entry")
	}
	for name, spec := range manifest.Dependencies {
		if root.Dependencies[name] != spec {
			return fmt.Errorf("package.json and package-lock.json disagree for dependency %s", name)
		}
	}
	for name, spec := range manifest.DevDependencies {
		if root.DevDependencies[name] != spec {
			return fmt.Errorf("package.json and package-lock.json disagree for devDependency %s", name)
		}
	}
	for name, spec := range manifest.OptionalDependencies {
		if root.OptionalDependencies[name] != spec {
			return fmt.Errorf("package.json and package-lock.json disagree for optionalDependency %s", name)
		}
	}
	for name, spec := range manifest.PeerDependencies {
		if root.PeerDependencies[name] != spec {
			return fmt.Errorf("package.json and package-lock.json disagree for peerDependency %s", name)
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
	if lock.LockfileVersion < 2 || lock.Packages == nil {
		return nil, fmt.Errorf("unsupported package-lock.json format; expected lockfileVersion 2 or 3")
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
		if entry.Link || entry.Version == "" || entry.Resolved == "" || entry.Integrity == "" {
			return nil, fmt.Errorf("package %s has no verifiable registry tarball and cannot be safely analyzed", strings.TrimPrefix(key, "node_modules/"))
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

func packageSpec(name, version string) string {
	if strings.HasPrefix(name, "@") {
		return name + "@" + version
	}
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
		if isSensitiveProjectInput(rel) {
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
