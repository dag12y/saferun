package package_manager

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dag12y/saferun/internal/registry"
)

const (
	manifestName        = "package.json"
	lockName            = "package-lock.json"
	publicationLockName = ".saferun-install.lock"
	hostStagePrefix     = ".saferun-install-"
)

type projectInput struct {
	name string
	data []byte
	mode os.FileMode
}

type installPlan struct {
	dir             string
	packageJSON     projectInput
	packageLock     projectInput
	packages        []registry.PackageInfo
	dependencyNames []string
	directVersions  map[string]string
	ciFlags         []string
	saveManifest    bool
	saveLock        bool
}

func prepareInstallPlan(projectDir string, parsed InstallArgs, projectMode bool) (*installPlan, error) {
	if !projectMode {
		if err := validatePlannedFlags(parsed.Flags); err != nil {
			return nil, err
		}
	}
	plan := &installPlan{saveManifest: !projectMode, saveLock: true}
	for _, flag := range parsed.Flags {
		switch flag {
		case "--no-save":
			plan.saveManifest, plan.saveLock = false, false
		case "--no-package-lock":
			plan.saveLock = false
		}
	}
	plan.ciFlags = supportedProjectFlags(parsed.Flags)
	if err := checkProjectInstallInputs(projectDir); err != nil {
		return nil, err
	}
	var err error
	plan.packageJSON, err = readProjectInput(projectDir, manifestName)
	if err != nil {
		return nil, err
	}
	plan.packageLock, err = readProjectInput(projectDir, lockName)
	if err != nil {
		return nil, err
	}
	if projectMode && plan.packageJSON.data == nil {
		return nil, fmt.Errorf("package.json not found in the current directory")
	}

	plan.dir, err = os.MkdirTemp("", "saferun-install-plan-")
	if err != nil {
		return nil, err
	}
	if err := plan.resolve(projectDir, parsed, projectMode); err != nil {
		plan.cleanup()
		return nil, err
	}
	return plan, nil
}

func checkProjectInstallInputs(projectDir string) error {
	for _, name := range []string{".npmrc", "npm-shrinkwrap.json"} {
		_, err := os.Lstat(filepath.Join(projectDir, name))
		if err == nil {
			return fmt.Errorf("project %s is not supported for verified installation", name)
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("inspect project %s: %w", name, err)
		}
	}
	return nil
}

func readProjectInput(dir, name string) (projectInput, error) {
	input := projectInput{name: name}
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return input, nil
	}
	if err != nil {
		return input, err
	}
	if !info.Mode().IsRegular() {
		return input, fmt.Errorf("project %s must be a regular file", name)
	}
	input.mode = info.Mode().Perm()
	input.data, err = os.ReadFile(path)
	return input, err
}

func (p *installPlan) resolve(projectDir string, parsed InstallArgs, projectMode bool) error {
	if err := copyProjectInputs(projectDir, p.dir); err != nil {
		return fmt.Errorf("stage project for dependency resolution: %w", err)
	}
	manifestPath := filepath.Join(p.dir, manifestName)
	lockPath := filepath.Join(p.dir, lockName)
	manifest := p.packageJSON.data
	if manifest == nil {
		manifest = []byte("{\"private\":true}\n")
	}
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		return err
	}
	if p.packageLock.data != nil {
		if err := os.WriteFile(lockPath, p.packageLock.data, 0o600); err != nil {
			return err
		}
	}

	_, err := readInstallManifest(manifestPath)
	if err != nil {
		return err
	}
	for _, spec := range parsed.Packages {
		if err := validateRegistrySpec(spec); err != nil {
			return err
		}
	}
	if !projectMode || p.packageLock.data == nil {
		args := append([]string{"install"}, p.ciFlags...)
		for _, flag := range parsed.Flags {
			switch flag {
			case "-D", "-P", "-O", "-E", "--save", "--save-dev", "--save-prod", "--save-optional", "--save-exact":
				args = append(args, flag)
			default:
				if strings.HasPrefix(flag, "--tag=") || strings.HasPrefix(flag, "--save-prefix=") {
					args = append(args, flag)
				}
			}
		}
		if slices.Contains(parsed.Flags, "--no-package-lock") {
			if err := os.Remove(lockPath); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		args = append(args, "--ignore-scripts", "--package-lock-only", "--no-audit", "--no-fund")
		if len(parsed.Packages) > 0 {
			args = append(append(args, "--"), parsed.Packages...)
		}
		if err := defaultNPMInstallerInDir(p.dir, args, true); err != nil {
			return fmt.Errorf("resolve dependency lockfile: %w", err)
		}
	}
	after, err := readInstallManifest(manifestPath)
	if err != nil {
		return err
	}
	if err := validateProjectLockfile(lockPath, after); err != nil {
		return err
	}
	if projectMode {
		for _, dependency := range after.dependencies() {
			p.dependencyNames = append(p.dependencyNames, dependency.Name)
		}
	}
	packages, err := readLockfile(lockPath)
	if err != nil {
		return err
	}
	seen := make(map[registry.PackageInfo]bool, len(packages))
	for _, pkg := range packages {
		if !seen[pkg] {
			p.packages = append(p.packages, pkg)
			seen[pkg] = true
		}
	}
	if !projectMode {
		lock, err := readInstallInventory(lockPath)
		if err != nil {
			return err
		}
		p.directVersions = make(map[string]string, len(parsed.Packages))
		for _, spec := range parsed.Packages {
			name, _, _ := registry.ParsePackageSpec(spec)
			entry, found := lock.Packages["node_modules/"+name]
			if !found {
				return fmt.Errorf("requested package %s is missing from the resolved lockfile", name)
			}
			p.directVersions[name] = entry.Version
		}
	}
	return nil
}

func readInstallManifest(path string) (projectManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return projectManifest{}, err
	}
	var settings struct {
		Workspaces json.RawMessage `json:"workspaces"`
		Overrides  map[string]any  `json:"overrides"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return projectManifest{}, fmt.Errorf("parse package.json: %w", err)
	}
	if len(settings.Workspaces) != 0 && string(settings.Workspaces) != "null" {
		return projectManifest{}, fmt.Errorf("npm workspaces are not supported for verified installation")
	}
	if err := validateOverrides(settings.Overrides); err != nil {
		return projectManifest{}, err
	}
	manifest, err := loadProjectManifest(path)
	if err != nil {
		return manifest, err
	}
	for _, dependencies := range []map[string]string{manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies, manifest.PeerDependencies} {
		for name, spec := range dependencies {
			if err := validateRegistrySpec(packageSpec(name, spec)); err != nil {
				return manifest, err
			}
		}
	}
	return manifest, nil
}

func validateOverrides(overrides map[string]any) error {
	for key, value := range overrides {
		switch override := value.(type) {
		case string:
			if strings.HasPrefix(override, "$") && validPackageName(override[1:]) {
				continue
			}
			if err := validateRegistrySpec("override@" + override); err != nil || override == "" {
				return fmt.Errorf("unsupported npm override for %q", key)
			}
		case map[string]any:
			if err := validateOverrides(override); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported npm override for %q", key)
		}
	}
	return nil
}

func validateRegistrySpec(spec string) error {
	name, version, err := registry.ParsePackageSpec(spec)
	if err != nil || !validPackageName(name) {
		return fmt.Errorf("expected a registry npm package specifier, got %q", spec)
	}
	if version != "" {
		if err := validateDependencySpec(version); err != nil || strings.ContainsAny(version, "/\\:@#%") {
			return fmt.Errorf("expected a registry npm version, range, or tag in %q", spec)
		}
	}
	return nil
}

func (p *installPlan) ciArgs(ignoreScripts bool) []string {
	args := append([]string{"ci", "--no-audit", "--no-fund"}, p.ciFlags...)
	if ignoreScripts {
		args = append(args, "--ignore-scripts")
	}
	return args
}

func (p *installPlan) checkOriginal(projectDir string) error {
	if err := checkProjectInstallInputs(projectDir); err != nil {
		return err
	}
	for _, original := range []projectInput{p.packageJSON, p.packageLock} {
		current, err := readProjectInput(projectDir, original.name)
		if err != nil {
			return err
		}
		if (current.data == nil) != (original.data == nil) || !bytes.Equal(current.data, original.data) || current.mode != original.mode {
			return fmt.Errorf("%s changed during analysis; run SafeRun again", original.name)
		}
	}
	return nil
}

func (p *installPlan) prepareHostTree(projectDir string) (string, error) {
	dir, err := os.MkdirTemp(projectDir, hostStagePrefix)
	if err != nil {
		return "", err
	}
	if err := p.installHostTree(dir); err != nil {
		return "", errors.Join(err, os.RemoveAll(dir))
	}
	return dir, nil
}

func (p *installPlan) installHostTree(dir string) error {
	for _, original := range []projectInput{p.packageJSON, p.packageLock} {
		data, err := os.ReadFile(filepath.Join(p.dir, original.name))
		if err != nil {
			return err
		}
		mode := original.mode
		if original.data == nil {
			mode = 0o644
		}
		if err := os.WriteFile(filepath.Join(dir, original.name), data, mode); err != nil {
			return err
		}
	}
	if err := defaultNPMInstallerInDir(dir, p.ciArgs(true), false); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755); err != nil {
		return err
	}
	return verifyInstalledTreeAgainst(dir, filepath.Join(p.dir, lockName), p)
}

func verifyInstalledTreeAgainst(dir, approvedLockPath string, plan *installPlan) error {
	expected, err := readInstallInventory(approvedLockPath)
	if err != nil {
		return err
	}
	installed, err := readInstallInventory(filepath.Join(dir, "node_modules", ".package-lock.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for path, entry := range expected.Packages {
		if _, found := installed.Packages[path]; path != "" && !found && !plan.mayOmit(entry) {
			return fmt.Errorf("approved package %s is missing from the installed dependency tree", path)
		}
	}
	for path, entry := range installed.Packages {
		approved, found := expected.Packages[path]
		if path == "" || !found || entry.Version != approved.Version || entry.Resolved != approved.Resolved || entry.Integrity != approved.Integrity {
			return fmt.Errorf("installed package %s differs from the approved lockfile", path)
		}
		meta, err := readPackageJSON(filepath.Join(dir, filepath.FromSlash(path)))
		if err != nil || meta.Name != packageNameFromLockKey(path) || meta.Version != approved.Version {
			return fmt.Errorf("installed package %s has unexpected identity", path)
		}
	}
	return nil
}

func readInstallInventory(path string) (lockfile, error) {
	var inventory lockfile
	data, err := os.ReadFile(path)
	if err != nil {
		return inventory, fmt.Errorf("read dependency inventory %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &inventory); err != nil || inventory.Packages == nil {
		return inventory, fmt.Errorf("invalid dependency inventory %s", path)
	}
	return inventory, nil
}

func (p *installPlan) mayOmit(entry lockPackage) bool {
	omit := map[string]bool{}
	for _, f := range p.ciFlags {
		switch {
		case f == "--production":
			omit["dev"] = true
		case f == "--legacy-peer-deps":
			omit["peer"] = true
		case strings.HasPrefix(f, "--omit="):
			omit[strings.TrimPrefix(f, "--omit=")] = true
		}
	}
	for _, f := range p.ciFlags {
		if strings.HasPrefix(f, "--include=") {
			delete(omit, strings.TrimPrefix(f, "--include="))
		}
	}
	return entry.Optional || entry.Dev && omit["dev"] || entry.Peer && omit["peer"] || entry.DevOptional && omit["dev"]
}

func lockProjectPublication(projectDir string) (func(), error) {
	path := filepath.Join(projectDir, publicationLockName)
	if err := os.Mkdir(path, 0o700); err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("another SafeRun install is publishing dependencies in this project (%s)", path)
		}
		return nil, err
	}
	return func() { _ = os.Remove(path) }, nil
}

func (p *installPlan) verifyPublished(projectDir string) error {
	for _, saved := range []struct {
		input projectInput
		write bool
	}{{p.packageJSON, p.saveManifest}, {p.packageLock, p.saveLock}} {
		expected := saved.input.data
		if saved.write {
			var err error
			expected, err = os.ReadFile(filepath.Join(p.dir, saved.input.name))
			if err != nil {
				return err
			}
		}
		actual, err := readProjectInput(projectDir, saved.input.name)
		if err != nil {
			return err
		}
		if (expected == nil) != (actual.data == nil) || !bytes.Equal(expected, actual.data) {
			return fmt.Errorf("installed %s differs from the expected project metadata", saved.input.name)
		}
	}
	return verifyInstalledTreeAgainst(projectDir, filepath.Join(p.dir, lockName), p)
}

func (p *installPlan) publish(projectDir, hostTree string) error {
	target := filepath.Join(projectDir, "node_modules")
	if err := os.RemoveAll(target); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(hostTree, "node_modules"), target); err != nil {
		return err
	}
	if p.saveManifest {
		if err := os.Rename(filepath.Join(hostTree, manifestName), filepath.Join(projectDir, manifestName)); err != nil {
			return err
		}
	}
	if p.saveLock {
		return os.Rename(filepath.Join(hostTree, lockName), filepath.Join(projectDir, lockName))
	}
	return nil
}

func (p *installPlan) cleanup() {
	_ = os.RemoveAll(p.dir)
}
