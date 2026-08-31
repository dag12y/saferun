package package_manager

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dag12y/saferun/internal/analyzer"
	"github.com/dag12y/saferun/internal/prompt"
	"github.com/dag12y/saferun/internal/registry"
	"github.com/dag12y/saferun/internal/risk"
	"github.com/dag12y/saferun/internal/sandbox"
)

type NPM struct {
	Sandbox       sandbox.Config
	Registry      registry.NPMRegistry
	ResolveFunc   func(string) (registry.PackageInfo, error)
	DownloadFunc  func(registry.PackageInfo) (string, error)
	SandboxRunner func(sandbox.Config, ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error)
	RealInstaller func([]string) error
	Prompt        func(string) bool
}

func DefaultNPMInstaller(args []string) error {
	cmd := exec.Command("npm", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm %v: %w", args, err)
	}
	return nil
}

func (n NPM) Name() string {
	return "npm"
}

func (n NPM) Install(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no npm package specified")
	}

	packageName := args[0]
	var (
		pkg         registry.PackageInfo
		packagePath string
		analysis    analyzer.NPMAnalysis
		err         error
	)

	if isLocalPackagePath(packageName) {
		packagePath, err = resolveLocalPackagePath(packageName)
		if err != nil {
			return err
		}
		defer os.RemoveAll(packagePath)

		pkg, err = loadLocalPackageInfo(packagePath)
		if err != nil {
			return fmt.Errorf("failed to read local package metadata: %w", err)
		}
		fmt.Printf("Package: %s@%s\n", pkg.Name, pkg.Version)
		fmt.Printf("Source: %s\n", packagePath)
		fmt.Println()
	} else {
		fmt.Printf("Resolving package: %s\n", packageName)

		resolveFunc := n.ResolveFunc
		if resolveFunc == nil {
			resolveFunc = n.Registry.Resolve
		}

		pkg, err = resolveFunc(packageName)
		if err != nil {
			return fmt.Errorf("failed to resolve package: %w", err)
		}

		fmt.Printf("Package: %s@%s\n", pkg.Name, pkg.Version)
		fmt.Printf("Integrity: %s\n", pkg.Integrity)
		fmt.Printf("Tarball: %s\n", pkg.TarballURL)

		fmt.Println()
		fmt.Println("Downloading package...")

		downloadFunc := n.DownloadFunc
		if downloadFunc == nil {
			downloadFunc = n.Registry.Download
		}

		packagePath, err = downloadFunc(pkg)
		if err != nil {
			return fmt.Errorf("failed to download package: %w", err)
		}
		defer os.RemoveAll(packagePath)

		fmt.Printf("Extracted to: %s\n", packagePath)
	}

	analysis, err = analyzer.AnalyzePackageJSON(
		filepath.Join(packagePath, "package.json"),
	)
	if err != nil {
		return fmt.Errorf("failed to analyze package metadata: %w", err)
	}

	findings := make([]risk.Finding, 0)
	for name, command := range analysis.Scripts {
		scriptFindings := analyzer.AnalyzeScript(command)
		if len(scriptFindings) == 0 {
			findings = append(findings, risk.Finding{
				Name:        name,
				Description: command,
				Severity:    risk.Medium,
			})
			continue
		}
		for _, scriptFinding := range scriptFindings {
			findings = append(findings, risk.Finding{
				Name:        fmt.Sprintf("%s: %s", name, scriptFinding.Pattern),
				Description: scriptFinding.Description,
				Severity:    risk.Level(scriptFinding.Severity),
			})
		}
	}

	fileFindings, err := analyzer.AnalyzeFiles(packagePath)
	if err != nil {
		return fmt.Errorf("failed to analyze package files: %w", err)
	}
	for _, finding := range fileFindings {
		findings = append(findings, risk.Finding{
			Name:        finding.Path,
			Description: finding.Description,
			Severity:    risk.Level(finding.Severity),
		})
	}

	fmt.Println()
	fmt.Println("Starting sandbox...")

	sandboxCommand := append([]string{"npm", "install"}, args...)
	runner := n.SandboxRunner
	if runner == nil {
		runner = sandbox.Run
	}
	changes, processFindings, networkConnections, err := runner(n.Sandbox, sandboxCommand...)
	if err != nil {
		return fmt.Errorf("sandbox installation failed: %w", err)
	}

	behaviorFindings := analyzer.AnalyzeFileChanges(changes)
	for _, finding := range behaviorFindings {
		findings = append(findings, risk.Finding{
			Name:        finding.Path,
			Description: finding.Description,
			Severity:    risk.Level(finding.Severity),
		})
	}
	for _, finding := range processFindings {
		findings = append(findings, risk.Finding{
			Name:        finding.Command,
			Description: finding.Reason,
			Severity:    risk.Level(finding.Severity),
		})
	}

	networkFindings := analyzer.AnalyzeNetworkConnections(networkConnections)
	for _, finding := range networkFindings {
		findings = append(findings, finding)
	}

	result := risk.Analyze(findings)

	fmt.Println()
	fmt.Println("Behavior Analysis")
	fmt.Println("-----------------")
	if len(behaviorFindings) == 0 {
		fmt.Println("  ✓ No suspicious file behavior detected")
	} else {
		for _, finding := range behaviorFindings {
			fmt.Printf("  ⚠ %s [%s]: %s\n", finding.Path, finding.Severity, finding.Description)
		}
	}

	fmt.Println()
	fmt.Println("Process Analysis")
	fmt.Println("----------------")
	if len(processFindings) == 0 {
		fmt.Println("  ✓ No suspicious processes detected")
	} else {
		for _, finding := range processFindings {
			fmt.Printf("  ⚠ %s [%s]: %s\n", finding.Command, finding.Severity, finding.Reason)
		}
	}

	fmt.Println()
	fmt.Println("Network Analysis")
	fmt.Println("----------------")
	expectedConnections := analyzer.ExpectedRegistryConnections(networkConnections)
	if len(expectedConnections) > 0 {
		for _, destination := range expectedConnections {
			fmt.Printf("  ✓ %s\n", destination)
		}
	}
	if len(networkFindings) == 0 && len(expectedConnections) == 0 {
		fmt.Println("  ✓ No unexpected network connections detected")
	} else {
		for _, finding := range networkFindings {
			fmt.Printf("  ⚠ %s [%s]: %s\n", finding.Name, finding.Severity, finding.Description)
		}
	}
	if len(expectedConnections) > 0 && len(networkFindings) == 0 {
		fmt.Println("  ✓ Registry traffic was allowed")
	}

	fmt.Println()
	fmt.Println("SafeRun Security Report")
	fmt.Println("-----------------------")
	fmt.Printf("Package: %s@%s\n\n", pkg.Name, pkg.Version)
	fmt.Println("Metadata")
	fmt.Printf("  Dependencies: %d\n", analysis.Dependencies)
	fmt.Printf("  Dev dependencies: %d\n", analysis.DevDependencies)
	fmt.Println()
	fmt.Println("Lifecycle Scripts")
	if len(analysis.Scripts) == 0 {
		fmt.Println("  ✓ None detected")
	} else {
		for name, command := range analysis.Scripts {
			fmt.Printf("  ⚠ %s: %s\n", name, command)
			for _, finding := range analyzer.AnalyzeScript(command) {
				fmt.Printf("      └─ %s [%s]\n", finding.Description, finding.Severity)
			}
		}
	}
	fmt.Println()
	fmt.Println("File Analysis")
	if len(fileFindings) == 0 {
		fmt.Println("  ✓ No suspicious files detected")
	} else {
		for _, finding := range fileFindings {
			fmt.Printf("  ⚠ %s [%s]: %s\n", finding.Path, finding.Severity, finding.Description)
		}
	}
	fmt.Printf("\nRisk: %s\n", result.Level)

	confirm := n.Prompt
	if confirm == nil {
		confirm = prompt.Confirm
	}
	fmt.Println()
	if !confirm(fmt.Sprintf("Install %s@%s in your project?", pkg.Name, pkg.Version)) {
		fmt.Println("Installation cancelled.")
		return nil
	}

	fmt.Println()
	fmt.Printf("Installing %s@%s in your project...\n", pkg.Name, pkg.Version)
	installer := n.RealInstaller
	if installer == nil {
		installer = DefaultNPMInstaller
	}
	if err := installer(append([]string{"install"}, args...)); err != nil {
		return fmt.Errorf("real npm installation failed: %w", err)
	}
	return nil
}

func isLocalPackagePath(spec string) bool {
	if spec == "" {
		return false
	}
	if filepath.IsAbs(spec) || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "~") || strings.HasPrefix(spec, "..") {
		return true
	}
	info, err := os.Stat(spec)
	if err == nil && info.IsDir() {
		return true
	}
	return false
}

func resolveLocalPackagePath(spec string) (string, error) {
	path, err := filepath.Abs(spec)
	if err != nil {
		return "", fmt.Errorf("resolve local package path %q: %w", spec, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("local package path %q does not exist: %w", spec, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("local package path %q is not a directory", spec)
	}

	packageJSONPath := filepath.Join(path, "package.json")
	if _, err := os.Stat(packageJSONPath); err != nil {
		return "", fmt.Errorf("local package %q is missing package.json: %w", spec, err)
	}

	tempDir, err := os.MkdirTemp("", "saferun-local-package-*")
	if err != nil {
		return "", fmt.Errorf("create temporary package copy: %w", err)
	}

	if err := copyDirectoryContents(path, tempDir); err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("copy local package %q to temporary directory: %w", spec, err)
	}

	return tempDir, nil
}

func loadLocalPackageInfo(packagePath string) (registry.PackageInfo, error) {
	path := filepath.Join(packagePath, "package.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return registry.PackageInfo{}, fmt.Errorf("read package.json: %w", err)
	}

	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return registry.PackageInfo{}, fmt.Errorf("decode package metadata: %w", err)
	}
	if pkg.Name == "" || pkg.Version == "" {
		return registry.PackageInfo{}, fmt.Errorf("package.json missing name/version")
	}

	return registry.PackageInfo{
		Name:    pkg.Name,
		Version: pkg.Version,
	}, nil
}

func copyDirectoryContents(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(dst, relPath)
		if info.IsDir() {
			return os.MkdirAll(targetPath, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}
		defer out.Close()
		_, err = io.Copy(out, in)
		return err
	})
}
