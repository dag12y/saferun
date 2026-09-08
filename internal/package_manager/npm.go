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
	"github.com/dag12y/saferun/internal/audit"
	"github.com/dag12y/saferun/internal/cli"
	"github.com/dag12y/saferun/internal/policy"
	"github.com/dag12y/saferun/internal/prompt"
	"github.com/dag12y/saferun/internal/registry"
	"github.com/dag12y/saferun/internal/report"
	"github.com/dag12y/saferun/internal/risk"
	"github.com/dag12y/saferun/internal/sandbox"
	"github.com/dag12y/saferun/internal/setup"
)

type NPM struct {
	Sandbox       sandbox.Config
	Registry      registry.NPMRegistry
	ProjectDir    string
	AuditLogger   audit.Logger
	ResolveFunc   func(string) (registry.PackageInfo, error)
	DownloadFunc  func(registry.PackageInfo) (string, error)
	SandboxRunner func(sandbox.Config, ...string) (analyzer.FileChanges, []analyzer.ProcessFinding, []analyzer.NetworkConnection, error)
	RealInstaller func([]string) error
	Prompt        func(string) bool
	JSON          bool
}

func DefaultNPMInstaller(args []string) error {
	return defaultNPMInstallerInDir("", args, false)
}

func defaultNPMInstallerInDir(projectDir string, args []string, jsonOutput bool) error {
	if err := validateHostInstallArgs(args); err != nil {
		return err
	}
	env, cleanup, err := prepareNPMEnvironment(projectDir)
	if err != nil {
		return err
	}
	defer cleanup()
	cmd := exec.Command("npm", args...)
	if projectDir != "" {
		cmd.Dir = projectDir
	}
	cmd.Env = env
	if jsonOutput {
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("npm %v: %w", args, err)
	}
	return nil
}

func validateHostInstallArgs(args []string) error {
	for _, arg := range args {
		lower := strings.ToLower(arg)
		for _, prefix := range []string{
			"--prefix", "--userconfig", "--globalconfig", "--cache", "--registry", "--config",
		} {
			if lower == prefix || strings.HasPrefix(lower, prefix+"=") {
				return fmt.Errorf("unsupported npm option %q: host installation target or configuration cannot be redirected", arg)
			}
		}
		if lower == "-g" || lower == "--global" || lower == "-c" {
			return fmt.Errorf("unsupported npm option %q: global or configuration installation is not allowed", arg)
		}
		if strings.HasPrefix(lower, "-c=") || strings.HasPrefix(lower, "-c") && len(lower) > 2 {
			return fmt.Errorf("unsupported npm option %q: npm configuration cannot be redirected", arg)
		}
	}
	return nil
}

func prepareNPMEnvironment(projectDir string) ([]string, func(), error) {
	if projectDir == "" {
		var err error
		projectDir, err = os.Getwd()
		if err != nil {
			return nil, func() {}, fmt.Errorf("determine npm project directory: %w", err)
		}
	}
	if _, err := os.Stat(filepath.Join(projectDir, ".npmrc")); err == nil {
		return nil, func() {}, fmt.Errorf("project .npmrc is not supported for host installation; remove it or use explicit SafeRun-supported registry settings")
	} else if !os.IsNotExist(err) {
		return nil, func() {}, fmt.Errorf("inspect project .npmrc: %w", err)
	}

	configDir, err := os.MkdirTemp("", "saferun-npm-config-")
	if err != nil {
		return nil, func() {}, fmt.Errorf("create isolated npm configuration: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(configDir) }
	userConfig := filepath.Join(configDir, "user.npmrc")
	globalConfig := filepath.Join(configDir, "global.npmrc")
	for _, path := range []string{userConfig, globalConfig} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("create isolated npm configuration: %w", err)
		}
	}
	env := []string{
		"HOME=" + configDir,
		"TMPDIR=" + configDir,
		"npm_config_userconfig=" + userConfig,
		"npm_config_globalconfig=" + globalConfig,
		"npm_config_cache=" + filepath.Join(configDir, "cache"),
	}
	for _, entry := range os.Environ() {
		name, value, ok := strings.Cut(entry, "=")
		if ok && allowedNPMEnvironmentVariable(name) {
			env = append(env, name+"="+value)
		}
	}
	if os.Getenv("USERPROFILE") != "" {
		env = append(env, "USERPROFILE="+configDir)
	}
	return env, cleanup, nil
}

func allowedNPMEnvironmentVariable(name string) bool {
	upper := strings.ToUpper(name)
	if upper == "PATH" || upper == "SYSTEMROOT" || upper == "COMSPEC" || upper == "PATHEXT" || upper == "LANG" || upper == "TERM" || strings.HasPrefix(upper, "LC_") {
		return true
	}
	return false
}

func (n NPM) Name() string {
	return "npm"
}

type packageReport struct {
	Package      registry.PackageInfo
	Analysis     analyzer.NPMAnalysis
	Findings     []risk.Finding
	FileFindings []analyzer.FileFinding
	Source       string
}

type outputFormatter struct {
	io.Writer
}

func (f outputFormatter) Println(args ...any) (int, error) {
	return fmt.Fprintln(f.Writer, args...)
}

func (f outputFormatter) Printf(format string, args ...any) (int, error) {
	return fmt.Fprintf(f.Writer, format, args...)
}

func (f outputFormatter) Errorf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

func (f outputFormatter) Sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

func (f outputFormatter) Print(args ...any) (int, error) {
	return fmt.Fprint(f.Writer, args...)
}

func (n NPM) Install(args []string) error {
	output := io.Writer(os.Stdout)
	if n.JSON {
		output = io.Discard
	}
	fmt := outputFormatter{Writer: output}
	n.Sandbox.Output = output

	if n.Sandbox.Image == "" {
		n.Sandbox.Image = sandbox.DefaultImage
	}
	parsed, err := parseInstallArgsAllowEmpty(args)
	if err != nil {
		return err
	}
	projectMode := len(parsed.Packages) == 0
	projectDir := n.ProjectDir
	if projectMode {
		if err := validateProjectFlags(parsed.Flags); err != nil {
			return err
		}
	}
	if projectMode && projectDir == "" {
		projectDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("determine current project directory: %w", err)
		}
	}
	packageArgs := append([]string(nil), parsed.Packages...)
	installArgs := append([]string(nil), args...)
	if err := validateHostInstallArgs(installArgs); err != nil {
		return err
	}
	analysisArgs := append([]string(nil), packageArgs...)
	if projectMode {
		manifestPath := filepath.Join(projectDir, "package.json")
		if _, statErr := os.Stat(manifestPath); statErr != nil {
			if os.IsNotExist(statErr) {
				return fmt.Errorf("package.json not found in the current directory")
			}
			return fmt.Errorf("inspect package.json: %w", statErr)
		}
		resolution, resolveErr := resolveProject(projectDir, parsed.Flags)
		if resolveErr != nil {
			return resolveErr
		}
		packageArgs = make([]string, 0, len(resolution.Dependencies))
		for _, dependency := range resolution.Dependencies {
			packageArgs = append(packageArgs, dependency.Name)
		}
		analysisArgs = make([]string, 0, len(resolution.Packages))
		resolvedPackages := make(map[string]registry.PackageInfo, len(resolution.Packages))
		for _, pkg := range resolution.Packages {
			spec := packageSpec(pkg.Name, pkg.Version)
			if _, exists := resolvedPackages[spec]; exists {
				continue
			}
			resolvedPackages[spec] = pkg
			analysisArgs = append(analysisArgs, spec)
		}
		if len(resolution.Packages) == 0 && len(resolution.Dependencies) > 0 {
			return fmt.Errorf("package-lock.json contains no analyzable packages")
		}
		originalResolve := n.ResolveFunc
		originalDownload := n.DownloadFunc
		n.ResolveFunc = func(spec string) (registry.PackageInfo, error) {
			if pkg, ok := resolvedPackages[spec]; ok {
				return pkg, nil
			}
			if originalResolve != nil {
				return originalResolve(spec)
			}
			return registry.PackageInfo{}, fmt.Errorf("package %s was not present in the resolved dependency graph", spec)
		}
		n.DownloadFunc = func(pkg registry.PackageInfo) (string, error) {
			if originalDownload != nil {
				return originalDownload(pkg)
			}
			return n.Registry.Download(pkg)
		}
		n.Sandbox.ProjectDir = projectDir
	}
	if n.SandboxRunner == nil {
		if _, err := exec.LookPath("docker"); err == nil {
			imgCtx, cancel := setup.DockerTimeoutContext()
			defer cancel()
			if _, err := setup.CheckSandboxImage(imgCtx, setup.RealDocker{}, n.Sandbox.Image); err != nil {
				fmt.Println()
				fmt.Println("SafeRun sandbox is not configured.")
				fmt.Println()
				fmt.Println("Run:")
				fmt.Println()
				fmt.Println("  saferun setup")
				fmt.Println("before installing packages.")
				return fmt.Errorf("sandbox image %q is not available; run 'saferun setup' first", n.Sandbox.Image)
			}
		}
	}
	packageReports := make([]packageReport, 0, len(packageArgs))
	allFindings := make([]risk.Finding, 0)

	for _, packageName := range analysisArgs {
		var report packageReport

		if isLocalPackagePath(packageName) {
			localPath, err := resolveLocalPackagePath(packageName)
			if err != nil {
				return err
			}
			defer os.RemoveAll(localPath)

			info, err := loadLocalPackageInfo(localPath)
			if err != nil {
				return fmt.Errorf("failed to read local package metadata: %w", err)
			}
			report.Package = info
			report.Source = localPath
			fmt.Printf("Package: %s@%s\n", report.Package.Name, report.Package.Version)
			fmt.Printf("Source: %s\n", report.Source)
			fmt.Println()
		} else {
			fmt.Printf("Resolving package: %s\n", packageName)
			resolveFunc := n.ResolveFunc
			if resolveFunc == nil {
				resolveFunc = n.Registry.Resolve
			}

			resolved, err := resolveFunc(packageName)
			if err != nil {
				return fmt.Errorf("failed to resolve package %q: %w", packageName, err)
			}
			report.Package = resolved
			fmt.Printf("Package: %s@%s\n", report.Package.Name, report.Package.Version)
			fmt.Printf("Integrity: %s\n", report.Package.Integrity)
			fmt.Printf("Tarball: %s\n", report.Package.TarballURL)
			fmt.Println()
			fmt.Println("Downloading package...")

			downloadFunc := n.DownloadFunc
			if downloadFunc == nil {
				downloadFunc = n.Registry.Download
			}

			downloaded, err := downloadFunc(resolved)
			if err != nil {
				return fmt.Errorf("failed to download package %q: %w", packageName, err)
			}
			defer os.RemoveAll(downloaded)
			report.Source = downloaded
			fmt.Printf("Extracted to: %s\n", report.Source)
			if err := validateDownloadedPackageIdentity(resolved, downloaded); err != nil {
				return fmt.Errorf("failed to validate package identity: %w", err)
			}
		}

		analysis, err := analyzer.AnalyzePackageJSON(filepath.Join(report.Source, "package.json"))
		if err != nil {
			return fmt.Errorf("failed to analyze package metadata: %w", err)
		}
		report.Analysis = analysis

		packageFindings := make([]risk.Finding, 0)
		for name, command := range analysis.Scripts {
			scriptFindings := analyzer.AnalyzeScript(command)
			if len(scriptFindings) == 0 {
				packageFindings = append(packageFindings, risk.Finding{
					Name:        name,
					Description: command,
					Severity:    risk.Medium,
				})
				continue
			}
			for _, scriptFinding := range scriptFindings {
				packageFindings = append(packageFindings, risk.Finding{
					Name:        fmt.Sprintf("%s: %s", name, scriptFinding.Pattern),
					Description: scriptFinding.Description,
					Severity:    risk.Level(scriptFinding.Severity),
				})
			}
		}

		fileFindings, err := analyzer.AnalyzeFiles(report.Source)
		if err != nil {
			return fmt.Errorf("failed to analyze package files for %s: %w", report.Package.Name, err)
		}
		report.FileFindings = fileFindings
		for _, finding := range fileFindings {
			packageFindings = append(packageFindings, risk.Finding{
				Name:        finding.Path,
				Description: finding.Description,
				Severity:    risk.Level(finding.Severity),
			})
		}
		report.Findings = packageFindings
		allFindings = append(allFindings, packageFindings...)
		packageReports = append(packageReports, report)
	}

	fmt.Println()
	fmt.Println("Starting sandbox...")

	sandboxCommand := append([]string{"npm", "install"}, installArgs...)
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
		allFindings = append(allFindings, risk.Finding{
			Name:        finding.Path,
			Description: finding.Description,
			Severity:    risk.Level(finding.Severity),
		})
	}
	for _, finding := range processFindings {
		allFindings = append(allFindings, risk.Finding{
			Name:        finding.Command,
			Description: finding.Reason,
			Severity:    risk.Level(finding.Severity),
		})
	}
	for _, finding := range analyzer.AnalyzeNetworkConnections(networkConnections) {
		allFindings = append(allFindings, finding)
	}

	result := risk.Analyze(allFindings)
	logger := n.auditLogger()
	auditContext := func(event audit.Event) audit.Event {
		if projectMode {
			event.Operation = "install"
			event.Scope = "project"
			event.Project = filepath.Base(projectDir)
			event.PackagesAnalyzed = len(packageReports)
		}
		return event
	}

	fmt.Println()
	fmt.Println(cli.Heading("Behavior Analysis"))
	fmt.Println(cli.Muted("-----------------"))
	if len(behaviorFindings) == 0 {
		fmt.Println(cli.Success("  ✓ No suspicious file behavior detected"))
	} else {
		for _, finding := range behaviorFindings {
			fmt.Println(cli.Severity(string(finding.Severity), fmt.Sprintf("  ⚠ %s [%s]: %s", finding.Path, finding.Severity, finding.Description)))
		}
	}

	fmt.Println()
	fmt.Println(cli.Heading("Process Analysis"))
	fmt.Println(cli.Muted("----------------"))
	if len(processFindings) == 0 {
		fmt.Println(cli.Success("  ✓ No suspicious processes detected"))
	} else {
		for _, finding := range processFindings {
			fmt.Println(cli.Severity(string(finding.Severity), fmt.Sprintf("  ⚠ %s [%s]: %s", finding.Command, finding.Severity, finding.Reason)))
		}
	}

	fmt.Println()
	fmt.Println(cli.Heading("Network Analysis"))
	fmt.Println(cli.Muted("----------------"))
	expectedConnections := analyzer.ExpectedRegistryConnections(networkConnections)
	if len(expectedConnections) > 0 {
		for _, destination := range expectedConnections {
			fmt.Println(cli.Success(fmt.Sprintf("  ✓ %s", destination)))
		}
	}
	if len(analyzer.AnalyzeNetworkConnections(networkConnections)) == 0 && len(expectedConnections) == 0 {
		fmt.Println(cli.Success("  ✓ No unexpected network connections detected"))
	} else {
		for _, finding := range analyzer.AnalyzeNetworkConnections(networkConnections) {
			fmt.Println(cli.Severity(string(finding.Severity), fmt.Sprintf("  ⚠ %s [%s]: %s", finding.Name, finding.Severity, finding.Description)))
		}
	}
	if len(expectedConnections) > 0 && len(analyzer.AnalyzeNetworkConnections(networkConnections)) == 0 {
		fmt.Println(cli.Success("  ✓ Registry traffic was allowed"))
	}

	fmt.Println()
	fmt.Println(cli.Heading("SafeRun Security Report"))
	fmt.Println(cli.Muted("-----------------------"))
	if len(packageReports) > 1 {
		fmt.Printf("Packages: %d\n\n", len(packageReports))
	}
	for _, pkgReport := range packageReports {
		fmt.Printf("Package: %s@%s\n\n", pkgReport.Package.Name, pkgReport.Package.Version)
		fmt.Println("Metadata")
		fmt.Printf("  Dependencies: %d\n", pkgReport.Analysis.Dependencies)
		fmt.Printf("  Dev dependencies: %d\n", pkgReport.Analysis.DevDependencies)
		fmt.Println()
		fmt.Println(cli.Heading("Lifecycle Scripts"))
		if len(pkgReport.Analysis.Scripts) == 0 {
			fmt.Println(cli.Success("  ✓ None detected"))
		} else {
			for name, command := range pkgReport.Analysis.Scripts {
				fmt.Println(cli.Warning(fmt.Sprintf("  ⚠ %s: %s", name, command)))
				for _, finding := range analyzer.AnalyzeScript(command) {
					fmt.Println(cli.Severity(string(finding.Severity), fmt.Sprintf("      └─ %s [%s]", finding.Description, finding.Severity)))
				}
			}
		}
		fmt.Println()
		fmt.Println(cli.Heading("File Analysis"))
		if len(pkgReport.FileFindings) == 0 {
			fmt.Println(cli.Success("  ✓ No suspicious files detected"))
		} else {
			for _, finding := range pkgReport.FileFindings {
				fmt.Println(cli.Severity(string(finding.Severity), fmt.Sprintf("  ⚠ %s [%s]: %s", finding.Path, finding.Severity, finding.Description)))
			}
		}
		fmt.Println()
	}
	fmt.Println(cli.Heading("Risk Summary"))
	fmt.Println(cli.Muted("------------"))
	fmt.Println(cli.Risk(string(result.Level), fmt.Sprintf("Score: %d", result.Score)))
	fmt.Println(cli.Risk(string(result.Level), fmt.Sprintf("Findings: %d", result.FindingCount)))
	fmt.Println()
	fmt.Println(cli.Heading("Reasons:"))
	if len(result.Findings) == 0 {
		fmt.Println(cli.Success("  ✓ No suspicious findings detected"))
	} else {
		for _, finding := range result.Findings {
			if finding.Name == "" {
				fmt.Println(cli.Severity(string(finding.Severity), fmt.Sprintf("  ⚠ %-8s %s", finding.Severity, finding.Description)))
				continue
			}
			fmt.Println(cli.Severity(string(finding.Severity), fmt.Sprintf("  ⚠ %-8s %s: %s", finding.Severity, finding.Name, finding.Description)))
		}
	}
	fmt.Printf("\n%s\n", cli.Risk(string(result.Level), fmt.Sprintf("Risk: %s", result.Level)))

	decision, reason, policyErr := policy.Evaluate(result)
	decisionStatus := toAuditDecision(decision)
	if n.JSON {
		if projectMode {
			projectPackages := make([]report.ProjectPackageInput, 0, len(packageReports))
			for _, pkg := range packageReports {
				projectPackages = append(projectPackages, report.ProjectPackageInput{Name: pkg.Package.Name, Version: pkg.Package.Version, Findings: pkg.Findings})
			}
			projectReport := report.NewProjectSecurityReport(filepath.Base(projectDir), result, projectPackages, behaviorFindings, processFindings, expectedConnections, decision)
			if policyErr != nil {
				return fmt.Errorf("security policy evaluation failed: %w", policyErr)
			}
			if err := json.NewEncoder(os.Stdout).Encode(projectReport); err != nil {
				return fmt.Errorf("encode security report: %w", err)
			}
			if decision != policy.Allow {
				return fmt.Errorf("security policy blocks installation: %s", reason)
			}
			return nil
		}
		securityReport := report.NewSecurityReport(
			packageReports[0].Package.Name,
			packageReports[0].Package.Version,
			result,
			behaviorFindings,
			processFindings,
			expectedConnections,
			packageReports[0].FileFindings,
			decision,
		)
		if policyErr != nil {
			return fmt.Errorf("security policy evaluation failed: %w", policyErr)
		}
		if err := json.NewEncoder(os.Stdout).Encode(securityReport); err != nil {
			return fmt.Errorf("encode security report: %w", err)
		}
		if decision != policy.Allow {
			return fmt.Errorf("security policy blocks installation: %s", reason)
		}
		return nil
	}
	fmt.Println()
	fmt.Println(cli.Heading("Security Policy"))
	fmt.Println(cli.Muted("---------------"))
	fmt.Printf("Decision: %s\n", cli.Decision(string(decisionStatus), string(decisionStatus)))
	if reason != "" {
		fmt.Printf("Reason: %s\n", reason)
	}

	if policyErr != nil {
		loggerRecord(logger, auditContext(audit.Event{
			Packages:     append([]string(nil), packageArgs...),
			Risk:         string(result.Level),
			Score:        result.Score,
			FindingCount: result.FindingCount,
			Decision:     audit.DecisionBlock,
			Approval:     audit.ApprovalNotNeeded,
			Installation: audit.InstallationNotRun,
			Verification: audit.VerificationNotRun,
			Reason:       policyErr.Error(),
		}))
		fmt.Println()
		fmt.Println("Audit")
		fmt.Println("-----")
		fmt.Println(cli.Success("✓ Security event recorded"))
		return fmt.Errorf("security policy evaluation failed: %w", policyErr)
	}
	if decision == policy.Block {
		auditEvent := audit.Event{
			Packages:     append([]string(nil), packageArgs...),
			Risk:         string(result.Level),
			Score:        result.Score,
			FindingCount: result.FindingCount,
			Decision:     audit.DecisionBlock,
			Approval:     audit.ApprovalNotNeeded,
			Installation: audit.InstallationNotRun,
			Verification: audit.VerificationNotRun,
			Reason:       reason,
		}
		loggerRecord(logger, auditContext(auditEvent))
		fmt.Println()
		fmt.Println("Audit")
		fmt.Println("-----")
		fmt.Println(cli.Success("✓ Security event recorded"))
		return fmt.Errorf("security policy blocks installation: %s", reason)
	}

	confirm := n.Prompt
	if confirm == nil {
		confirm = prompt.Confirm
	}
	fmt.Println()
	if projectMode {
		if !confirm("Install project dependencies?") {
			fmt.Println("Installation cancelled.")
			auditEvent := audit.Event{
				Packages: append([]string(nil), packageArgs...), Risk: string(result.Level), Score: result.Score,
				FindingCount: result.FindingCount, Decision: decisionStatus, Approval: audit.ApprovalDeclined,
				Installation: audit.InstallationNotRun, Verification: audit.VerificationNotRun,
				Reason: "User declined installation.",
			}
			loggerRecord(logger, auditContext(auditEvent))
			return nil
		}
	} else if len(packageReports) > 1 {
		if !confirm(fmt.Sprintf("Install %d packages in your project?", len(packageReports))) {
			fmt.Println("Installation cancelled.")
			auditEvent := audit.Event{
				Packages:     append([]string(nil), packageArgs...),
				Risk:         string(result.Level),
				Score:        result.Score,
				FindingCount: result.FindingCount,
				Decision:     decisionStatus,
				Approval:     audit.ApprovalDeclined,
				Installation: audit.InstallationNotRun,
				Verification: audit.VerificationNotRun,
				Reason:       "User declined installation.",
			}
			loggerRecord(logger, auditContext(auditEvent))
			fmt.Println()
			fmt.Println("Audit")
			fmt.Println("-----")
			fmt.Println("✓ Security event recorded")
			return nil
		}
	} else {
		if !confirm(fmt.Sprintf("Install %s@%s in your project?", packageReports[0].Package.Name, packageReports[0].Package.Version)) {
			fmt.Println("Installation cancelled.")
			auditEvent := audit.Event{
				Packages:     append([]string(nil), packageArgs...),
				Risk:         string(result.Level),
				Score:        result.Score,
				FindingCount: result.FindingCount,
				Decision:     decisionStatus,
				Approval:     audit.ApprovalDeclined,
				Installation: audit.InstallationNotRun,
				Verification: audit.VerificationNotRun,
				Reason:       "User declined installation.",
			}
			loggerRecord(logger, auditContext(auditEvent))
			fmt.Println()
			fmt.Println("Audit")
			fmt.Println("-----")
			fmt.Println("✓ Security event recorded")
			return nil
		}
	}

	fmt.Println()
	if projectMode {
		fmt.Println("Installing project dependencies...")
	} else if len(packageReports) > 1 {
		fmt.Printf("Installing %d packages in your project...\n", len(packageReports))
	} else {
		fmt.Printf("Installing %s@%s in your project...\n", packageReports[0].Package.Name, packageReports[0].Package.Version)
	}
	installer := n.RealInstaller
	if installer == nil {
		if projectMode {
			installer = func(installArgs []string) error { return defaultNPMInstallerInDir(projectDir, installArgs, n.JSON) }
		} else {
			installer = DefaultNPMInstaller
		}
	}
	if projectDir == "" {
		projectDir, err = os.Getwd()
		if err != nil {
			auditEvent := audit.Event{
				Packages:     append([]string(nil), packageArgs...),
				Risk:         string(result.Level),
				Score:        result.Score,
				FindingCount: result.FindingCount,
				Decision:     decisionStatus,
				Approval:     audit.ApprovalAccepted,
				Installation: audit.InstallationFailed,
				Verification: audit.VerificationNotRun,
				Rollback:     audit.RollbackNotRequired,
				Reason:       fmt.Sprintf("verification setup failed: %v", err),
			}
			loggerRecord(logger, auditContext(auditEvent))
			fmt.Println()
			fmt.Println("Audit")
			fmt.Println("-----")
			fmt.Println("✓ Security event recorded")
			return fmt.Errorf("resolve project directory for verification: %w", err)
		}
	}

	backup, backupErr := createProjectBackupMode(projectDir, packageArgs, projectMode)
	if backupErr != nil {
		auditEvent := audit.Event{
			Packages:     append([]string(nil), packageArgs...),
			Risk:         string(result.Level),
			Score:        result.Score,
			FindingCount: result.FindingCount,
			Decision:     decisionStatus,
			Approval:     audit.ApprovalAccepted,
			Installation: audit.InstallationFailed,
			Verification: audit.VerificationNotRun,
			Rollback:     audit.RollbackNotRequired,
			Reason:       backupErr.Error(),
		}
		loggerRecord(logger, auditContext(auditEvent))
		fmt.Println()
		fmt.Println("Backup failed")
		fmt.Println("Audit")
		fmt.Println("-----")
		fmt.Println("✓ Security event recorded")
		return fmt.Errorf("create project backup: %w", backupErr)
	}

	if err := installer(append([]string{"install"}, installArgs...)); err != nil {
		rollbackErr := backup.Restore()
		auditEvent := audit.Event{
			Packages:     append([]string(nil), packageArgs...),
			Risk:         string(result.Level),
			Score:        result.Score,
			FindingCount: result.FindingCount,
			Decision:     decisionStatus,
			Approval:     audit.ApprovalAccepted,
			Installation: audit.InstallationFailed,
			Verification: audit.VerificationNotRun,
			Rollback:     audit.RollbackSucceeded,
			Reason:       err.Error(),
		}
		if rollbackErr != nil {
			auditEvent.Rollback = audit.RollbackFailed
			auditEvent.Reason = fmt.Sprintf("%s; rollback failed: %v", err.Error(), rollbackErr)
			loggerRecord(logger, auditContext(auditEvent))
			fmt.Println()
			fmt.Println("Rolling back installation...")
			fmt.Println("✗ Rollback failed.")
			fmt.Println()
			fmt.Println("WARNING: SafeRun could not completely restore the project.")
			fmt.Println("Manual recovery may be required.")
			fmt.Println()
			fmt.Println("Audit")
			fmt.Println("-----")
			fmt.Println("✓ Security event recorded")
			return fmt.Errorf("real npm installation failed: %w; rollback failed: %v", err, rollbackErr)
		}
		loggerRecord(logger, auditContext(auditEvent))
		fmt.Println()
		fmt.Println("Rolling back installation...")
		fmt.Println("✓ Project restored successfully.")
		fmt.Println()
		fmt.Println("Audit")
		fmt.Println("-----")
		fmt.Println("✓ Security event recorded")
		return fmt.Errorf("real npm installation failed: %w", err)
	}

	verifier := InstallationVerifier{ProjectDir: projectDir}
	verificationResult, verifyErr := verifier.Verify(packageArgs, parsed.Flags)
	fmt.Println()
	fmt.Println("Installation Verification")
	fmt.Println("-------------------------")
	for _, pkg := range verificationResult.Packages {
		if !pkg.Installed {
			fmt.Printf("✗ %s not installed\n", pkg.Name)
			continue
		}
		fmt.Printf("✓ %s@%s installed\n", pkg.Name, pkg.InstalledVersion)
		if pkg.RecordMatch {
			fmt.Printf("✓ Recorded in %s\n", pkg.RecordedIn)
		}
	}
	fmt.Println()
	fmt.Println("Lockfile")
	fmt.Println("--------")
	if _, err := os.Stat(filepath.Join(projectDir, "package-lock.json")); err == nil {
		if verificationResult.LockfileVerified {
			fmt.Println("✓ package-lock.json verified")
		} else {
			fmt.Println("✗ package-lock.json is invalid JSON")
		}
	} else {
		fmt.Println("✓ no package-lock.json present")
	}

	if verifyErr != nil {
		rollbackErr := backup.Restore()
		auditEvent := audit.Event{
			Packages:     append([]string(nil), packageArgs...),
			Risk:         string(result.Level),
			Score:        result.Score,
			FindingCount: result.FindingCount,
			Decision:     decisionStatus,
			Approval:     audit.ApprovalAccepted,
			Installation: audit.InstallationFailed,
			Verification: audit.VerificationFailed,
			Rollback:     audit.RollbackSucceeded,
			Reason:       verifyErr.Error(),
		}
		if rollbackErr != nil {
			auditEvent.Rollback = audit.RollbackFailed
			auditEvent.Reason = fmt.Sprintf("%s; rollback failed: %v", verifyErr.Error(), rollbackErr)
			loggerRecord(logger, auditContext(auditEvent))
			fmt.Println()
			fmt.Println("Rolling back installation...")
			fmt.Println("✗ Rollback failed.")
			fmt.Println()
			fmt.Println("WARNING: SafeRun could not completely restore the project.")
			fmt.Println("Manual recovery may be required.")
			fmt.Println()
			fmt.Println("Audit")
			fmt.Println("-----")
			fmt.Println("✓ Security event recorded")
			return fmt.Errorf("installation verification failed: %w; rollback failed: %v", verifyErr, rollbackErr)
		}
		loggerRecord(logger, auditContext(auditEvent))
		fmt.Println()
		fmt.Println("Rolling back installation...")
		fmt.Println("✓ Project restored successfully.")
		fmt.Println()
		fmt.Println("SafeRun installation failed.")
		fmt.Println("✓ Rollback completed.")
		fmt.Println()
		fmt.Println("Audit")
		fmt.Println("-----")
		fmt.Println("✓ Security event recorded")
		return verifyErr
	}

	auditEvent := audit.Event{
		Packages:     append([]string(nil), packageArgs...),
		Risk:         string(result.Level),
		Score:        result.Score,
		FindingCount: result.FindingCount,
		Decision:     decisionStatus,
		Approval:     audit.ApprovalAccepted,
		Installation: audit.InstallationSuccess,
		Verification: audit.VerificationPassed,
		Rollback:     audit.RollbackNotRequired,
	}
	if err := backup.Cleanup(); err != nil {
		auditEvent.Rollback = audit.RollbackFailed
		auditEvent.Reason = err.Error()
		loggerRecord(logger, auditContext(auditEvent))
		fmt.Println()
		fmt.Println("WARNING: SafeRun could not fully clean up backup artifacts.")
		fmt.Println()
		fmt.Println("Audit")
		fmt.Println("-----")
		fmt.Println("✓ Security event recorded")
		return fmt.Errorf("cleanup backup: %w", err)
	}
	loggerRecord(logger, auditContext(auditEvent))

	fmt.Println()
	fmt.Println("SafeRun completed successfully.")
	fmt.Println()
	fmt.Println("Audit")
	fmt.Println("-----")
	fmt.Println("✓ Security event recorded")
	return nil
}

func validateDownloadedPackageIdentity(expected registry.PackageInfo, source string) error {
	manifest, err := readPackageJSON(source)
	if err != nil {
		return err
	}
	if manifest.Name != expected.Name {
		return fmt.Errorf("package name mismatch: expected %q, got %q", expected.Name, manifest.Name)
	}
	if manifest.Version != expected.Version {
		return fmt.Errorf("package version mismatch: expected %q, got %q", expected.Version, manifest.Version)
	}
	return nil
}

func toAuditDecision(decision policy.Decision) audit.Decision {
	switch decision {
	case policy.Allow:
		return audit.DecisionAllow
	case policy.RequireConfirmation:
		return audit.DecisionConfirmationRequired
	default:
		return audit.DecisionBlock
	}
}

func (n NPM) auditLogger() audit.Logger {
	if n.AuditLogger.Path != "" {
		return n.AuditLogger
	}
	return audit.NewLogger()
}

func loggerRecord(logger audit.Logger, event audit.Event) {
	if err := logger.Record(event); err != nil {
		fmt.Printf("Warning: audit log unavailable: %v\n", err)
	}
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
