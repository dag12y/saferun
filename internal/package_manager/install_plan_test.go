package package_manager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyInstalledTreeRequiresApprovedPackages(t *testing.T) {
	project := t.TempDir()
	approved := filepath.Join(project, lockName)
	approvedEntry := lockPackage{
		Version: "1.2.3", Resolved: "https://registry.npmjs.org/demo/-/demo-1.2.3.tgz", Integrity: testIntegrity(),
	}
	const approvedKey = "node_modules/demo"
	writeProjectJSON(t, approved, lockfile{
		LockfileVersion: 3,
		Packages:        map[string]lockPackage{"": {}, approvedKey: approvedEntry},
	})
	if err := os.Mkdir(filepath.Join(project, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	plan := &installPlan{}
	if err := verifyInstalledTreeAgainst(project, approved, plan); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected a missing dependency error, got %v", err)
	}
	pkgDir := filepath.Join(project, filepath.FromSlash(approvedKey))
	if err := os.Mkdir(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeProjectJSON(t, filepath.Join(pkgDir, manifestName), packageJSON{Name: "demo", Version: "1.2.3"})
	writeProjectJSON(t, filepath.Join(project, "node_modules", ".package-lock.json"), lockfile{
		LockfileVersion: 3,
		Packages:        map[string]lockPackage{approvedKey: approvedEntry},
	})
	if err := verifyInstalledTreeAgainst(project, approved, plan); err != nil {
		t.Fatal(err)
	}
	approvedEntry.Integrity += "changed"
	writeProjectJSON(t, filepath.Join(project, "node_modules", ".package-lock.json"), lockfile{
		LockfileVersion: 3,
		Packages:        map[string]lockPackage{approvedKey: approvedEntry},
	})
	if err := verifyInstalledTreeAgainst(project, approved, plan); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("expected an integrity mismatch, got %v", err)
	}
}

func TestProjectInputsAreCheckedAgainBeforeInstallation(t *testing.T) {
	project := t.TempDir()
	writeProjectJSON(t, filepath.Join(project, manifestName), packageJSON{Name: "demo", Version: "1.2.3"})
	writeProjectJSON(t, filepath.Join(project, lockName), lockfile{
		LockfileVersion: 3, Packages: map[string]lockPackage{"": {Name: "demo", Version: "1.2.3"}},
	})
	plan, err := prepareInstallPlan(project, InstallArgs{}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.cleanup()

	writeProjectJSON(t, filepath.Join(project, manifestName), packageJSON{Name: "edited"})
	if err := plan.checkOriginal(project); err == nil || !strings.Contains(err.Error(), "changed during analysis") {
		t.Fatalf("expected manifest drift error, got %v", err)
	}
}
