package package_manager

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type ProjectBackup struct {
	ProjectDir string
	BackupDir  string
	entries    []backupEntry
}

type backupEntry struct {
	Path       string
	Existed    bool
	IsDir      bool
	BackupPath string
}

func createProjectBackup(projectDir string, packageSpecs []string) (*ProjectBackup, error) {
	absProjectDir, err := filepath.Abs(projectDir)
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}

	backupDir, err := os.MkdirTemp("", "saferun-backup-")
	if err != nil {
		return nil, fmt.Errorf("create backup directory: %w", err)
	}

	backup := &ProjectBackup{
		ProjectDir: absProjectDir,
		BackupDir:  backupDir,
	}

	paths := collectBackupTargets(absProjectDir, packageSpecs)
	for _, target := range paths {
		entry, err := capturePath(absProjectDir, backupDir, target)
		if err != nil {
			_ = os.RemoveAll(backupDir)
			return nil, err
		}
		backup.entries = append(backup.entries, entry)
	}
	return backup, nil
}

func collectBackupTargets(projectDir string, packageSpecs []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(packageSpecs)+4)
	addPath := func(path string) {
		if path == "" {
			return
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return
		}
		if _, ok := seen[abs]; ok {
			return
		}
		seen[abs] = struct{}{}
		result = append(result, abs)
	}

	addPath(filepath.Join(projectDir, "package.json"))
	if lockfilePath := filepath.Join(projectDir, "package-lock.json"); fileExists(lockfilePath) {
		addPath(lockfilePath)
	}
	for _, spec := range packageSpecs {
		pkgName, _, err := resolveRequestedPackage(spec, projectDir)
		if err != nil {
			continue
		}
		addPath(filepath.Join(projectDir, "node_modules", pkgName))
	}
	return result
}

func (b *ProjectBackup) Restore() error {
	if b == nil {
		return nil
	}
	var errs []string
	for _, entry := range b.entries {
		if err := restoreEntry(entry); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("restore project state: %s", strings.Join(errs, "; "))
	}
	if err := b.Cleanup(); err != nil {
		return fmt.Errorf("cleanup backup after restore: %w", err)
	}
	return nil
}

func (b *ProjectBackup) Cleanup() error {
	if b == nil || b.BackupDir == "" {
		return nil
	}
	if err := os.RemoveAll(b.BackupDir); err != nil {
		return fmt.Errorf("remove backup directory %q: %w", b.BackupDir, err)
	}
	b.BackupDir = ""
	return nil
}

func capturePath(projectDir, backupDir, target string) (backupEntry, error) {
	cleanTarget, err := filepath.Abs(target)
	if err != nil {
		return backupEntry{}, fmt.Errorf("resolve path %q: %w", target, err)
	}
	if err := ensureInsideProject(projectDir, cleanTarget); err != nil {
		return backupEntry{}, err
	}

	entry := backupEntry{Path: cleanTarget}
	info, err := os.Lstat(cleanTarget)
	if err != nil {
		if os.IsNotExist(err) {
			entry.Existed = false
			return entry, nil
		}
		return backupEntry{}, fmt.Errorf("stat %q: %w", cleanTarget, err)
	}
	entry.Existed = true
	entry.IsDir = info.IsDir()
	if info.Mode()&os.ModeSymlink != 0 {
		return backupEntry{}, fmt.Errorf("refusing to back up symlink %q", cleanTarget)
	}

	relativePath, err := filepath.Rel(projectDir, cleanTarget)
	if err != nil {
		return backupEntry{}, fmt.Errorf("compute relative path for %q: %w", cleanTarget, err)
	}
	backupPath := filepath.Join(backupDir, relativePath)
	entry.BackupPath = backupPath
	if info.IsDir() {
		if err := os.MkdirAll(backupPath, 0o755); err != nil {
			return backupEntry{}, fmt.Errorf("create backup dir for %q: %w", cleanTarget, err)
		}
		if err := copyDirectory(cleanTarget, backupPath); err != nil {
			return backupEntry{}, fmt.Errorf("copy directory %q to backup: %w", cleanTarget, err)
		}
		return entry, nil
	}
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o755); err != nil {
		return backupEntry{}, fmt.Errorf("create backup parent for %q: %w", cleanTarget, err)
	}
	if err := copyFile(cleanTarget, backupPath); err != nil {
		return backupEntry{}, fmt.Errorf("copy file %q to backup: %w", cleanTarget, err)
	}
	return entry, nil
}

func restoreEntry(entry backupEntry) error {
	if !entry.Existed {
		if err := os.RemoveAll(entry.Path); err != nil {
			return fmt.Errorf("remove newly created path %q: %w", entry.Path, err)
		}
		return nil
	}
	if err := ensureInsideProject(filepath.Dir(entry.Path), entry.Path); err != nil {
		return err
	}
	if err := os.RemoveAll(entry.Path); err != nil {
		return fmt.Errorf("clear path %q before restore: %w", entry.Path, err)
	}
	if err := os.MkdirAll(filepath.Dir(entry.Path), 0o755); err != nil {
		return fmt.Errorf("create parent dir for %q: %w", entry.Path, err)
	}
	if entry.IsDir {
		if err := copyDirectory(entry.BackupPath, entry.Path); err != nil {
			return fmt.Errorf("restore directory %q: %w", entry.Path, err)
		}
		return nil
	}
	if err := copyFile(entry.BackupPath, entry.Path); err != nil {
		return fmt.Errorf("restore file %q: %w", entry.Path, err)
	}
	return nil
}

func ensureInsideProject(projectDir, candidate string) error {
	absProject, err := filepath.Abs(projectDir)
	if err != nil {
		return fmt.Errorf("resolve project root: %w", err)
	}
	absCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return fmt.Errorf("resolve candidate path: %w", err)
	}
	rel, err := filepath.Rel(absProject, absCandidate)
	if err != nil {
		return fmt.Errorf("compute relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == "" && absCandidate != absProject {
		return fmt.Errorf("path escapes project root: %s", candidate)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func copyDirectory(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to copy symlink %q", path)
		}
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := copyFile(path, target); err != nil {
			return err
		}
		return os.Chmod(target, info.Mode())
	})
}
