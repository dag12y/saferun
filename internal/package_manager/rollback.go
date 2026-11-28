package package_manager

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type ProjectBackup struct {
	ProjectDir string
	BackupDir  string
	entries    []backupEntry
}

type backupEntry struct {
	Path       string
	Existed    bool
	BackupPath string
}

func createProjectBackup(projectDir string) (*ProjectBackup, error) {
	absProjectDir, err := filepath.Abs(projectDir)
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}
	absProjectDir, err = filepath.EvalSymlinks(absProjectDir)
	if err != nil {
		return nil, fmt.Errorf("inspect project root: %w", err)
	}

	backupDir, err := os.MkdirTemp("", "saferun-backup-")
	if err != nil {
		return nil, fmt.Errorf("create backup directory: %w", err)
	}

	backup := &ProjectBackup{ProjectDir: absProjectDir, BackupDir: backupDir}
	// npm can update or remove existing transitive packages during named and project installs.
	for _, name := range []string{"package.json", "package-lock.json", "npm-shrinkwrap.json", "node_modules"} {
		entry, err := capturePath(absProjectDir, backupDir, filepath.Join(absProjectDir, name))
		if err != nil {
			return nil, errors.Join(err, backup.Cleanup())
		}
		backup.entries = append(backup.entries, entry)
	}
	return backup, nil
}

func (b *ProjectBackup) Restore() error {
	if b == nil || b.BackupDir == "" {
		return nil
	}
	var restoreErrors []error
	for _, entry := range b.entries {
		if err := b.restoreEntry(entry); err != nil {
			restoreErrors = append(restoreErrors, err)
		}
	}
	if err := errors.Join(restoreErrors...); err != nil {
		return fmt.Errorf("restore project state (backup at %q): %w", b.BackupDir, err)
	}
	return b.Cleanup()
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
	if err := validateBackupTarget(projectDir, target); err != nil {
		return backupEntry{}, err
	}

	entry := backupEntry{Path: target}
	info, err := os.Lstat(target)
	if os.IsNotExist(err) {
		return entry, nil
	}
	if err != nil {
		return backupEntry{}, fmt.Errorf("stat %q: %w", target, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return backupEntry{}, fmt.Errorf("refusing to back up project entry symlink %q", target)
	}

	entry.Existed = true
	entry.BackupPath = filepath.Join(backupDir, filepath.Base(target))
	if err := copyBackupTree(target, entry.BackupPath); err != nil {
		return backupEntry{}, fmt.Errorf("back up %q: %w", target, err)
	}
	return entry, nil
}

func (b *ProjectBackup) restoreEntry(entry backupEntry) error {
	if err := validateBackupTarget(b.ProjectDir, entry.Path); err != nil {
		return err
	}
	// RemoveAll unlinks a replacement symlink without removing its target.
	if err := os.RemoveAll(entry.Path); err != nil {
		return fmt.Errorf("clear path %q before restore: %w", entry.Path, err)
	}
	if entry.Existed {
		if err := copyBackupTree(entry.BackupPath, entry.Path); err != nil {
			return fmt.Errorf("restore %q: %w", entry.Path, err)
		}
	}
	return nil
}

func validateBackupTarget(projectDir, target string) error {
	if filepath.Dir(filepath.Clean(target)) != projectDir {
		return fmt.Errorf("backup target must be directly inside the project root: %s", target)
	}
	return nil
}

func copyBackupTree(src, dst string) error {
	type directoryMode struct {
		path string
		mode os.FileMode
	}
	var directories []directoryMode
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case info.IsDir():
			directories = append(directories, directoryMode{path: target, mode: info.Mode().Perm()})
			return os.Mkdir(target, 0o700)
		case info.Mode().IsRegular():
			return copyBackupFile(path, target, info.Mode().Perm())
		case info.Mode()&os.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		default:
			return fmt.Errorf("unsupported file type for %q: %s", path, info.Mode())
		}
	})
	if err != nil {
		return err
	}
	for i := len(directories) - 1; i >= 0; i-- {
		if err := os.Chmod(directories[i].path, directories[i].mode); err != nil {
			return err
		}
	}
	return nil
}

func copyBackupFile(src, dst string, mode os.FileMode) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, out.Close()) }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Chmod(mode)
}
