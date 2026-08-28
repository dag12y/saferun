package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
)

type FileSnapshot struct {
	Path string
	Size int64
	Mode os.FileMode
}

func SnapshotDirectory(root string) (map[string]FileSnapshot, error) {
	snapshot := make(map[string]FileSnapshot)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		relativePath, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("get relative path: %w", err)
		}

		snapshot[relativePath] = FileSnapshot{
			Path: relativePath,
			Size: info.Size(),
			Mode: info.Mode(),
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("snapshot directory: %w", err)
	}

	return snapshot, nil
}

type FileChanges struct {
	Created  []FileSnapshot
	Modified []FileSnapshot
	Deleted  []FileSnapshot
}

func CompareSnapshots(
	before map[string]FileSnapshot,
	after map[string]FileSnapshot,
) FileChanges {
	var changes FileChanges

	for path, afterFile := range after {
		beforeFile, exists := before[path]

		if !exists {
			changes.Created = append(changes.Created, afterFile)
			continue
		}

		if beforeFile.Size != afterFile.Size ||
			beforeFile.Mode != afterFile.Mode {
			changes.Modified = append(changes.Modified, afterFile)
		}
	}

	for path, beforeFile := range before {
		if _, exists := after[path]; !exists {
			changes.Deleted = append(changes.Deleted, beforeFile)
		}
	}

	return changes
}
