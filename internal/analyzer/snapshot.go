package analyzer

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type FileSnapshot struct {
	Path string
	Size int64
	Mode os.FileMode
	Hash [32]byte
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
		relativePath = filepath.ToSlash(relativePath)

		var hash [32]byte
		if info.Mode().IsRegular() {
			fileHash, hashErr := hashFile(path)
			if hashErr != nil {
				return fmt.Errorf("hash file %q: %w", relativePath, hashErr)
			}
			hash = fileHash
		}

		snapshot[relativePath] = FileSnapshot{
			Path: relativePath,
			Size: info.Size(),
			Mode: info.Mode(),
			Hash: hash,
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("snapshot directory: %w", err)
	}

	return snapshot, nil
}

func hashFile(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
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
			beforeFile.Mode != afterFile.Mode ||
			beforeFile.Hash != afterFile.Hash {
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
