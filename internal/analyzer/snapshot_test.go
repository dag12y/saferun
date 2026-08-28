package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotAndCompare(t *testing.T) {
	root := t.TempDir()

	before, err := SnapshotDirectory(root)
	if err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(root, "created.txt")

	if err := os.WriteFile(file, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	after, err := SnapshotDirectory(root)
	if err != nil {
		t.Fatal(err)
	}

	changes := CompareSnapshots(before, after)

	if len(changes.Created) != 1 {
		t.Fatalf(
			"expected 1 created file, got %d",
			len(changes.Created),
		)
	}

	if changes.Created[0].Path != "created.txt" {
		t.Fatalf(
			"expected created.txt, got %s",
			changes.Created[0].Path,
		)
	}
}
