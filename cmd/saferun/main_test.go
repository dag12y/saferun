package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestWriteJSONErrorProducesValidJSON(t *testing.T) {
	originalStdout := os.Stdout
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = write
	writeJSONError(os.ErrNotExist)
	_ = write.Close()
	os.Stdout = originalStdout

	var response map[string]string
	if err := json.NewDecoder(read).Decode(&response); err != nil {
		t.Fatalf("decode JSON error: %v", err)
	}
	if response["error"] == "" || response["message"] == "" {
		t.Fatalf("incomplete JSON error: %v", response)
	}
}
