package main

import (
	"fmt"
	"os"

	"github.com/dag12y/saferun/internal/sandbox"
)

func main() {
	fmt.Println("SafeRun")
	fmt.Println("Secure package installation sandbox")
	fmt.Println()

	config := sandbox.Config{
		Image:   "saferun-node:dev",
		Network: "none",
		Memory:  "512m",
		CPUs:    "1",
	}

	if err := sandbox.Run(config, "node", "-e", "require('https').get('https://example.com')"); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
