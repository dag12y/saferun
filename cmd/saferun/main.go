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

	if err := sandbox.Run("npm", "install", "lodash"); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}