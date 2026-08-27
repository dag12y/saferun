package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func Confirm(message string) bool {
	fmt.Printf("%s [y/N]: ", message)

	reader := bufio.NewReader(os.Stdin)

	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	input = strings.TrimSpace(strings.ToLower(input))

	return input == "y" || input == "yes"
}
