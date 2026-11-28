package prompt

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func NewConfirmer(input io.Reader, output io.Writer) func(string) bool {
	reader := bufio.NewReader(input)
	return func(message string) bool {
		fmt.Fprintf(output, "%s [y/N]: ", message)
		answer, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return false
		}
		answer = strings.TrimSpace(strings.ToLower(answer))
		return answer == "y" || answer == "yes"
	}
}
