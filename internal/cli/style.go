package cli

import (
	"strings"

	"github.com/fatih/color"
)

var (
	headingColor = color.New(color.Bold, color.FgCyan)
	successColor = color.New(color.FgGreen)
	warningColor = color.New(color.FgYellow)
	dangerColor  = color.New(color.FgRed)
	mutedColor   = color.New(color.Faint)
)

func Heading(text string) string { return headingColor.Sprint(text) }

func Success(text string) string { return successColor.Sprint(text) }

func Warning(text string) string { return warningColor.Sprint(text) }

func Danger(text string) string { return dangerColor.Sprint(text) }

func Muted(text string) string { return mutedColor.Sprint(text) }

func Severity(level, text string) string {
	switch strings.ToUpper(level) {
	case "CRITICAL", "HIGH":
		return Danger(text)
	case "MEDIUM":
		return Warning(text)
	default:
		return Success(text)
	}
}

func Risk(level, text string) string { return Severity(level, text) }

func Decision(decision, text string) string {
	switch strings.ToUpper(decision) {
	case "BLOCK":
		return dangerColor.Add(color.Bold).Sprint(text)
	case "CONFIRMATION_REQUIRED", "PROMPT":
		return warningColor.Add(color.Bold).Sprint(text)
	default:
		return successColor.Add(color.Bold).Sprint(text)
	}
}
