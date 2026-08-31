package policy

import (
	"fmt"

	"github.com/dag12y/saferun/internal/risk"
)

type Decision int

const (
	Allow Decision = iota
	RequireConfirmation
	Block
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "ALLOW"
	case RequireConfirmation:
		return "CONFIRMATION REQUIRED"
	case Block:
		return "BLOCK"
	default:
		return "UNKNOWN"
	}
}

func Evaluate(report risk.Report) (Decision, string, error) {
	switch report.Level {
	case "":
		return Block, "", fmt.Errorf("unable to determine security policy decision")
	case risk.Low:
		return Allow, "", nil
	case risk.Medium:
		return RequireConfirmation, "Medium-risk behavior detected.", nil
	case risk.High:
		return Block, "High-risk behavior detected.", nil
	case risk.Critical:
		return Block, "Critical security finding detected.", nil
	default:
		return Block, "", fmt.Errorf("unable to determine security policy decision")
	}
}
