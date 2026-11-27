package semver

import (
	"fmt"
	"strconv"
	"strings"
)

// Version represents a parsed SemVer 2.0.0 version.
type Version struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease []string
}

// Parse parses a semantic version string (with optional leading "v").
func Parse(raw string) (Version, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return Version{}, fmt.Errorf("empty version")
	}

	if idx := strings.IndexByte(s, '+'); idx != -1 {
		s = s[:idx]
	}

	var pre []string
	if idx := strings.IndexByte(s, '-'); idx != -1 {
		preStr := s[idx+1:]
		if preStr == "" {
			return Version{}, fmt.Errorf("invalid prerelease in %q", raw)
		}
		pre = strings.Split(preStr, ".")
		s = s[:idx]
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("invalid semver %q", raw)
	}

	major, err := parseNonNegInt(parts[0])
	if err != nil {
		return Version{}, fmt.Errorf("invalid major version in %q: %w", raw, err)
	}
	minor, err := parseNonNegInt(parts[1])
	if err != nil {
		return Version{}, fmt.Errorf("invalid minor version in %q: %w", raw, err)
	}
	patch, err := parseNonNegInt(parts[2])
	if err != nil {
		return Version{}, fmt.Errorf("invalid patch version in %q: %w", raw, err)
	}

	return Version{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: pre,
	}, nil
}

func parseNonNegInt(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty number")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid number %q", s)
	}
	return n, nil
}

// Compare returns -1 if a < b, 0 if a == b, and 1 if a > b.
func Compare(a, b Version) int {
	if a.Major != b.Major {
		return cmpInt(a.Major, b.Major)
	}
	if a.Minor != b.Minor {
		return cmpInt(a.Minor, b.Minor)
	}
	if a.Patch != b.Patch {
		return cmpInt(a.Patch, b.Patch)
	}

	aPre, bPre := len(a.Prerelease) > 0, len(b.Prerelease) > 0
	if !aPre && !bPre {
		return 0
	}
	if !aPre {
		return 1
	}
	if !bPre {
		return -1
	}

	maxLen := len(a.Prerelease)
	if len(b.Prerelease) > maxLen {
		maxLen = len(b.Prerelease)
	}
	for i := 0; i < maxLen; i++ {
		if i >= len(a.Prerelease) {
			return -1
		}
		if i >= len(b.Prerelease) {
			return 1
		}
		if c := comparePrereleasePart(a.Prerelease[i], b.Prerelease[i]); c != 0 {
			return c
		}
	}
	return 0
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func comparePrereleasePart(a, b string) int {
	aNum, aErr := strconv.Atoi(a)
	bNum, bErr := strconv.Atoi(b)
	switch {
	case aErr == nil && bErr == nil:
		return cmpInt(aNum, bNum)
	case aErr == nil:
		return -1
	case bErr == nil:
		return 1
	default:
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	}
}

// IsRangeOrVersion reports whether raw looks like a semver version or range
// rather than an npm dist-tag such as "latest" or "next".
func IsRangeOrVersion(raw string) bool {
	s := strings.TrimSpace(raw)
	if s == "" {
		return false
	}
	first := s[0]
	if (first >= '0' && first <= '9') || first == '^' || first == '~' || first == '>' || first == '<' || first == '=' || first == '*' {
		return true
	}
	if (first == 'v' || first == 'V') && len(s) > 1 && s[1] >= '0' && s[1] <= '9' {
		return true
	}
	if s == "x" || s == "X" {
		return true
	}
	return false
}

// Satisfies reports whether versionStr satisfies the npm-style semver rangeStr.
func Satisfies(versionStr, rangeStr string) (bool, error) {
	v, err := Parse(versionStr)
	if err != nil {
		return false, err
	}

	clauses := strings.Split(rangeStr, "||")
	for _, clause := range clauses {
		ok, err := satisfiesClause(v, strings.TrimSpace(clause))
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// MaxSatisfying returns the highest non-prerelease (or matching prerelease) version
// from versions that satisfies rangeStr.
func MaxSatisfying(versions []string, rangeStr string) (string, error) {
	var bestRaw string
	var bestVer Version
	found := false

	for _, raw := range versions {
		v, err := Parse(raw)
		if err != nil {
			continue
		}
		// Skip prereleases unless explicitly matched by exact/prerelease range.
		if len(v.Prerelease) > 0 && !strings.Contains(rangeStr, "-") {
			continue
		}
		ok, err := Satisfies(raw, rangeStr)
		if err != nil {
			return "", err
		}
		if !ok {
			continue
		}
		if !found || Compare(v, bestVer) > 0 {
			bestRaw = raw
			bestVer = v
			found = true
		}
	}

	if !found {
		return "", fmt.Errorf("no version satisfies range %q", rangeStr)
	}
	return bestRaw, nil
}

func satisfiesClause(v Version, clause string) (bool, error) {
	if clause == "" || clause == "*" || clause == "x" || clause == "X" {
		return len(v.Prerelease) == 0, nil
	}

	tokens := strings.Fields(clause)
	for _, token := range tokens {
		ok, err := satisfiesComparator(v, token)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func satisfiesComparator(v Version, token string) (bool, error) {
	switch {
	case strings.HasPrefix(token, "^"):
		return satisfiesCaret(v, strings.TrimPrefix(token, "^"))
	case strings.HasPrefix(token, "~"):
		return satisfiesTilde(v, strings.TrimPrefix(token, "~"))
	case strings.HasPrefix(token, ">="):
		target, err := parsePartialLower(strings.TrimPrefix(token, ">="))
		if err != nil {
			return false, err
		}
		return Compare(v, target) >= 0, nil
	case strings.HasPrefix(token, "<="):
		target, upperExclusive, err := parsePartialUpper(strings.TrimPrefix(token, "<="))
		if err != nil {
			return false, err
		}
		if upperExclusive {
			return Compare(v, target) < 0, nil
		}
		return Compare(v, target) <= 0, nil
	case strings.HasPrefix(token, ">"):
		target, err := parsePartialLower(strings.TrimPrefix(token, ">"))
		if err != nil {
			return false, err
		}
		return Compare(v, target) > 0, nil
	case strings.HasPrefix(token, "<"):
		target, err := parsePartialLower(strings.TrimPrefix(token, "<"))
		if err != nil {
			return false, err
		}
		return Compare(v, target) < 0, nil
	case strings.HasPrefix(token, "="):
		return satisfiesExactOrWildcard(v, strings.TrimPrefix(token, "="))
	default:
		return satisfiesExactOrWildcard(v, token)
	}
}

func satisfiesCaret(v Version, raw string) (bool, error) {
	parts, pre, err := parsePartialParts(raw)
	if err != nil {
		return false, err
	}
	lower := Version{Major: parts[0], Minor: parts[1], Patch: parts[2], Prerelease: pre}
	if Compare(v, lower) < 0 {
		return false, nil
	}

	var upper Version
	switch {
	case parts[0] > 0:
		upper = Version{Major: parts[0] + 1}
	case len(parts) > 1 && parts[1] > 0:
		upper = Version{Major: 0, Minor: parts[1] + 1}
	default:
		upper = Version{Major: 0, Minor: 0, Patch: parts[2] + 1}
	}
	return Compare(v, upper) < 0, nil
}

func satisfiesTilde(v Version, raw string) (bool, error) {
	parts, pre, err := parsePartialParts(raw)
	if err != nil {
		return false, err
	}
	lower := Version{Major: parts[0], Minor: parts[1], Patch: parts[2], Prerelease: pre}
	if Compare(v, lower) < 0 {
		return false, nil
	}

	var upper Version
	if parts[3] == 1 { // only major specified, e.g. ~1
		upper = Version{Major: parts[0] + 1}
	} else {
		upper = Version{Major: parts[0], Minor: parts[1] + 1}
	}
	return Compare(v, upper) < 0, nil
}

func satisfiesExactOrWildcard(v Version, raw string) (bool, error) {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(raw, "v"), "V"))
	if s == "*" || s == "x" || s == "X" {
		return len(v.Prerelease) == 0, nil
	}
	if target, err := Parse(s); err == nil {
		return Compare(v, target) == 0, nil
	}
	segs := strings.Split(s, ".")
	if len(segs) >= 1 && !isWildcard(segs[0]) {
		major, err := parseNonNegInt(segs[0])
		if err != nil {
			return false, err
		}
		if len(segs) == 1 || isWildcard(segs[1]) {
			return v.Major == major && len(v.Prerelease) == 0, nil
		}
		minor, err := parseNonNegInt(segs[1])
		if err != nil {
			return false, err
		}
		if len(segs) == 2 || isWildcard(segs[2]) {
			return v.Major == major && v.Minor == minor && len(v.Prerelease) == 0, nil
		}
	}
	return false, fmt.Errorf("invalid version comparator %q", raw)
}

func isWildcard(s string) bool {
	return s == "*" || s == "x" || s == "X"
}

// parsePartialParts returns [major, minor, patch, specifiedCount], prerelease, error.
func parsePartialParts(raw string) ([4]int, []string, error) {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(raw, "v"), "V"))
	if idx := strings.IndexByte(s, '+'); idx != -1 {
		s = s[:idx]
	}
	var pre []string
	if idx := strings.IndexByte(s, '-'); idx != -1 {
		pre = strings.Split(s[idx+1:], ".")
		s = s[:idx]
	}
	segs := strings.Split(s, ".")
	if len(segs) == 0 || len(segs) > 3 {
		return [4]int{}, nil, fmt.Errorf("invalid semver %q", raw)
	}
	var out [4]int
	count := 0
	for i, seg := range segs {
		if isWildcard(seg) {
			break
		}
		val, err := parseNonNegInt(seg)
		if err != nil {
			return [4]int{}, nil, err
		}
		out[i] = val
		count++
	}
	if count == 0 {
		return [4]int{}, nil, fmt.Errorf("invalid semver %q", raw)
	}
	out[3] = count
	return out, pre, nil
}

func parsePartialLower(raw string) (Version, error) {
	parts, pre, err := parsePartialParts(raw)
	if err != nil {
		return Version{}, err
	}
	return Version{Major: parts[0], Minor: parts[1], Patch: parts[2], Prerelease: pre}, nil
}

func parsePartialUpper(raw string) (Version, bool, error) {
	parts, pre, err := parsePartialParts(raw)
	if err != nil {
		return Version{}, false, err
	}
	if parts[3] == 1 {
		return Version{Major: parts[0] + 1}, true, nil
	}
	if parts[3] == 2 {
		return Version{Major: parts[0], Minor: parts[1] + 1}, true, nil
	}
	return Version{Major: parts[0], Minor: parts[1], Patch: parts[2], Prerelease: pre}, false, nil
}
