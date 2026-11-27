package semver

import "testing"

func TestSatisfies(t *testing.T) {
	cases := []struct {
		version string
		expr    string
		want    bool
	}{
		{"4.17.21", "4.17.21", true},
		{"4.17.21", "4.18.1", false},
		{"4.17.21", "^4.17.0", true},
		{"4.18.0", "^4.17.21", true},
		{"5.0.0", "^4.17.21", false},
		{"0.2.5", "^0.2.3", true},
		{"0.3.0", "^0.2.3", false},
		{"0.0.3", "^0.0.3", true},
		{"0.0.4", "^0.0.3", false},
		{"4.17.25", "~4.17.21", true},
		{"4.18.0", "~4.17.21", false},
		{"2.1.0", ">=2.0.0 <3.0.0", true},
		{"3.0.0", ">=2.0.0 <3.0.0", false},
		{"1.5.0", "1.x", true},
		{"2.0.0", "1.x", false},
		{"1.5.2", "1.5.x", true},
		{"2.1.0", "^1.0.0 || ^2.0.0", true},
		{"3.0.0", "^1.0.0 || ^2.0.0", false},
		{"1.2.3-beta.1", "1.2.3-beta.1", true},
	}

	for _, tc := range cases {
		got, err := Satisfies(tc.version, tc.expr)
		if err != nil {
			t.Fatalf("Satisfies(%q, %q) unexpected error: %v", tc.version, tc.expr, err)
		}
		if got != tc.want {
			t.Errorf("Satisfies(%q, %q) = %v, want %v", tc.version, tc.expr, got, tc.want)
		}
	}
}

func TestMaxSatisfying(t *testing.T) {
	versions := []string{"4.17.19", "4.17.21", "4.18.0", "5.0.0-alpha.1", "5.0.0"}

	got, err := MaxSatisfying(versions, "^4.17.0")
	if err != nil {
		t.Fatalf("MaxSatisfying: %v", err)
	}
	if got != "4.18.0" {
		t.Fatalf("expected 4.18.0, got %s", got)
	}

	got, err = MaxSatisfying(versions, "~4.17.19")
	if err != nil {
		t.Fatalf("MaxSatisfying: %v", err)
	}
	if got != "4.17.21" {
		t.Fatalf("expected 4.17.21, got %s", got)
	}
}

func TestIsRangeOrVersion(t *testing.T) {
	for _, s := range []string{"1.2.3", "v1.2.3", "^1.0.0", "~2.1.0", ">=1.0.0", "*", "x"} {
		if !IsRangeOrVersion(s) {
			t.Errorf("expected IsRangeOrVersion(%q) = true", s)
		}
	}
	for _, s := range []string{"latest", "next", "beta", "canary", ""} {
		if IsRangeOrVersion(s) {
			t.Errorf("expected IsRangeOrVersion(%q) = false", s)
		}
	}
}
