package main

import (
	"strings"
	"testing"
)

// TestAddSpec tests that we can add items to a database
func TestAddSpec(t *testing.T) {
	testdb := NewDatabase()

	testdb.AddSpec("foo/bar", []string{">=1.0", "<1.9"})

	if len(testdb.specs) != 1 {
		t.Error("wrong db size after element has been added")
	}

}

func TestCheckSpec(t *testing.T) {
	cases := []struct {
		constraint string
		version    string
		expected   bool
	}{
		{">=1.0,<1.9", "0.9999", false},
		{">=1.0,<1.9", "1.0", true},
		{">=1.0,<1.9", "1.2.3", true},
		// { ">=1.0,<1.9", "1.2.3.4-rc1-with-hypen", true},
		// { ">=1.0,<1.9", "v1.8rc2", true},
		{">=1.0,<1.9", "1.8", true},
		// { ">=1.0,<1.9", "v1.9rc2", true},
		// { ">=1.0,<1.9", "1.9rc2", true},
		{">=1.0,<1.9", "1.9", false},
		{">=1.0,<1.9", "1.89", false},
		{"<1.9", "1.8", true},
		{"<1.9", "1.9", false},
	}

	for _, tc := range cases {
		testdb := NewDatabase()
		testdb.AddSpec("foo/bar", strings.Split(tc.constraint, ","))
		vuln, err := testdb.Vulnerable("foo/bar", tc.version)
		// t.Logf("version %s is %t", tc.version, vuln)
		if err != nil {
			t.Fatal("unexpected error")
		}
		if vuln != tc.expected {
			t.Errorf("foo/bat version %s should be %t", tc.version, tc.expected)
		}
	}

}
