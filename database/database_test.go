package database

import (
	"strings"
	"testing"
)

// TestAddSpec tests that we can add items to a database
func TestAddSpec(t *testing.T) {
	testdb := NewDatabase()

	addSpec(testdb, "foo/bar", []string{">=1.0", "<1.9"})

	if len(testdb.packages) != 1 {
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
		addSpec(testdb, "foo/bar", strings.Split(tc.constraint, ","))
		vuln, err := testdb.Vulnerable("foo/bar", tc.version)
		// t.Logf("version %s is %t", tc.version, vuln)
		if err != nil {
			t.Fatalf("unexpected error %v", err)
		}
		if (len(vuln) != 0) != tc.expected {
			t.Errorf("foo/bat version %s should be %t (len(vuln) is %d, len(vuln) != 0 is %t, tc.expected is %t)",
				tc.version, tc.expected, len(vuln), len(vuln) != 0, tc.expected)
		}
	}
}

func addSpec(db *VulnDatabase, key string, versions []string) {
	if _, ok := db.packages[key]; !ok {
		db.packages[key] = []FoFSecurityAdvisory{}
	}

	vuln := FoFSecurityAdvisory{
		Branches: map[string]struct {
			Time     string   `yaml:"time"`
			Versions []string `yaml:"versions"`
		}{},
	}
	master := vuln.Branches["master"]
	master.Versions = versions
	vuln.Branches["master"] = master

	db.packages[key] = append(db.packages[key], vuln)
}
