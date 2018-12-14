package database

import (
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	version "github.com/hashicorp/go-version"
)

// FoFSecurityAdvisory holds a FriendsOfSymfony advisory
type FoFSecurityAdvisory struct {
	Title    string `yaml:"title"`
	Link     string `yaml:"link"`
	CVE      string `yaml:"cve"`
	Branches map[string]struct {
		Time     string   `yaml:"time"`
		Versions []string `yaml:"versions"`
	} `yaml:"branches"`
	Reference string `yaml:"reference"`
}

// VulnDatabase is a map of FoFSecurityAdvisory list
// Each key is a package name, and contains a FoFSecurityAdvisory list
type VulnDatabase struct {
	sync.Mutex
	packages map[string][]FoFSecurityAdvisory
}

// NewDatabase returns an empty vulnerabilities database
func NewDatabase() *VulnDatabase {
	return &VulnDatabase{
		packages: make(map[string][]FoFSecurityAdvisory),
	}
}

// AddVulnerability adds vulnerable version bounds for a package
func (db *VulnDatabase) AddVulnerability(key string, vuln FoFSecurityAdvisory) {
	db.Lock()
	defer db.Unlock()

	log.Debugf("adding vulnerability for %s", key)

	// If package is unknown, create it's structure
	if _, ok := db.packages[key]; !ok {
		db.packages[key] = []FoFSecurityAdvisory{}
	}

	db.packages[key] = append(db.packages[key], vuln)
}

// Vulnerable returns true if package is vulnerable, false otherwise.
func (db *VulnDatabase) Vulnerable(pkg, vrs string) ([]FoFSecurityAdvisory, error) {
	db.Lock()
	defer db.Unlock()

	v, err := version.NewVersion(vrs)

	if err != nil {
		return nil, err
	}
	// When pkg is not in the database, we
	if _, ok := db.packages[pkg]; !ok {
		return nil, nil
	}

	var advisories []FoFSecurityAdvisory

	// We have multiple advisories per package, don't forget that !
	for _, adv := range db.packages[pkg] {
		// and multiple branches per advisories
		for _, br := range adv.Branches {
			constraints, err := version.NewConstraint(strings.Join(br.Versions, ","))

			if err != nil {
				return advisories, err
			}

			if constraints.Check(v) {
				// could be nice to propose versions !
				advisories = append(advisories, adv)
			}
			// }
		}
	}

	return advisories, nil
}
