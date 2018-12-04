package main

import (
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	version "github.com/hashicorp/go-version"
)

type versionSpecs struct {
	constraint string
}

type vulnSpec []versionSpecs

type vulnDatabase struct {
	sync.Mutex
	specs map[string]vulnSpec
}

// NewDatabase returns an empty vulnerabilities database
func NewDatabase() *vulnDatabase {
	return &vulnDatabase{
		specs: make(map[string]vulnSpec),
	}
}

// AddSpec adds vulnerable version bounds for a package
func (db *vulnDatabase) AddSpec(key string, constraint []string) {
	db.Lock()
	defer db.Unlock()

	log.Debugf("adding spec for %s: %v", key, constraint)

	// If package is unknown, create it's structure
	if _, ok := db.specs[key]; !ok {
		db.specs[key] = vulnSpec{}
	}

	db.specs[key] = append(db.specs[key], versionSpecs{strings.Join(constraint, ",")})
}

// Vulnerable returns true if package is vulnerable, false otherwise.
func (db *vulnDatabase) Vulnerable(pkg, vrs string) (bool, error) {
	db.Lock()
	defer db.Unlock()

	v, err := version.NewVersion(vrs)

	if err != nil {
		return true, err
	}
	// When pkg is not in the database, we
	if _, ok := db.specs[pkg]; !ok {
		return false, nil
	}

	for _, sp := range db.specs[pkg] {
		constraints, err := version.NewConstraint(sp.constraint)

		if err != nil {
			return true, err
		}

		if constraints.Check(v) {
			return true, nil
		}
	}

	return false, nil
}
