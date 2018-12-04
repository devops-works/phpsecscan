package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	flag "github.com/namsral/flag"
	log "github.com/sirupsen/logrus"
	git "gopkg.in/libgit2/git2go.v26"
	yaml "gopkg.in/yaml.v2"
)

// title:     HTTP Proxy header vulnerability
// link:      https://github.com/guzzle/guzzle/releases/tag/6.2.1
// cve:       CVE-2016-5385
// branches:
//     master:
//         time:     2015-07-15 17:14:23
//         versions: ['>=6', '<6.2.1']
//     4.x:
//         time:     2015-07-15 17:36:08
//         versions: ['>=4.0.0-rc2', '<4.2.4']
//     "5.3":
//         time:     2015-07-15 19:28:39
//         versions: ['>=5', '<5.3.1']
// reference: composer://guzzlehttp/guzzle

type fofSecurityAdvisory struct {
	Title    string `yaml:"title"`
	Link     string `yaml:"link"`
	CVE      string `yaml:"cve"`
	Branches map[string]struct {
		Time     string   `yaml:"time"`
		Versions []string `yaml:"versions"`
	} `yaml:"branches"`
	Reference string `yaml:"reference"`
}

type composerLock struct {
	Readme      []string `json:"_readme"`
	ContentHash string   `json:"content-hash"`
	Packages    []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Source  struct {
			Type      string `json:"type"`
			URL       string `json:"url"`
			Reference string `json:"reference"`
		} `json:"packages"`
		Dist struct {
			Type      string `json:"type"`
			URL       string `json:"url"`
			Reference string `json:"reference"`
			SHAsum    string `json:"shasum"`
		} `json:"dist"`
		// Require struct {
		//   InRequire string
		// } `json:"require"`
		// Conflict struct {
		//   InConflict string
		// } `json:"conflict"`
		// Require struct {
		//   InRequire string
		// } `json:"require"`

	} `json:"packages"`
}

var database *vulnDatabase
var sha1 string

// could be cool to use it as a:
// - cli
// - web service server
func main() {
	var err error
	var help, isDebug bool
	var gitDirectory, serverPort, uri string
	var syncInterval int

	flag.StringVar(&gitDirectory, "gitdir", "", "Path to store CVE git checkout")
	flag.BoolVar(&isDebug, "debug", false, "Debug mode")
	flag.StringVar(&serverPort, "port", "8080", "Server port")
	flag.StringVar(&uri, "repo", "https://github.com/FriendsOfPHP/security-advisories.git", "CVE repository")
	flag.IntVar(&syncInterval, "interval", 600, "Interval between CVE repository sync")
	flag.BoolVar(&help, "help", false, "Help usage")
	flag.BoolVar(&help, "h", false, "Help usage")

	flag.Parse()

	if help {
		flag.Usage()
		os.Exit(0)
	}

	// Setup logging
	if isDebug {
		setupLogging(log.DebugLevel)
	} else {
		setupLogging(log.InfoLevel)
	}

	// If gitDirectory is not set, get a temporary directory
	// because we still need to checkkout somewhere
	// This directory will be removed afterwards
	if gitDirectory == "" {
		gitDirectory, err = ioutil.TempDir("", "phpsecscan")
		log.Debugf("created temporary directory: %s", gitDirectory)

		if err != nil {
			log.Panicf("unable to create temporary directory: %v", err)
		}
		defer os.RemoveAll(gitDirectory)
	}

	// If dir does not exist, clone it
	if _, err := os.Stat(gitDirectory + "/.git"); os.IsNotExist(err) {
		clone(uri, gitDirectory)
	}

	database, err = createDb(gitDirectory)

	if err != nil {
		log.Fatalf("unable to create database: %v", err)
	}

	// create a goroutine that periodically syncs
	// go run sync() every X

	// we'll need a:
	// - in memory struct to index CVEs
	// - mutex to control access to this struct

	if flag.NArg() == 1 {
		// scan once
		jsonData, err := ioutil.ReadFile(flag.Arg(0))

		if err != nil {
			log.Fatalf("unable to open %s: %v", flag.Arg(0), err)
			os.Exit(1)
		}

		// jsonData := []byte(`{"_readme":["This file locks the dependencies of your project to a known state","Read more about it at https://getcomposer.org/doc/01-basic-usage.md#installing-dependencies","This file is @generated automatically"],"content-hash":"65a253e04313f9b5ce326594dfa89789","packages":[{"name":"algatux/influxdb-bundle","version":"2.1.4","source":{"type":"git","url":"https://github.com/Algatux/influxdb-bundle.git","reference":"aa2c9aaef77a5cd5ac9d964c5e4f928a42d51fe6"},"dist":{"type":"zip","url":"https://api.github.com/repos/Algatux/influxdb-bundle/zipball/aa2c9aaef77a5cd5ac9d964c5e4f928a42d51fe6","reference":"aa2c9aaef77a5cd5ac9d964c5e4f928a42d51fe6","shasum":""},"require":{"influxdb/influxdb-php":"^1.2","php":"^7.0","symfony/console":"^2.8 || ^3.0 || ^4.0","symfony/framework-bundle":"^2.8 || ^3.0 || ^4.0"},"conflict":{"symfony/form":"<2.8"},"require-dev":{"matthiasnoback/symfony-dependency-injection-test":"^1.0","symfony/form":"^2.8 || ^3.0 || ^4.0","symfony/phpunit-bridge":"^4.0"},"suggest":{"symfony/form":"Needed for form types usage"},"type":"symfony-bundle","extra":{"branch-alias":{"dev-master":"2.x-dev"}},"autoload":{"psr-4":{"Algatux\\InfluxDbBundle\\":"src/"}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Sullivan SENECHAL","email":"soullivaneuh@gmail.com"},{"name":"Alessandro Galli","email":"a.galli85@gmail.com"}],"description":"Bundle service integration of official influxdb/influxdb-php client","keywords":["database","influxdb","symfony"],"time":"2018-02-27T14:11:13+00:00"},{"name":"algolia/algoliasearch-client-php","version":"1.27.0","source":{"type":"git","url":"https://github.com/algolia/algoliasearch-client-php.git","reference":"d4e83cd7756bafff1e1cb2adcbf3c08b974dc263"},"dist":{"type":"zip","url":"https://api.github.com/repos/algolia/algoliasearch-client-php/zipball/d4e83cd7756bafff1e1cb2adcbf3c08b974dc263","reference":"d4e83cd7756bafff1e1cb2adcbf3c08b974dc263","shasum":""},"require":{"ext-curl":"*","ext-mbstring":"*","php":">=5.3"},"require-dev":{"phpunit/phpunit":"^4.8.35 || ^5.7 || ^6.4","satooshi/php-coveralls":"^1.0"},"type":"library","autoload":{"psr-0":{"AlgoliaSearch":"src/"}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"authors":[{"name":"Algolia Team","email":"contact@algolia.com"},{"name":"Ryan T. Catlin","email":"ryan.catlin@gmail.com"},{"name":"Jonathan H. Wage","email":"jonwage@gmail.com"}],"description":"Algolia Search API Client for PHP","homepage":"https://github.com/algolia/algoliasearch-client-php","time":"2018-06-19T05:59:53+00:00"}],"aliases":[],"minimum-stability":"stable","stability-flags":{"snc/redis-bundle":20,"xsolve-pl/xsolve-cookie-acknowledgement-bundle":20,"yproximite/common":20,"behat/mink":20},"prefer-stable":false,"prefer-lowest":false,"platform":{"php":">=7.2"},"platform-dev":[],"platform-overrides":{"php":"7.2.4"}}`)

		// var v interface{}
		var v composerLock
		json.Unmarshal(jsonData, &v)

		for _, val := range v.Packages {
			status, err := database.Vulnerable(val.Name, val.Version)

			log.Debugf("package %s (%s) is %t\n", val.Name, val.Version, status)

			if err != nil {
				log.Warnf("got error checking %s: %v\n", val.Name, err)
				continue
			}

			if status == true {
				fmt.Printf("package %s (%s) is vulnerable\n", val.Name, val.Version)
			}
		}

		os.Exit(0)
	}

	log.Info("webserver mode")
	cronsync(gitDirectory, time.Duration(syncInterval)*time.Second)
	webserver(":" + serverPort)
}

func setupLogging(level log.Level) {
	// Formatter
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	log.SetFormatter(customFormatter)
	customFormatter.FullTimestamp = true

	// Only log the warning severity or above.
	log.SetLevel(level)
}

func webserver(port string) {
	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/check", checkHandler)
	http.HandleFunc("/reflect", reflectHandler)
	log.Infof("listening on port %s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	message := fmt.Sprintf(`{ "sha1": "%s" }`, sha1)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(message))
}

func reflectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	lines, err := ioutil.ReadAll(r.Body)

	if err != nil {
		log.Infof("error reading body: %v", err)
		return
	}

	log.Infof("read body %s", lines)
	w.Write(lines)

	return
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug("checking composer.lock")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var complock composerLock

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&complock)

	if err != nil {
		log.Errorf("error decoding body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "malformed request" }`))
		return
	}

	for _, val := range complock.Packages {
		status, err := database.Vulnerable(val.Name, val.Version)

		if err != nil {
			continue
		}

		message := fmt.Sprintf("package %s (%s) is %t\n", val.Name, val.Version, status)
		log.Debug(message)

		if status {
			message := fmt.Sprintf("package %s (%s) is vulnerable\n", val.Name, val.Version)
			w.Write([]byte(message))
		}
	}
}

func cronsync(where string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	quit := make(chan struct{})

	log.Infof("initial sync in %s", where)
	err := fetchRepo(where)

	if err != nil {
		log.Errorf("unable to sync repo: %v", err)
	}

	log.Infof("lauching sync routine every %d secs", interval/time.Second)

	go func() {
		for {
			select {
			case <-ticker.C:
				// do stuff
				err = fetchRepo(where)
				if err != nil {
					log.Errorf("unable to sync repo: %v", err)
				}
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
}

func fetchRepo(where string) error {
	log.Debug("fetching")

	cloneOptions := &git.CloneOptions{}

	cloneOptions.FetchOptions = &git.FetchOptions{
		RemoteCallbacks: git.RemoteCallbacks{},
	}

	repo, err := git.OpenRepository(where)
	remote, err := repo.Remotes.Lookup("origin")
	err = remote.Fetch([]string{}, cloneOptions.FetchOptions, "")

	if err != nil {
		return err
	}

	err = repo.SetHead("refs/remotes/origin/master")

	if err != nil {
		return err
	}

	err = repo.CheckoutHead(&git.CheckoutOpts{Strategy: git.CheckoutForce})

	if err != nil {
		return err
	}

	idx, err := repo.Index()

	if err != nil {
		return err
	}

	err = idx.Write()

	if err != nil {
		return err
	}

	head, err := repo.Head()

	if err != nil {
		return err
	}

	tip, err := repo.LookupCommit(head.Target())

	if err != nil {
		return err
	}

	sha1, err = tip.ShortId()

	if err != nil {
		return err
	}

	log.Debugf("tip is %s at %s", head.Shorthand(), sha1)
	log.Debug("fetch done")

	return nil
}

func clone(uri string, where string) {
	log.Infof("CVEs source set to %s", uri)
	log.Infof("cloning CVEs in %s", where)

	cloneOptions := &git.CloneOptions{}

	cloneOptions.FetchOptions = &git.FetchOptions{
		RemoteCallbacks: git.RemoteCallbacks{},
	}
	_, err := git.Clone(uri, where, cloneOptions)

	if err != nil {
		log.Panic(err)
	}
}

func createDb(repos string) (*vulnDatabase, error) {
	fileList := []string{}
	db := NewDatabase()

	err := filepath.Walk(repos, func(path string, f os.FileInfo, err error) error {
		if strings.HasSuffix(path, ".yaml") {
			fileList = append(fileList, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	for _, file := range fileList {
		f, err := os.Open(file)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		log.Debugf("parsing file %s", file)

		var dec fofSecurityAdvisory

		decoder := yaml.NewDecoder(f)
		err = decoder.Decode(&dec)

		if err != nil {
			return nil, err
		}

		for _, v := range dec.Branches {
			key := strings.Replace(dec.Reference, "composer://", "", 1)

			log.Debugf("adding versions %v for %s", v.Versions, key)
			db.AddSpec(key, v.Versions)
		}
	}

	return db, nil
}
