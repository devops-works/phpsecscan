package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	db "github.com/devops-works/phpsecscan/database"
	stats "github.com/devops-works/phpsecscan/statsd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	flag "github.com/namsral/flag"
	log "github.com/sirupsen/logrus"
	git "gopkg.in/src-d/go-git.v4"

	yaml "gopkg.in/yaml.v2"
)

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

const (
	JSON = "json"
	TEXT = "text"
)

var (
	database  *db.VulnDatabase
	sha1      string
	version   string
	buildDate string

	checksProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "phpsecscan_processed_checks",
		Help: "The total number of processed composer.lock check requests",
	})

	checksVulnerable = promauto.NewCounter(prometheus.CounterOpts{
		Name: "phpsecscan_processed_vulnerable",
		Help: "The total number of vulnerable composer.lock found",
	})

	checksNotVulnerable = promauto.NewCounter(prometheus.CounterOpts{
		Name: "phpsecscan_processed_notvulnerable",
		Help: "The total number of not vulnerable composer.lock found",
	})

	checksVulnerabilitiesfound = promauto.NewCounter(prometheus.CounterOpts{
		Name: "phpsecscan_processed_vulnerabilities_found",
		Help: "The total number of vulnerabilities found in composer.lock",
	})

	checkDuration = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "phpsecscan_check_duration_ms",
		Help: "Time taken to check compose.json in ms",
	})

	clonesIssued = promauto.NewCounter(prometheus.CounterOpts{
		Name: "phpsecscan_clones_issued",
		Help: "The total number of CVE repository refreshes",
	})

	clonesFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "phpsecscan_clones_failed",
		Help: "The total number of CVE repository clone failed",
	})

	clonesDuration = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "phpsecscan_clones_duration_ms",
		Help: "Time taken to clone the CVE repository in ms",
	})

	cveCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "phpsecscan_cve",
		Help: "The current number of CVE in database",
	})
)

func main() {
	var err error
	var help, isDebug bool
	var gitDirectory, serverPort, uri, statsdServer, logFormat string
	var syncInterval int

	flag.StringVar(&gitDirectory, "gitdir", "", "Path to store CVE git checkout")
	flag.BoolVar(&isDebug, "debug", false, "Debug mode")
	flag.StringVar(&serverPort, "port", "8080", "Server port")
	flag.StringVar(&logFormat, "logformat", "text", "Log format (text or json)")
	flag.StringVar(&uri, "repo", "https://github.com/FriendsOfPHP/security-advisories.git", "CVE repository")
	flag.IntVar(&syncInterval, "interval", 600, "Interval between CVE repository sync")
	flag.StringVar(&statsdServer, "statsd", "", "URL for statsd server (e.g. 127.0.0.1:8025)")
	flag.BoolVar(&help, "help", false, "Help usage")
	flag.BoolVar(&help, "h", false, "Help usage")

	flag.Parse()

	if help {
		flag.Usage()
		os.Exit(0)
	}

	// Setup logging
	if isDebug {
		setupLogging(logFormat, log.DebugLevel)
	} else {
		setupLogging(logFormat, log.InfoLevel)
	}

	log.Infof("version %s (built %s) starting", version, buildDate)

	// Setup metrics
	if statsdServer != "" {
		stats.Open(statsdServer)
	}

	// If gitDirectory is not set, get a temporary directory
	// because we still need to checkkout somewhere
	// This directory will be removed afterwards
	if gitDirectory == "" {
		gitDirectory, err = os.MkdirTemp("", "phpsecscan")
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

	// Single run mode
	if flag.NArg() == 1 {
		log.Info("single run mode")

		err = fetchRepo(gitDirectory)

		if err != nil {
			log.Errorf("unable to sync repo: %v", err)
		}

		if fileIsVulnerable(flag.Arg(0)) {
			os.Exit(1)
		}

		os.Exit(0)
	}

	log.Info("webserver mode")

	cronsync(gitDirectory, time.Duration(syncInterval)*time.Second)
	webserver(":" + serverPort)
}

func setupLogging(mode string, level log.Level) {
	// Formatter
	// var customFormatter log.Formatter

	// customFormatter = new(log.TextFormatter)

	if mode == JSON {
		customFormatter := new(log.JSONFormatter)
		customFormatter.TimestampFormat = "2006-01-02 15:04:05"
		log.SetFormatter(customFormatter)
	} else {
		customFormatter := new(log.TextFormatter)
		customFormatter.TimestampFormat = "2006-01-02 15:04:05"
		customFormatter.FullTimestamp = true
		log.SetFormatter(customFormatter)
	}

	// Only log the warning severity or above.
	log.SetLevel(level)
}

func webserver(port string) {
	http.HandleFunc("/status", statusHandler)
	http.HandleFunc("/check", checkHandler)
	http.HandleFunc("/reflect", reflectHandler)
	http.Handle("/metrics", promhttp.Handler())
	log.Infof("listening on port %s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	message := fmt.Sprintf(`{ "dbsha1": "%s", "version": "%s", "build_date": "%s"}`, sha1, version, buildDate)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(message))
}

func reflectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	io.Copy(w, r.Body)
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	log.Debugf("checking composer.lock for %s", r.RemoteAddr)

	t := time.Now()
	defer func() {
		stats.Time("checks.timetaken", time.Since(t))
		stats.Count("checks.total", 1)
		checkDuration.Set(float64(time.Since(t).Milliseconds()))
		checksProcessed.Inc()
	}()

	if r.Method != http.MethodPost {
		stats.Count("checks.failed.method", 1)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var complock composerLock

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&complock)

	if err != nil {
		log.Errorf("error decoding body from %s: %v", r.RemoteAddr, err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "malformed request" }`))
		stats.Count("checks.failed.decode", 1)
		return
	}

	response := ""
	// response = s[:sz-1]

	for _, val := range complock.Packages {
		advisories, err := database.Vulnerable(val.Name, val.Version)

		if err != nil {
			continue
		}

		if len(advisories) > 0 {
			// We have vulnerabilities for this package
			// Initialize package entry in response
			response += `{ "package": "` + val.Name + `", "vulnerable": true, "cve": [`

			for _, adv := range advisories {
				//	fmt.Printf("\t%s (%s)\n", adv.CVE, adv.Link)
				response += `{ "id": "` + adv.CVE + `", "title": "` + adv.Title + `", "link": "` + adv.Link + `"},`
			}
			// For the last iteration, remove the trailing ','
			response = response[:len(response)-1]

			// For the last iteration, close json array and package object
			response += `] },`
			checksVulnerabilitiesfound.Add(float64(len(advisories)))
		}

	}

	if len(response) > 0 {
		// We have vulnerabilities
		// So remove the trailing ',' for the last iteration and enclose vulnerabilities list
		response = response[:len(response)-1]
		response = `{  "vulnerable": true, "version": "` + sha1 + `", "vulnerabilities": [ ` + response + ` ] }`
		stats.Count("checks.success.vulnerable", 1)
		checksVulnerable.Inc()
		log.Info("lock file is vulnerable")

	} else {
		response = `{ "vulnerable": false, "version": "` + sha1 + `" }`
		stats.Count("checks.success.notvulnerable", 1)
		checksNotVulnerable.Inc()
		log.Info("lock file is not vulnerable")
	}

	w.Write([]byte(response))
	log.Debugf("check done in %d ms", time.Since(t)/time.Millisecond)
}

func fileIsVulnerable(file string) bool {
	vulnerable := false
	jsonData, err := os.ReadFile(file)

	if err != nil {
		log.Fatalf("unable to open %s: %v", file, err)
		os.Exit(1)
	}

	var v composerLock
	json.Unmarshal(jsonData, &v)

	for _, val := range v.Packages {
		advisories, err := database.Vulnerable(val.Name, val.Version)

		if err != nil {
			log.Warnf("got error checking %s: %v\n", val.Name, err)
			continue
		}

		if len(advisories) > 0 {
			vulnerable = true
			fmt.Printf("package %s (%s) is vulnerable\n", val.Name, val.Version)
			for _, adv := range advisories {
				fmt.Printf("\t%s (%s)\n", adv.CVE, adv.Link)
			}
		}
	}

	return vulnerable
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
	log.Debugf("fetching database at %s", where)

	t := time.Now()
	defer func() {
		stats.Time("fetch.timetaken", time.Since(t))
		clonesDuration.Set(float64(time.Since(t) / time.Millisecond))
	}()

	repo, err := git.PlainOpen(where)
	repo.Fetch(&git.FetchOptions{})

	if err != nil {
		return err
	}

	clonesIssued.Inc()

	head, err := repo.Head()

	if err != nil {
		return err
	}

	sha1 = head.Hash().String()

	log.Debugf("tip is at %s with sha1 %s", head.Name(), sha1)
	log.Debugf("fetch done in %d ms", time.Since(t)/time.Millisecond)

	return nil
}

func clone(uri string, where string) {
	log.Infof("CVEs source set to %s", uri)
	log.Infof("cloning CVEs in %s", where)

	t := time.Now()
	defer func() {
		stats.Time("clone.timetaken", time.Since(t))
		clonesDuration.Set(float64(time.Since(t) / time.Millisecond))
	}()

	// Clones the repository into the given dir, just as a normal git clone does
	_, err := git.PlainClone(where, false, &git.CloneOptions{
		URL: uri,
	})

	clonesIssued.Inc()

	if err != nil {
		log.Error("unable to clone CVE repositories: %v", err)
		clonesFailed.Inc()
		return
	}

	log.Debugf("clone done in %d ms", time.Since(t)/time.Millisecond)
}

func createDb(repos string) (*db.VulnDatabase, error) {
	fileList := []string{}
	vdb := db.NewDatabase()

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
			log.Fatalf("unable to open %s: %v", file, err)
		}

		log.Debugf("parsing file %s", file)

		var dec db.FoFSecurityAdvisory

		decoder := yaml.NewDecoder(f)
		err = decoder.Decode(&dec)

		if err != nil {
			return nil, err
		}

		key := strings.Replace(dec.Reference, "composer://", "", 1)
		vdb.AddVulnerability(key, dec)
		f.Close()
	}

	log.Infof("database contains %d vulnerabilities", len(fileList))
	stats.Gauge("database.vulnerabilities", len(fileList))
	cveCount.Set(float64(len(fileList)))
	return vdb, nil
}
