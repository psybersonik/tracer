package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/shlex"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/psybersonik/tracer/pkg/job"
	"github.com/robfig/cron/v3"
	"gopkg.in/yaml.v3"
)

var (
	metricsPort          = flag.Int("metrics-port", 8080, "Port for Prometheus metrics HTTP endpoint (default: 8080)")
	disableGolangMetrics = flag.Bool("disable-golang-metrics", false, "Disable Go runtime metrics endpoint (default: false)")
	configPath           = flag.String("config", "", "Path to YAML config file defining settings and MTR targets (e.g., config.yaml)")
	dbPath               = flag.String("db-path", "", "Path to CSV ASN database (default: asn.csv in executable directory)")
	logFile              = flag.String("log-file", "", "Path to log file (default: stdout; overridden by config.yaml log_file if set)")
	dbUpdateInterval     = flag.Duration("db-update-interval", 0, "Interval to check for CSV ASN database updates (e.g., 24h; 0 disables updates)")
	dbUpdateSource       = flag.String("db-update-source", "", "Source for CSV ASN database updates (local file path or URL)")
)

const version = "0.7.0"

// Metrics for database updates
var (
	dbUpdateStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mtr_asn_db_update_status",
		Help: "Status of CSV ASN database update (1 for success, 0 for failure)",
	}, []string{"status", "source"})
)

// ASNEntry represents a row in the CSV ASN database.
type ASNEntry struct {
	Network    *net.IPNet
	IsSingleIP bool
	ASN        string
	Org        string
}

// ASNDB holds the CSV ASN database.
type ASNDB struct {
	Entries []ASNEntry
}

// DBHolder holds the current ASN database atomically.
type DBHolder struct {
	db atomic.Pointer[ASNDB]
}

func (h *DBHolder) Get() *ASNDB {
	return h.db.Load()
}

func (h *DBHolder) Set(db *ASNDB) {
	h.db.Store(db)
}

// Config defines the YAML structure for settings and targets.
type Config struct {
	MetricsPort          int      `yaml:"metrics_port"`
	DisableGolangMetrics bool     `yaml:"disable_golang_metrics"`
	DBPath               string   `yaml:"db_path"`
	LogFile              string   `yaml:"log_file"`
	DBUpdateInterval     string   `yaml:"db_update_interval"`
	DBUpdateSource       string   `yaml:"db_update_source"`
	Targets              []Target `yaml:"targets"`
}

// Target defines a single MTR target and its schedule.
type Target struct {
	Host     string `yaml:"host"`
	Schedule string `yaml:"schedule"`
}

// JobManager manages multiple MTR jobs and acts as a Prometheus collector.
type JobManager struct {
	jobs []*job.MTRJob
	mu   sync.Mutex
}

// NewJobManager creates a new JobManager.
func NewJobManager() *JobManager {
	return &JobManager{}
}

// AddJob adds an MTR job to the manager.
func (jm *JobManager) AddJob(mtrJob *job.MTRJob) {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	jm.jobs = append(jm.jobs, mtrJob)
}

// Describe implements prometheus.Collector.
func (jm *JobManager) Describe(ch chan<- *prometheus.Desc) {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	for _, mtrJob := range jm.jobs {
		mtrJob.Describe(ch)
	}
}

// Collect implements prometheus.Collector.
func (jm *JobManager) Collect(ch chan<- prometheus.Metric) {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	for _, mtrJob := range jm.jobs {
		mtrJob.Collect(ch)
	}
}

func init() {
	flag.Usage = func() {
		usage := `tracer v%[1]s

Usage: %[2]s [flags] [-- MTR arguments]

tracer runs MTR (My Traceroute) and exposes network metrics for Prometheus.
MTR metrics are available at /metrics; Go runtime metrics at /metrics/golang (unless disabled).
Requests to other paths redirect to /metrics.
Use a YAML config file (-config) for settings and multiple targets or specify a single target via MTR arguments.
If no arguments are provided, uses default_config.yaml in the executable directory.
Command-line flags override config.yaml settings.
Example: %[2]s -config=config.yaml
Example: %[2]s -metrics-port=9090 -schedule="@every 10s" -log-file=/tmp/tracer.log -- 1.1.1.1
Example: %[2]s

Flags:
`
		if _, err := fmt.Fprintf(os.Stderr, usage, version, os.Args[0]); err != nil {
			log.Printf("Failed to write usage message: %v", err)
			os.Exit(1)
		}
		flag.PrintDefaults()
		notes := `
Notes:
- If -config is set, MTR arguments are ignored.
- If no arguments are provided, default_config.yaml must exist in the executable directory.
- Logs are written to stdout unless -log-file or config.yaml log_file is set.
- Schedule format supports cron (e.g., "0 * * * * *" for every minute) or @every <duration> (e.g., @every 10s).
- YAML config supports # for comments and ${VARIABLE} or ${VARIABLE:default} for environment variable substitution.
- CSV ASN database updates require a valid source (local file or URL).
- If asn.csv is missing at startup, tracer continues with ASN values as "unavailable" until the database is available.
- If no ASN entry is found for an IP, "notfound" is used for ASN and organization values.
- CSV ASN database format (header: network,autonomous_system_number,autonomous_system_organization):
  - network: Single IPv4/IPv6 address (e.g., 1.1.1.1, 2001:db8::1) or CIDR network (e.g., 192.168.1.0/24). Single IPs take precedence over CIDR matches.
  - Example:
    1.1.1.1,13335,Cloudflare
    2001:db8::1,15169,Google
    192.168.1.0/24,13335,Cloudflare
- YAML config example:
  # Main settings
  metrics_port: 8080  # Prometheus port
  disable_golang_metrics: false  # Disable Go runtime metrics
  db_path: /tmp/asn.csv
  log_file: /tmp/tracer.log  # Log output file
  db_update_interval: 24h  # Update check interval
  db_update_source: https://example.com/asn.csv
  targets:
    - host: 1.1.1.1  # Cloudflare DNS
      schedule: "@every 300s"
`
		if _, err := fmt.Fprintf(os.Stderr, notes); err != nil {
			log.Printf("Failed to write usage notes: %v", err)
			os.Exit(1)
		}
	}
}

func main() {
	flag.Parse()

	// Log initialization with version
	log.Printf("Initializing tracer v%[1]s", version)

	// Get executable directory
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("failed to get executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)

	// Set default config and db paths
	configPathValue := *configPath
	dbPathValue := *dbPath
	metricsPortValue := *metricsPort
	disableGolangMetricsValue := *disableGolangMetrics
	logFileValue := *logFile
	dbUpdateIntervalValue := *dbUpdateInterval
	dbUpdateSourceValue := *dbUpdateSource

	// Handle no arguments: use default_config.yaml
	if len(flag.Args()) == 0 && configPathValue == "" {
		configPathValue = filepath.Join(exeDir, "default_config.yaml")
		if _, err := os.Stat(configPathValue); err != nil {
			log.Fatalf("failed to check default config file %s: %v", configPathValue, err)
		}
	}

	// Load config if provided
	var config *Config
	if configPathValue != "" {
		config, err = loadConfig(configPathValue)
		if err != nil {
			log.Fatalf("failed to load config: %v", err)
		}
	}

	// Apply config.yaml settings if not overridden by flags
	if config != nil {
		if dbPathValue == "" {
			dbPathValue = config.DBPath
		}
		if logFileValue == "" {
			logFileValue = config.LogFile
		}
		if metricsPortValue == 8080 {
			metricsPortValue = config.MetricsPort
		}
		if !disableGolangMetricsValue {
			disableGolangMetricsValue = config.DisableGolangMetrics
		}
		if dbUpdateIntervalValue == 0 && config.DBUpdateInterval != "" {
			if duration, err := time.ParseDuration(config.DBUpdateInterval); err != nil {
				log.Printf("invalid db_update_interval in config: %v", err)
			} else {
				dbUpdateIntervalValue = duration
			}
		}
		if dbUpdateSourceValue == "" {
			dbUpdateSourceValue = config.DBUpdateSource
		}
	}

	// Set default dbPath if still empty
	if dbPathValue == "" {
		dbPathValue = filepath.Join(exeDir, "asn.csv")
	}

	// Initialize logging
	if logFileValue != "" {
		f, err := os.OpenFile(logFileValue, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("failed to open log file %s: %v", logFileValue, err)
		}
		defer f.Close()
		log.SetOutput(f)
	} else {
		log.SetOutput(os.Stdout)
	}

	// Initialize CSV ASN database
	dbHolder := &DBHolder{}
	var dbInitiallyUnavailable bool
	db, err := loadCSVDatabase(dbPathValue)
	if err != nil {
		log.Printf("Failed to open CSV ASN database at %s: %v; continuing with ASN values as 'unavailable'", dbPathValue, err)
		dbHolder.Set(nil)
		dbInitiallyUnavailable = true
		// Attempt to download database if update source is configured
		if dbUpdateSourceValue != "" {
			log.Printf("Attempting to download CSV ASN database from %s", dbUpdateSourceValue)
			if newDB, err := loadNewDatabase(dbUpdateSourceValue, dbPathValue); err == nil {
				dbHolder.Set(newDB)
				log.Printf("Successfully loaded initial CSV ASN database from %s", dbUpdateSourceValue)
				dbInitiallyUnavailable = false
			} else {
				log.Printf("Failed to download initial CSV ASN database: %v", err)
			}
		}
	} else {
		dbHolder.Set(db)
	}

	// Create separate registries for MTR and Golang metrics
	mtrRegistry := prometheus.NewRegistry()
	var golangRegistry *prometheus.Registry
	if !disableGolangMetricsValue {
		golangRegistry = prometheus.NewRegistry()
		golangRegistry.MustRegister(
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		)
	}

	// Register MTR metrics
	jobManager := NewJobManager()
	mtrRegistry.MustRegister(jobManager)
	mtrRegistry.MustRegister(dbUpdateStatus)

	// Start database update goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if dbUpdateIntervalValue > 0 && dbUpdateSourceValue != "" {
		go updateDatabase(ctx, dbHolder, dbPathValue, dbUpdateSourceValue, dbUpdateIntervalValue, &dbInitiallyUnavailable)
	}

	// Create scheduler
	scheduler := cron.New(cron.WithSeconds())

	// Load targets from config
	if configPathValue != "" {
		for _, target := range config.Targets {
			mtrArgs, err := shlex.Split(target.Host)
			if err != nil {
				log.Printf("failed to parse args for %s: %v", target.Host, err)
				continue
			}
			mtrJob := job.NewMTRJob(mtrArgs, func(host string) (string, string) {
				return lookupASN(dbHolder.Get(), host)
			})
			jobManager.AddJob(mtrJob)
			log.Printf("Running initial MTR job for %s", target.Host)
			if err := mtrJob.Run(ctx); err != nil {
				log.Printf("Initial mtr job for %s failed: %v", target.Host, err)
			}
			id, err := scheduler.AddFunc(target.Schedule, func() {
				log.Printf("Running scheduled MTR job for %s", target.Host)
				if err := mtrJob.Run(ctx); err != nil {
					log.Printf("mtr job for %s failed: %v", target.Host, err)
				}
			})
			if err != nil {
				log.Printf("failed to schedule mtr job for %s: %v", target.Host, err)
				continue
			}
			log.Printf("Scheduled MTR job for %s with ID %d", target.Host, id)
		}
	} else if len(flag.Args()) > 0 {
		// Fallback to single target from command line
		mtrArgs, err := shlex.Split(flag.Args()[0])
		if err != nil {
			log.Fatalf("failed to parse mtr arguments: %v", err)
		}
		mtrJob := job.NewMTRJob(mtrArgs, func(host string) (string, string) {
			return lookupASN(dbHolder.Get(), host)
		})
		jobManager.AddJob(mtrJob)
		log.Println("Running initial MTR job")
		if err := mtrJob.Run(ctx); err != nil {
			log.Printf("Initial mtr job failed: %v", err)
		}
		schedule := *flag.String("schedule", "@every 1m", "Cron schedule for single target (e.g., @every 10s or 0 * * * * *)")
		id, err := scheduler.AddFunc(schedule, func() {
			log.Println("Running scheduled MTR job")
			if err := mtrJob.Run(ctx); err != nil {
				log.Printf("mtr job for %s failed: %v", mtrJob.Target(), err)
			}
		})
		if err != nil {
			log.Fatalf("failed to schedule mtr job: %v", err)
		}
		log.Printf("Scheduled MTR job for %s with ID %d", mtrJob.Target(), id)
	} else {
		log.Fatal("missing mtr arguments or config file")
	}

	listenAddr := fmt.Sprintf(":%d", metricsPortValue)
	// Serve metrics
	http.Handle("/metrics", promhttp.HandlerFor(mtrRegistry, promhttp.HandlerOpts{}))
	if !disableGolangMetricsValue {
		http.Handle("/metrics/golang", promhttp.HandlerFor(golangRegistry, promhttp.HandlerOpts{}))
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" && (!disableGolangMetricsValue && r.URL.Path != "/metrics/golang") {
			http.Redirect(w, r, "/metrics", http.StatusFound)
		}
	})
	scheduler.Start()
	log.Printf("tracer v%[1]s starting. Metrics served on %s", version, listenAddr)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}

// loadConfig reads and parses the YAML config file, stripping # comments and substituting environment variables.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	// Substitute environment variables in the format ${VARIABLE} or ${VARIABLE:default}
	var re = regexp.MustCompile(`\${([^:]+?)(?::(.*?))?}`)
	expanded := re.ReplaceAllStringFunc(string(data), func(match string) string {
		parts := re.FindStringSubmatch(match)
		varName := parts[1]
		defaultValue := parts[2]
		if value, ok := os.LookupEnv(varName); ok {
			return value
		}
		if defaultValue != "" {
			return defaultValue
		}
		log.Printf("Warning: environment variable %s not set and no default provided in %s", varName, path)
		return ""
	})

	// Strip # comments
	var cleaned bytes.Buffer
	lines := strings.Split(expanded, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		cleaned.WriteString(line + "\n")
	}

	var config Config
	if err := yaml.Unmarshal(cleaned.Bytes(), &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}
	if len(config.Targets) == 0 {
		return nil, fmt.Errorf("no targets defined in config file %s", path)
	}
	return &config, nil
}

// lookupASN queries the CSV ASN database for ASN and organization
func lookupASN(db *ASNDB, host string) (string, string) {
	if db == nil {
		log.Printf("CSV ASN database is unavailable for host %s; returning 'unavailable'", host)
		return "unavailable", "unavailable"
	}
	ipStr := host
	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			log.Printf("Failed to resolve hostname %s: %v; returning 'notfound'", host, err)
			return "notfound", "notfound"
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				ipStr = ip.String()
				break
			}
		}
		if ipStr == host {
			ipStr = ips[0].String()
		}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Printf("Invalid IP after resolution: %s; returning 'notfound'", ipStr)
		return "notfound", "notfound"
	}

	// Check for exact IP match first
	for _, entry := range db.Entries {
		if entry.IsSingleIP && entry.Network.IP.String() == ipStr {
			return "AS" + entry.ASN, entry.Org
		}
	}

	// Fallback to longest prefix match for CIDR networks
	var bestMatch *ASNEntry
	var bestPrefixLen int
	for _, entry := range db.Entries {
		if !entry.IsSingleIP && entry.Network.Contains(ip) {
			_, bits := entry.Network.Mask.Size()
			if bestMatch == nil || bits > bestPrefixLen {
				bestMatch = &entry
				bestPrefixLen = bits
			}
		}
	}

	if bestMatch == nil {
		log.Printf("No ASN match found for %s; returning 'notfound'", ipStr)
		return "notfound", "notfound"
	}

	return "AS" + bestMatch.ASN, bestMatch.Org
}

// loadCSVDatabase loads the CSV ASN database from a file.
func loadCSVDatabase(path string) (*ASNDB, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open CSV file %s: %w", path, err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV file %s: %w", path, err)
	}

	if len(records) < 1 {
		return nil, fmt.Errorf("CSV file %s is empty", path)
	}

	header := records[0]
	if len(header) != 3 || header[0] != "network" || header[1] != "autonomous_system_number" || header[2] != "autonomous_system_organization" {
		return nil, fmt.Errorf("invalid CSV header in %s; expected 'network,autonomous_system_number,autonomous_system_organization'", path)
	}

	var db ASNDB
	for i, record := range records[1:] {
		if len(record) != 3 {
			log.Printf("Skipping invalid CSV record at line %d: %v", i+2, record)
			continue
		}
		var network *net.IPNet
		isSingleIP := false
		if strings.Contains(record[0], "/") {
			_, network, err = net.ParseCIDR(record[0])
			if err != nil {
				log.Printf("Skipping invalid network %s at line %d: %v", record[0], i+2, err)
				continue
			}
		} else {
			ip := net.ParseIP(record[0])
			if ip == nil {
				log.Printf("Skipping invalid IP %s at line %d: invalid IP address", record[0], i+2)
				continue
			}
			isSingleIP = true
			var ipNet *net.IPNet
			if ip.To4() != nil {
				_, ipNet, err = net.ParseCIDR(record[0] + "/32")
			} else {
				_, ipNet, err = net.ParseCIDR(record[0] + "/128")
			}
			if err != nil {
				log.Printf("Skipping invalid IP %s at line %d: %v", record[0], i+2, err)
				continue
			}
			network = ipNet
		}
		db.Entries = append(db.Entries, ASNEntry{
			Network:    network,
			IsSingleIP: isSingleIP,
			ASN:        record[1],
			Org:        record[2],
		})
	}

	if len(db.Entries) == 0 {
		return nil, fmt.Errorf("no valid entries in CSV file %s", path)
	}

	return &db, nil
}

// updateDatabase periodically checks for and applies CSV database updates.
func updateDatabase(ctx context.Context, dbHolder *DBHolder, dbPath, source string, interval time.Duration, dbInitiallyUnavailable *bool) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Stopping CSV ASN database updates")
			return
		case <-ticker.C:
			log.Printf("Starting CSV ASN database update check at %s", time.Now().Format(time.RFC3339))
			newDB, err := loadNewDatabase(source, dbPath)
			if err != nil {
				log.Printf("Failed to update CSV ASN database from %s: %v", source, err)
				dbUpdateStatus.WithLabelValues("failure", source).Set(0)
				continue
			}
			dbHolder.Set(newDB)
			if *dbInitiallyUnavailable {
				log.Printf("CSV ASN database successfully downloaded from %s at %s", source, time.Now().Format(time.RFC3339))
				*dbInitiallyUnavailable = false
			} else {
				log.Printf("Successfully updated CSV ASN database from %s at %s", source, time.Now().Format(time.RFC3339))
			}
			dbUpdateStatus.WithLabelValues("success", source).Set(1)
		}
	}
}

// loadNewDatabase loads a new CSV ASN database from a local file or URL.
func loadNewDatabase(source, dbPath string) (*ASNDB, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		resp, err := http.Get(source)
		if err != nil {
			return nil, fmt.Errorf("failed to download CSV from %s: %w", source, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code %d downloading CSV from %s", resp.StatusCode, source)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read CSV from %s: %w", source, err)
		}
		// Save to temporary file
		tmpFile, err := os.CreateTemp("", "asn-*.csv")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp file: %w", err)
		}
		defer os.Remove(tmpFile.Name())
		if _, err := tmpFile.Write(data); err != nil {
			if closeErr := tmpFile.Close(); closeErr != nil {
				log.Printf("Failed to close temp file after write error: %v", closeErr)
			}
			return nil, fmt.Errorf("failed to write temp file: %w", err)
		}
		if err := tmpFile.Close(); err != nil {
			log.Printf("Failed to close temp file: %v", err)
			return nil, fmt.Errorf("failed to close temp file: %w", err)
		}
		// Load from temp file
		db, err := loadCSVDatabase(tmpFile.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to parse CSV database: %w", err)
		}
		// Move temp file to dbPath
		if err := os.Rename(tmpFile.Name(), dbPath); err != nil {
			return nil, fmt.Errorf("failed to move new CSV database to %s: %w", dbPath, err)
		}
		return db, nil
	} else {
		// Load from local file
		db, err := loadCSVDatabase(source)
		if err != nil {
			return nil, fmt.Errorf("failed to load CSV database from %s: %w", source, err)
		}
		return db, nil
	}
}
