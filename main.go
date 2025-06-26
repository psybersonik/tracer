package main

import (
	"bytes"
	"context"
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
	"github.com/oschwald/geoip2-golang"
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
	dbPath               = flag.String("db-path", "", "Path to MaxMind GeoLite2-ASN.mmdb database for ASN lookups (default: GeoLite2-ASN.mmdb in executable directory)")
	logFile              = flag.String("log-file", "", "Path to log file (default: stdout; overridden by config.yaml log_file if set)")
	dbUpdateInterval     = flag.Duration("db-update-interval", 0, "Interval to check for MaxMind GeoLite2-ASN.mmdb updates (e.g., 24h; 0 disables updates)")
	dbUpdateSource       = flag.String("db-update-source", "", "Source for MaxMind GeoLite2-ASN.mmdb updates (local file path or MaxMind API URL; requires license key for API)")
	maxmindLicenseKey    = flag.String("maxmind-license-key", "", "MaxMind license key for downloading GeoLite2-ASN.mmdb updates")
)

// Metrics for database updates
var (
	dbUpdateStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mtr_maxmind_db_update_status",
		Help: "Status of MaxMind GeoLite2-ASN.mmdb update (1 for success, 0 for failure)",
	}, []string{"status", "source"})
)

func init() {
	flag.Usage = func() {
		usage := `Usage: %s [flags] [-- MTR arguments]

tracer runs MTR (My Traceroute) and exposes network metrics for Prometheus.
MTR metrics are available at /metrics; Go runtime metrics at /metrics/golang (unless disabled).
Requests to other paths redirect to /metrics.
Use a YAML config file (-config) for settings and multiple targets or specify a single target via MTR arguments.
If no arguments are provided, uses default_config.yaml in the executable directory.
Command-line flags override config.yaml settings.
Example: %s -config=config.yaml
Example: %s -metrics-port=9090 -schedule="@every 10s" -log-file=/tmp/tracer.log -- 1.1.1.1
Example: %s

Flags:

%s

Notes:
- If -config is set, MTR arguments are ignored.
- If no arguments are provided, default_config.yaml must exist in the executable directory.
- Logs are written to stdout unless -log-file or config.yaml log_file is set.
- Schedule format supports cron (e.g., "0 * * * * *" for every minute) or @every <duration> (e.g., @every 10s).
- YAML config supports # for comments and ${VARIABLE} or ${VARIABLE:default} for environment variable substitution.
- MaxMind DB updates require a valid license key for API downloads.
- If GeoLite2-ASN.mmdb is missing at startup, tracer continues with ASN values as "unavailable" until the database is available.
- YAML config example:
  # Main settings
  metrics_port: 8080  # Prometheus port
  disable_golang_metrics: false  # Disable Go runtime metrics
  db_path: ${DB_PATH:/path/to/GeoLite2-ASN.mmdb}
  log_file: ${LOG_FILE:/tmp/tracer.log}  # Log output file
  db_update_interval: ${UPDATE_INTERVAL:24h}  # Update check interval
  db_update_source: ${UPDATE_SOURCE:https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_KEY&suffix=tar.gz}
  maxmind_license_key: ${MAXMIND_KEY}
  targets:
    - host: ${TARGET_HOST:1.1.1.1}  # Cloudflare DNS
      schedule: "@every 300s"
`
		if _, err := fmt.Fprintf(os.Stderr, usage, os.Args[0], os.Args[0], os.Args[0], os.Args[0], flag.CommandLine.Output()); err != nil {
			log.Printf("Failed to write usage message: %v", err)
		}
	}
}

// Config defines the YAML structure for settings and targets.
type Config struct {
	MetricsPort          int      `yaml:"metrics_port"`
	DisableGolangMetrics bool     `yaml:"disable_golang_metrics"`
	DBPath               string   `yaml:"db_path"`
	LogFile              string   `yaml:"log_file"`
	DBUpdateInterval     string   `yaml:"db_update_interval"`
	DBUpdateSource       string   `yaml:"db_update_source"`
	MaxmindLicenseKey    string   `yaml:"maxmind_license_key"`
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

// DBHolder holds the current MaxMind database reader atomically.
type DBHolder struct {
	reader atomic.Pointer[geoip2.Reader]
}

func (h *DBHolder) Get() *geoip2.Reader {
	return h.reader.Load()
}

func (h *DBHolder) Set(reader *geoip2.Reader) {
	h.reader.Store(reader)
}

func main() {
	flag.Parse()

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
	maxmindLicenseKeyValue := *maxmindLicenseKey

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
		if dbPathValue == "" && config.DBPath != "" {
			dbPathValue = config.DBPath
		}
		if logFileValue == "" && config.LogFile != "" {
			logFileValue = config.LogFile
		}
		if metricsPortValue == 8080 && config.MetricsPort != 0 {
			metricsPortValue = config.MetricsPort
		}
		if !disableGolangMetricsValue && config.DisableGolangMetrics {
			disableGolangMetricsValue = config.DisableGolangMetrics
		}
		if dbUpdateIntervalValue == 0 && config.DBUpdateInterval != "" {
			if duration, err := time.ParseDuration(config.DBUpdateInterval); err == nil {
				dbUpdateIntervalValue = duration
			} else {
				log.Printf("invalid db_update_interval in config: %v", err)
			}
		}
		if dbUpdateSourceValue == "" && config.DBUpdateSource != "" {
			dbUpdateSourceValue = config.DBUpdateSource
		}
		if maxmindLicenseKeyValue == "" && config.MaxmindLicenseKey != "" {
			maxmindLicenseKeyValue = config.MaxmindLicenseKey
		}
	}

	// Set default dbPath if still empty
	if dbPathValue == "" {
		dbPathValue = filepath.Join(exeDir, "GeoLite2-ASN.mmdb")
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

	// Initialize MaxMind database
	dbHolder := &DBHolder{}
	var dbInitiallyUnavailable bool
	db, err := geoip2.Open(dbPathValue)
	if err != nil {
		log.Printf("Failed to open GeoLite2-ASN.mmdb at %s: %v; continuing with ASN values as 'unavailable'", dbPathValue, err)
		dbHolder.Set(nil)
		dbInitiallyUnavailable = true
		// Attempt to download database if update source is configured
		if dbUpdateSourceValue != "" && maxmindLicenseKeyValue != "" {
			log.Printf("Attempting to download GeoLite2-ASN.mmdb from %s", dbUpdateSourceValue)
			if newDB, err := loadNewDatabase(dbUpdateSourceValue, maxmindLicenseKeyValue, dbPathValue); err == nil {
				dbHolder.Set(newDB)
				log.Printf("Successfully loaded initial GeoLite2-ASN.mmdb from %s", dbUpdateSourceValue)
				dbInitiallyUnavailable = false
			} else {
				log.Printf("Failed to download initial GeoLite2-ASN.mmdb: %v", err)
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
		go updateDatabase(ctx, dbHolder, dbPathValue, dbUpdateSourceValue, maxmindLicenseKeyValue, dbUpdateIntervalValue, &dbInitiallyUnavailable)
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
	log.Printf("tracer v0.6.0 starting, listening on %s", listenAddr)
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

// lookupASN queries the MaxMind database for ASN and organization
func lookupASN(db *geoip2.Reader, host string) (string, string) {
	if db == nil {
		log.Printf("MaxMind database is not available for host %s; using 'unavailable' as ASN Value", host)
		return "unavailable", "unavailable"
	}
	ipStr := host
	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			log.Printf("Failed to resolve hostname %s: %v; using 'unavailable' as ASN Value", host, err)
			return "unavailable", "unavailable"
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
		log.Printf("Invalid IP after resolution: %s; using 'unavailable' as ASN Value", ipStr)
		return "unavailable", "unavailable"
	}

	record, err := db.ASN(ip)
	if err != nil {
		log.Printf("ASN lookup failed for %s: %v; using 'unavailable' as ASN Value", ipStr, err)
		return "unavailable", "unavailable"
	}

	asn := fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
	org := record.AutonomousSystemOrganization
	if org == "" {
		org = "unavailable"
	}
	return asn, org
}

// updateDatabase periodically checks for and applies database updates.
func updateDatabase(ctx context.Context, dbHolder *DBHolder, dbPath, source, licenseKey string, interval time.Duration, dbInitiallyUnavailable *bool) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Stopping MaxMind database updates")
			return
		case <-ticker.C:
			log.Printf("Starting MaxMind database update check at %s", time.Now().Format(time.RFC3339))
			newDB, err := loadNewDatabase(source, licenseKey, dbPath)
			if err != nil {
				log.Printf("Failed to update MaxMind database from %s: %v", source, err)
				dbUpdateStatus.WithLabelValues("failure", source).Set(0)
				continue
			}
			oldDB := dbHolder.Get()
			dbHolder.Set(newDB)
			if *dbInitiallyUnavailable {
				log.Printf("GeoLite2-ASN.mmdb successfully downloaded from %s at %s", source, time.Now().Format(time.RFC3339))
				*dbInitiallyUnavailable = false
			} else {
				log.Printf("Successfully updated MaxMind database from %s at %s", source, time.Now().Format(time.RFC3339))
			}
			dbUpdateStatus.WithLabelValues("success", source).Set(1)
			if oldDB != nil {
				if err := oldDB.Close(); err != nil {
					log.Printf("Failed to close old MaxMind database: %v", err)
				}
			}
		}
	}
}

// loadNewDatabase loads a new MaxMind database from a local file or URL.
func loadNewDatabase(source, licenseKey, dbPath string) (*geoip2.Reader, error) {
	var data []byte
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		// Download from MaxMind API
		if licenseKey == "" {
			return nil, fmt.Errorf("missing MaxMind license key for URL source")
		}
		resp, err := http.Get(source)
		if err != nil {
			return nil, fmt.Errorf("failed to download database from %s: %w", source, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code %d downloading database from %s", resp.StatusCode, source)
		}
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read database from %s: %w", source, err)
		}
		// Save to temporary file
		tmpFile, err := os.CreateTemp("", "GeoLite2-ASN-*.mmdb")
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
		tmpFile.Close() // Close without checking error to avoid unused err
		db, err := geoip2.Open(tmpFile.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to open new database: %w", err)
		}
		// Move temp file to dbPath
		if err := os.Rename(tmpFile.Name(), dbPath); err != nil {
			if closeErr := db.Close(); closeErr != nil {
				log.Printf("Failed to close database after rename error: %v", closeErr)
			}
			return nil, fmt.Errorf("failed to move new database to %s: %w", dbPath, err)
		}
		return db, nil
	} else {
		// Load from local file
		db, err := geoip2.Open(source)
		if err != nil {
			return nil, fmt.Errorf("failed to open database from %s: %w", source, err)
		}
		return db, nil
	}
}
