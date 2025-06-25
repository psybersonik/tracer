package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

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
	metricsPort = flag.Int("metrics-port", 8080, "Port for Prometheus metrics HTTP endpoint (default: 8080)")
	configPath  = flag.String("config", "", "Path to YAML config file defining settings and MTR targets (e.g., config.yaml)")
	dbPath      = flag.String("db-path", "", "Path to MaxMind GeoLite2-ASN.mmdb database for ASN lookups (default: GeoLite2-ASN.mmdb in executable directory)")
	logFile     = flag.String("log-file", "", "Path to log file (default: stdout; overridden by config.yaml log_file if set)")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] [-- MTR arguments]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "tracer runs MTR (My Traceroute) and exposes network metrics for Prometheus.\n")
		fmt.Fprintf(os.Stderr, "MTR metrics are available at /metrics; Golang runtime metrics at /metrics/golang.\n")
		fmt.Fprintf(os.Stderr, "Requests to other paths redirect to /metrics.\n")
		fmt.Fprintf(os.Stderr, "Use a YAML config file (-config) for settings and multiple targets or specify a single target via MTR arguments.\n")
		fmt.Fprintf(os.Stderr, "If no arguments are provided, uses default_config.yaml in the executable directory.\n")
		fmt.Fprintf(os.Stderr, "Command-line flags override config.yaml settings.\n")
		fmt.Fprintf(os.Stderr, "Example: %s -config=config.yaml\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s -metrics-port=9090 -schedule=\"@every 10s\" -log-file=/tmp/tracer.log -- 1.1.1.1\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nNotes:\n")
		fmt.Fprintf(os.Stderr, "- If -config is set, MTR arguments are ignored.\n")
		fmt.Fprintf(os.Stderr, "- If no arguments are provided, default_config.yaml must exist in the executable directory.\n")
		fmt.Fprintf(os.Stderr, "- Logs are written to stdout unless -log-file or config.yaml log_file is set.\n")
		fmt.Fprintf(os.Stderr, "- Schedule format supports cron (e.g., \"0 * * * * *\" for every minute) or @every <duration> (e.g., @every 10s).\n")
		fmt.Fprintf(os.Stderr, "- YAML config supports # for comments.\n")
		fmt.Fprintf(os.Stderr, "- YAML config example:\n")
		fmt.Fprintf(os.Stderr, "  # Main settings\n")
		fmt.Fprintf(os.Stderr, "  metrics_port: 8080  # Prometheus port\n")
		fmt.Fprintf(os.Stderr, "  db_path: /path/to/GeoLite2-ASN.mmdb\n")
		fmt.Fprintf(os.Stderr, "  log_file: /path/to/tracer.log  # Log output file\n")
		fmt.Fprintf(os.Stderr, "  targets:\n")
		fmt.Fprintf(os.Stderr, "    - host: 1.1.1.1  # Cloudflare DNS\n")
		fmt.Fprintf(os.Stderr, "      schedule: \"@every 10s\"\n")
	}
}

// Config defines the YAML structure for settings and targets.
type Config struct {
	MetricsPort int      `yaml:"metrics_port"`
	DBPath      string   `yaml:"db_path"`
	LogFile     string   `yaml:"log_file"`
	Targets     []Target `yaml:"targets"`
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
func (jm *JobManager) AddJob(job *job.MTRJob) {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	jm.jobs = append(jm.jobs, job)
}

// Describe implements prometheus.Collector.
func (jm *JobManager) Describe(ch chan<- *prometheus.Desc) {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	for _, job := range jm.jobs {
		job.Describe(ch)
	}
}

// Collect implements prometheus.Collector.
func (jm *JobManager) Collect(ch chan<- prometheus.Metric) {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	for _, job := range jm.jobs {
		job.Collect(ch)
	}
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
	logFileValue := *logFile

	// Handle no arguments: use default_config.yaml
	if len(flag.Args()) == 0 && configPathValue == "" {
		configPathValue = filepath.Join(exeDir, "default_config.yaml")
		if _, err := os.Stat(configPathValue); os.IsNotExist(err) {
			log.Fatalf("default config file %s does not exist; please create it or provide arguments", configPathValue)
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

	// Open MaxMind GeoLite2-ASN database
	db, err := geoip2.Open(dbPathValue)
	if err != nil {
		log.Fatalf("failed to open GeoLite2-ASN.mmdb at %s: %v", dbPathValue, err)
	}
	defer db.Close()

	ctx := context.Background()
	scheduler := cron.New(cron.WithSeconds())
	jobManager := NewJobManager()

	// Create separate registries for MTR and Golang metrics
	mtrRegistry := prometheus.NewRegistry()
	golangRegistry := prometheus.NewRegistry()

	// Register MTR metrics
	mtrRegistry.MustRegister(jobManager)

	// Register Golang runtime metrics
	golangRegistry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// Load targets from config
	if configPathValue != "" {
		for _, target := range config.Targets {
			mtrArgs, err := shlex.Split(target.Host)
			if err != nil {
				log.Printf("failed to parse args for %s: %v", target.Host, err)
				continue
			}
			mtrJob := job.NewMTRJob(mtrArgs, func(host string) (string, string) {
				return lookupASN(db, host)
			})
			jobManager.AddJob(mtrJob)
			log.Printf("Running initial MTR job for %s", target.Host)
			if err := mtrJob.Run(ctx); err != nil {
				log.Printf("Initial mtr job for %s failed: %v", target.Host, err)
			}
			_, err = scheduler.AddFunc(target.Schedule, func() {
				log.Printf("Running scheduled MTR job for %s", target.Host)
				if err := mtrJob.Run(ctx); err != nil {
					log.Printf("mtr job for %s failed: %v", target.Host, err)
				}
			})
			if err != nil {
				log.Printf("failed to schedule mtr job for %s: %v", target.Host, err)
				continue
			}
		}
	} else if len(flag.Args()) > 0 {
		// Fallback to single target from command line
		mtrArgs, err := shlex.Split(flag.Args()[0])
		if err != nil {
			log.Fatalf("failed to parse mtr arguments: %v", err)
		}
		mtrJob := job.NewMTRJob(mtrArgs, func(host string) (string, string) {
			return lookupASN(db, host)
		})
		jobManager.AddJob(mtrJob)
		log.Println("Running initial MTR job")
		if err := mtrJob.Run(ctx); err != nil {
			log.Printf("Initial mtr job failed: %v", err)
		}
		_, err = scheduler.AddFunc(*flag.String("schedule", "@every 1m", "Cron schedule for single target (e.g., @every 10s or 0 * * * * *)"), func() {
			log.Println("Running scheduled MTR job")
			if err := mtrJob.Run(ctx); err != nil {
				log.Printf("mtr job for %s failed: %v", mtrJob.Target(), err)
			}
		})
		if err != nil {
			log.Fatalf("failed to schedule mtr job: %v", err)
		}
	} else {
		log.Fatal("missing mtr arguments or config file")
	}

	listenAddr := fmt.Sprintf(":%d", *metricsPort)
	// Serve MTR metrics at /metrics
	http.Handle("/metrics", promhttp.HandlerFor(mtrRegistry, promhttp.HandlerOpts{}))
	// Serve Golang metrics at /metrics/golang
	http.Handle("/metrics/golang", promhttp.HandlerFor(golangRegistry, promhttp.HandlerOpts{}))
	// Redirect all other paths to /metrics
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" && r.URL.Path != "/metrics/golang" {
			http.Redirect(w, r, "/metrics", http.StatusFound)
		}
	})
	scheduler.Start()
	log.Printf("tracer v0.6.0 starting, listening on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}

// loadConfig reads and parses the YAML config file, stripping # comments.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	// Strip # comments
	var cleaned bytes.Buffer
	lines := strings.Split(string(data), "\n")
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
	ipStr := host
	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			log.Printf("Failed to resolve hostname %s: %v", host, err)
			return "unknown", "unknown"
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
		log.Printf("Invalid IP after resolution: %s", ipStr)
		return "unknown", "unknown"
	}

	record, err := db.ASN(ip)
	if err != nil {
		log.Printf("ASN lookup failed for %s: %v", ipStr, err)
		return "unknown", "unknown"
	}

	asn := fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
	org := record.AutonomousSystemOrganization
	if org == "" {
		org = "unknown"
	}
	return asn, org
}
