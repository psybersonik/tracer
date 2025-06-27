# Tracer

**Version: 0.7.0**

A Prometheus exporter for MTR (My Traceroute) that runs MTR periodically and exposes network diagnostic metrics, enhanced with Autonomous System Number (ASN) information using a MaxMind GeoLite2-ASN database.

## Features

- Runs MTR against single or multiple targets with configurable schedules.
- Exposes Prometheus metrics for packet loss, latency, route volatility, and database update status, with `target`, `hop`, `ip`, `asn`, and `org` labels.
- Supports ASN lookups using a local MaxMind GeoLite2-ASN.mmdb database, loaded into memory, with fallback to "unavailable" if the database is unavailable or no ASN entry is found.
- Safely updates the MaxMind database at configurable intervals, using local files or MaxMind API downloads, with success/failure metrics.
- Configurable via command-line flags or YAML file (with `#` comment support and environment variable substitution).
- Redirects non-`/metrics` HTTP requests to `/metrics` (and non-`/metrics/golang` if Go metrics enabled).
- Logs to stdout or a specified file, including detailed database update events and version information.
- Default configuration (`default_config.yaml`) used when no arguments are provided.
- Option to disable Go runtime metrics.
- Continues execution with ASN values as "unavailable" if `GeoLite2-ASN.mmdb` is missing, until the database is downloaded or provided.

## Installation

### Prerequisites

- Go 1.21 or higher
- MTR (My Traceroute) installed (`sudo apt install mtr` or equivalent)
- MaxMind GeoLite2-ASN.mmdb database (optional at startup; can be downloaded via `db_update_source` with a valid license key)

### Build

1. Clone the repository:
   ```bash
   git clone https://github.com/psybersonik/tracer.git
   cd tracer
   ```

2. Install dependencies:
   ```bash
   go mod tidy
   go mod vendor
   ```

3. Build the executable:
   ```bash
   go build -o tracer .
   ```

4. Set MTR permissions (if raw socket access required):
   ```bash
   sudo setcap cap_net_raw+ep /usr/bin/mtr
   sudo setcap cap_net_raw+ep ./tracer
   ```

### Docker

Build and run with Docker:
```bash
docker build -t tracer .
docker run -v /path/to/GeoLite2-ASN.mmdb:/GeoLite2-ASN.mmdb -v /path/to/config.yaml:/config.yaml -p 8080:8080 tracer -config=/config.yaml
```

## Usage

Run with a YAML config file:
```bash
sudo ./tracer -config=/path/to/config.yaml
```

Run with a single target:
```bash
sudo ./tracer -metrics-port=9090 -schedule="@every 300s" -log-file=/tmp/tracer.log -- 1.1.1.1
```

Run with default config (requires `default_config.yaml` in the executable directory):
```bash
sudo ./tracer
```

Disable Go runtime metrics:
```bash
sudo ./tracer -config=/path/to/config.yaml -disable-golang-metrics
```

View MTR metrics at `http://localhost:<metrics-port>/metrics` and Go runtime metrics at `http://localhost:<metrics-port>/metrics/golang` (unless disabled). Requests to other paths (e.g., `/`) redirect to `/metrics`.

### Command-Line Flags

- `-metrics-port int`: Port for Prometheus metrics HTTP endpoint (default: 8080).
- `-disable-golang-metrics`: Disable Go runtime metrics endpoint (default: false).
- `-config string`: Path to YAML config file defining settings and MTR targets (e.g., `config.yaml`).
- `-db-path string`: Path to MaxMind GeoLite2-ASN.mmdb database (default: `GeoLite2-ASN.mmdb` in executable directory).
- `-log-file string`: Path to log file (default: stdout; overridden by `log_file` in config.yaml).
- `-db-update-interval duration`: Interval to check for MaxMind GeoLite2-ASN.mmdb updates (e.g., `24h`; 0 disables updates).
- `-db-update-source string`: Source for MaxMind GeoLite2-ASN.mmdb updates (local file path or MaxMind API URL, e.g., `https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_KEY&suffix=tar.gz`).
- `-maxmind-license-key string`: MaxMind license key for downloading GeoLite2-ASN.mmdb updates.
- `-schedule string`: Cron schedule for single target (e.g., `@every 300s` or `0 * * * * *`) (default: `@every 1m`).
- `-help`: Display help with usage and configuration details.

### YAML Configuration

The YAML config supports `#` comments, environment variable substitution (`${VARIABLE}` or `${VARIABLE:default}`), and defines settings and multiple targets. Command-line flags override YAML settings. If `GeoLite2-ASN.mmdb` is missing at startup, `tracer` continues with ASN values as "unavailable" and attempts to download the database if `db_update_source` and `maxmind_license_key` are set, logging a specific message upon successful initial download. Example `config.yaml`:
```yaml
# Configuration for tracer
metrics_port: 8080  # Prometheus metrics port
disable_golang_metrics: false  # Disable Go runtime metrics
db_path: /tmp/GeoLite2-ASN.mmdb  # Path to MaxMind database
log_file: /tmp/tracer.log  # Log output file
db_update_interval: 24h  # Check for updates
db_update_source: https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_KEY&suffix=tar.gz
maxmind_license_key: YOUR_KEY  # Example: ${MAXMIND_LICENSE_KEY:your_default_key}
targets:
  - host: 1.1.1.1  # Cloudflare DNS
    schedule: "@every 300s"
  - host: 8.8.8.8  # Google DNS
    schedule: "@every 300s"
  - host: google.com  # Google
    schedule: "@every 300s"
  - host: www.akamai.com  # Akamai CDN
    schedule: "@every 300s"
```

If no arguments are provided, the program uses `default_config.yaml` in the executable directory, which must exist. Example `default_config.yaml`:
```yaml
# Default configuration
metrics_port: 8080
disable_golang_metrics: false
db_path: GeoLite2-ASN.mmdb
log_file: tracer.log
db_update_interval: 24h
db_update_source: https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_KEY&suffix=tar.gz
maxmind_license_key: YOUR_KEY
targets:
  - host: 1.1.1.1
    schedule: "@every 300s"
```

Environment variables can be substituted using `${VARIABLE}` or `${VARIABLE:default}` syntax. If a variable is unset and no default is provided, it resolves to an empty string, and a warning is logged.

### MaxMind GeoLite2-ASN Database

The MaxMind GeoLite2-ASN.mmdb database is used for ASN lookups and is loaded into memory at startup for efficient queries. Obtain it from MaxMind (requires a free account and license key). If the database is unavailable or no matching ASN entry is found, ASN and organization values are set to "unavailable".

### Metrics

#### MTR Metrics (`/metrics`)

- `mtr_hop_loss_ratio{target, hop, ip, asn, org}`: Packet loss ratio per hop.
- `mtr_hop_sent_total{target, hop, ip, asn, org}`: Total packets sent per hop.
- `mtr_hop_last_ms{target, hop, ip, asn, org}`: Last round-trip time per hop (ms).
- `mtr_hop_avg_ms{target, hop, ip, asn, org}`: Average round-trip time per hop (ms).
- `mtr_hop_best_ms{target, hop, ip, asn, org}`: Best round-trip time per hop (ms).
- `mtr_hop_worst_ms{target, hop, ip, asn, org}`: Worst round-trip time per hop (ms).
- `mtr_hop_stddev_ms{target, hop, ip, asn, org}`: Standard deviation of round-trip times per hop (ms).
- `mtr_report_duration_ms{target}`: Duration of the MTR report (ms).
- `mtr_report_hops{target}`: Number of hops in the report.
- `mtr_report_loss{target}`: Overall loss ratio of the report.
- `mtr_report_packets{target}`: Total packets sent in the report.
- `mtr_route_volatility{target, route_changed, hop_count_variance, latency_jitter}`: Route volatility metrics:
    - `route_changed`: "true" if hop sequence changed, "false" otherwise.
    - `hop_count_variance`: Variance of hop counts across recent reports.
    - `latency_jitter`: Average variance of latency across matching hops in consecutive reports.
      Value is 1 if metrics are reported, 0 otherwise.
- `mtr_maxmind_db_update_status{status, source}`: Status of MaxMind GeoLite2-ASN.mmdb updates (1 for success, 0 for failure).
- The `hop` label indicates the hop type:
    - `"first"`: First hop in the traceroute.
    - `"perimeter"`: First hop with a public IP address.
    - `"intermediate"`: Middle hops not marked as `first`, `perimeter`, or `last`.
    - `"last"`: Final hop in the traceroute.

Example:
```
mtr_hop_loss_ratio{target="1.1.1.1",hop="first",ip="10.196.255.74",asn="unavailable",org="unavailable"} 0.1
mtr_hop_loss_ratio{target="1.1.1.1",hop="perimeter",ip="203.0.113.1",asn="unavailable",org="unavailable"} 0.05
mtr_hop_loss_ratio{target="1.1.1.1",hop="last",ip="one.one.one.one",asn="AS13335",org="Cloudflare"} 0
mtr_hop_loss_ratio{target="1.1.1.1",hop="intermediate",ip="x.x.x.x",asn="unknown",org="unknown"} 0.2
mtr_route_volatility{target="1.1.1.1",route_changed="false",hop_count_variance="0.25",latency_jitter="1.50"} 1
mtr_maxmind_db_update_status{status="success",source="https://download.maxmind.com/..."} 1
mtr_report_duration_ms{target="1.1.1.1"} 16279
```

#### Golang Metrics (`/metrics/golang`)

Available unless disabled via `-disable-golang-metrics` or `disable_golang_metrics: true`:
- `go_goroutines`
- `go_memstats_alloc_bytes`
- `process_cpu_seconds_total`
- And other runtime metrics.

Example:
```
go_goroutines 10
go_memstats_alloc_bytes 123456
process_cpu_seconds_total 0.01
```

## License

Licensed under [MIT License](https://github.com/psybersonik/tracer?tab=MIT-1-ov-file#readme).

## Contributing

Contributions are welcome! Please open an issue or pull request on [GitHub](https://github.com/psybersonik/tracer).