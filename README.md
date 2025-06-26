# Tracer

A Prometheus exporter for MTR (My Traceroute) that runs MTR periodically and exposes network diagnostic metrics, enhanced with Autonomous System Number (ASN) information using a MaxMind GeoLite2 ASN database.

## Features

- Runs MTR against single or multiple targets with configurable schedules.
- Exposes Prometheus metrics for packet loss, latency, route volatility, MaxMind database update status, and more, with `target`, `hop`, `ip`, `asn`, and `org` labels.
- Supports ASN lookups using a local `GeoLite2-ASN.mmdb` database, with fallback to "unavailable" if the database is unavailable.
- Safely updates the MaxMind database in-line at configurable intervals, using local files or MaxMind API downloads, with success/failure metrics.
- Configurable via command-line flags or YAML file (with `#` comment support and environment variable substitution).
- Redirects non-`/metrics` HTTP requests to `/metrics` (and non-`/metrics/golang` if Go metrics enabled).
- Logs to stdout or a specified file, including detailed MaxMind update events and a specific message when the database is first downloaded after being unavailable.
- Default configuration (`default_config.yaml`) used when no arguments are provided.
- Option to disable Go runtime metrics.
- Continues execution with ASN values as "unavailable" if `GeoLite2-ASN.mmdb` is missing, until the database is downloaded or provided.

## Installation

### Prerequisites

- Go 1.21 or higher
- MTR (My Traceroute) installed (`sudo apt install mtr` or equivalent)
- MaxMind GeoLite2 ASN database (`GeoLite2-ASN.mmdb`, optional at startup; can be downloaded via `db_update_source`)
- MaxMind license key (for API database downloads)

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

4. Set MTR permissions (If raw socket access required):
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
- `-db-path string`: Path to MaxMind `GeoLite2-ASN.mmdb` database (default: `GeoLite2-ASN.mmdb` in executable directory).
- `-log-file string`: Path to log file (default: stdout; overridden by `log_file` in config.yaml).
- `-db-update-interval duration`: Interval to check for MaxMind database updates (e.g., `24h`; 0 disables updates).
- `-db-update-source string`: Source for MaxMind database updates (local file path or MaxMind API URL, e.g., `https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_KEY&suffix=tar.gz`).
- `-maxmind-license-key string`: MaxMind license key for API downloads.
- `-