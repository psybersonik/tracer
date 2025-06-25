# Tracer

A Prometheus exporter for MTR (My Traceroute) that runs MTR periodically and exposes network diagnostic metrics, enhanced with Autonomous System Number (ASN) information using a MaxMind GeoLite2 ASN database.


## Features

- Runs MTR against single or multiple targets with configurable schedules.
- Exposes Prometheus metrics for packet loss, latency, route volatility, and more, with `target`, `hop`, `ip`, `asn`, and `org` labels.
- Supports ASN lookups using a local `GeoLite2-ASN.mmdb` database.
- Configurable via command-line flags or YAML file (with `#` comment support).
- Redirects non-`/metrics` HTTP requests to `/metrics` with a 302 status.
- Logs to stdout or a specified file.
- Default configuration (`default_config.yaml`) used when no arguments are provided.

## Installation

### Prerequisites

- Go 1.21 or higher
- MTR (My Traceroute) installed (`sudo apt install mtr` or equivalent)
- MaxMind GeoLite2 ASN database (`GeoLite2-ASN.mmdb`)

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

4. Set MTR permissions (requires raw socket access):
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
sudo ./tracer -metrics-port=9090 -schedule="@every 10s" -log-file=/tmp/tracer.log -- 1.1.1.1
```

Run with default config (requires `default_config.yaml` in the executable directory):
```bash
sudo ./tracer
```

View MTR metrics at `http://localhost:<metrics-port>/metrics` and Golang runtime metrics at `http://localhost:<metrics-port>/metrics/golang`. Requests to other paths (e.g., `/`) redirect to `/metrics`.

### Command-Line Flags

- `-metrics-port int`: Port for Prometheus metrics HTTP endpoint (default: 8080).
- `-config string`: Path to YAML config file defining settings and MTR targets (e.g., `config.yaml`).
- `-db-path string`: Path to MaxMind `GeoLite2-ASN.mmdb` database (default: `GeoLite2-ASN.mmdb` in executable directory).
- `-log-file string`: Path to log file (default: stdout; overridden by `log_file` in config.yaml).
- `-schedule string`: Cron schedule for single target (e.g., `@every 10s` or `0 * * * * *`) (default: `@every 1m`).
- `-help`: Display help with usage and configuration details.

### YAML Configuration

The YAML config supports `#` comments and can define settings and multiple targets. Command-line flags override YAML settings. Example `config.yaml`:
```yaml
# Configuration for tracer
metrics_port: 8080  # Prometheus metrics port
db_path: /path/to/GeoLite2-ASN.mmdb
log_file: /path/to/tracer.log
targets:
  - host: 1.1.1.1  # Cloudflare DNS
    schedule: "@every 10s"
  - host: 8.8.8.8  # Google DNS
    schedule: "@every 30s"
  - host: google.com
    schedule: "0 * * * * *"  # Every minute
```

If no arguments are provided, the program uses `default_config.yaml` in the executable directory, which must exist. Example `default_config.yaml`:
```yaml
# Default configuration
metrics_port: 8080
db_path: GeoLite2-ASN.mmdb
log_file: tracer.log
targets:
  - host: 1.1.1.1
    schedule: "@every 10s"
```

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

Example:
```
mtr_hop_loss_ratio{target="1.1.1.1",hop="intermediate",ip="10.196.255.74",asn="unknown",org="unknown"} 0.1
mtr_hop_loss_ratio{target="1.1.1.1",hop="last",ip="one.one.one.one",asn="AS13335",org="Cloudflare"} 0
mtr_route_volatility{target="1.1.1.1",route_changed="false",hop_count_variance="0.25",latency_jitter="1.50"} 1
mtr_report_duration_ms{target="1.1.1.1"} 16279
```

#### Golang Metrics (`/metrics/golang`)

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

See LICENCE File.
## Contributing

Contributions are welcome! Please open an issue or pull request on [GitHub](https://github.com/psybersonik/tracer).