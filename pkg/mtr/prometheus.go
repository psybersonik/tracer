package mtr

import (
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// Hub holds the labels for a hop.
type Hub struct {
	Target       string
	Hop          string
	IP           string
	ASN          string
	Organization string
}

type hop struct {
	Count  int
	IP     string
	ASN    string
	Org    string
	Loss   float64
	Sent   float64
	Last   float64
	Avg    float64
	Best   float64
	Worst  float64
	StdDev float64
}

type report struct {
	Hops     []hop
	Target   string
	HopCount int
	Loss     float64
	Packets  float64
	Duration float64
	Vol      routeVolatility
}

type routeVolatility struct {
	RouteChanged  bool
	HopCountVar   float64
	LatencyJitter float64
}

// Collector holds Prometheus metrics for MTR.
type Collector struct {
	HopLossRatio    *prometheus.GaugeVec
	HopSentTotal    *prometheus.CounterVec
	HopLastMs       *prometheus.GaugeVec
	HopAvgMs        *prometheus.GaugeVec
	HopBestMs       *prometheus.GaugeVec
	HopWorstMs      *prometheus.GaugeVec
	HopStddevMs     *prometheus.GaugeVec
	ReportMs        *prometheus.GaugeVec
	ReportHops      *prometheus.GaugeVec
	ReportLoss      *prometheus.GaugeVec
	ReportPackets   *prometheus.GaugeVec
	RouteVolatility *prometheus.GaugeVec
}

// NewCollector creates a new Collector for MTR metrics.
func NewCollector() *Collector {
	labels := []string{"target", "hop", "ip", "asn", "org"}
	return &Collector{
		HopLossRatio: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_hop_loss_ratio",
			Help: "Packet loss ratio per hop",
		}, labels),
		HopSentTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mtr_hop_sent_total",
			Help: "Total packets sent per hop",
		}, labels),
		HopLastMs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_hop_last_ms",
			Help: "Last round-trip time per hop (ms)",
		}, labels),
		HopAvgMs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_hop_avg_ms",
			Help: "Average round-trip time per hop (ms)",
		}, labels),
		HopBestMs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_hop_best_ms",
			Help: "Best round-trip time per hop (ms)",
		}, labels),
		HopWorstMs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_hop_worst_ms",
			Help: "Worst round-trip time per hop (ms)",
		}, labels),
		HopStddevMs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_hop_stddev_ms",
			Help: "Standard deviation of round-trip times per hop (ms)",
		}, labels),
		ReportMs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_report_duration_ms",
			Help: "Duration of the MTR report (ms)",
		}, []string{"target"}),
		ReportHops: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_report_hops",
			Help: "Number of hops in the report",
		}, []string{"target"}),
		ReportLoss: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_report_loss",
			Help: "Overall loss ratio of the report",
		}, []string{"target"}),
		ReportPackets: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_report_packets",
			Help: "Total packets sent in the report",
		}, []string{"target"}),
		RouteVolatility: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_route_volatility",
			Help: "Route volatility metrics",
		}, []string{"target", "route_changed", "hop_count_variance", "latency_jitter"}),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	c.HopLossRatio.Describe(ch)
	c.HopSentTotal.Describe(ch)
	c.HopLastMs.Describe(ch)
	c.HopAvgMs.Describe(ch)
	c.HopBestMs.Describe(ch)
	c.HopWorstMs.Describe(ch)
	c.HopStddevMs.Describe(ch)
	c.ReportMs.Describe(ch)
	c.ReportHops.Describe(ch)
	c.ReportLoss.Describe(ch)
	c.ReportPackets.Describe(ch)
	c.RouteVolatility.Describe(ch)
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.HopLossRatio.Collect(ch)
	c.HopSentTotal.Collect(ch)
	c.HopLastMs.Collect(ch)
	c.HopAvgMs.Collect(ch)
	c.HopBestMs.Collect(ch)
	c.HopWorstMs.Collect(ch)
	c.HopStddevMs.Collect(ch)
	c.ReportMs.Collect(ch)
	c.ReportHops.Collect(ch)
	c.ReportLoss.Collect(ch)
	c.ReportPackets.Collect(ch)
	c.RouteVolatility.Collect(ch)
}

func (c *Collector) Reset() {
	c.HopLossRatio.Reset()
	c.HopSentTotal.Reset()
	c.HopLastMs.Reset()
	c.HopAvgMs.Reset()
	c.HopBestMs.Reset()
	c.HopWorstMs.Reset()
	c.HopStddevMs.Reset()
	c.ReportMs.Reset()
	c.ReportHops.Reset()
	c.ReportLoss.Reset()
	c.ReportPackets.Reset()
	c.RouteVolatility.Reset()
}

func (c *Collector) Update(r *report, lookup func(string) (string, string)) {
	for i, h := range r.Hops {
		asn, org := lookup(h.IP)
		labels := map[string]string{
			"target": r.Target,
			"hop":    hLabel(i, h.IP, r.Hops),
			"ip":     h.IP,
			"asn":    asn,
			"org":    org,
		}
		c.HopLossRatio.With(labels).Set(h.Loss)
		c.HopSentTotal.With(labels).Add(h.Sent)
		c.HopLastMs.With(labels).Set(h.Last)
		c.HopAvgMs.With(labels).Set(h.Avg)
		c.HopBestMs.With(labels).Set(h.Best)
		c.HopWorstMs.With(labels).Set(h.Worst)
		c.HopStddevMs.With(labels).Set(h.StdDev)
	}
	c.ReportMs.WithLabelValues(r.Target).Set(r.Duration)
	c.ReportHops.WithLabelValues(r.Target).Set(float64(r.HopCount))
	c.ReportLoss.WithLabelValues(r.Target).Set(r.Loss)
	c.ReportPackets.WithLabelValues(r.Target).Set(r.Packets)
	c.RouteVolatility.WithLabelValues(
		r.Target,
		strings.ToLower(strings.Title(strings.ToLower(fmt.Sprintf("%v", r.Vol.RouteChanged)))),
		fmt.Sprintf("%.2f", r.Vol.HopCountVar),
		fmt.Sprintf("%.2f", r.Vol.LatencyJitter),
	).Set(1)
}

func hLabel(i int, ip string, hops []hop) string {
	if i == len(hops)-1 {
		return "last"
	}
	return "intermediate"
}
