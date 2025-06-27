package mtr

import (
	"github.com/prometheus/client_golang/prometheus"
)

type Hub struct {
	Target       string
	Hop          string
	IP           string
	ASN          string
	Organization string
}

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

func NewCollector() *Collector {
	return &Collector{
		HopLossRatio: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_hop_loss_ratio",
			Help: "The ratio of lost packets per hop",
		}, []string{"target", "hop", "ip", "asn", "org"}),
		HopSentTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mtr_hop_sent_total",
			Help: "The total number of sent packets per hop",
		}, []string{"target", "hop", "ip", "asn", "org"}),
		HopLastMs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_hop_last_ms",
			Help: "The last measured round-trip time per hop in milliseconds",
		}, []string{"target", "hop", "ip", "asn", "org"}),
		HopAvgMs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_hop_avg_ms",
			Help: "The average round-trip time per hop in milliseconds",
		}, []string{"target", "hop", "ip", "asn", "org"}),
		HopBestMs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_hop_best_ms",
			Help: "The best round-trip time per hop in milliseconds",
		}, []string{"target", "hop", "ip", "asn", "org"}),
		HopWorstMs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_hop_worst_ms",
			Help: "The worst round-trip time per hop in milliseconds",
		}, []string{"target", "hop", "ip", "asn", "org"}),
		HopStddevMs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_hop_stddev_ms",
			Help: "The standard deviation of round-trip times per hop in milliseconds",
		}, []string{"target", "hop", "ip", "asn", "org"}),
		ReportMs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_report_duration_ms",
			Help: "The duration of the mtr report in milliseconds",
		}, []string{"target"}),
		ReportHops: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_report_hops",
			Help: "The number of hops in the mtr report",
		}, []string{"target"}),
		ReportLoss: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_report_loss",
			Help: "The overall loss ratio of the mtr report",
		}, []string{"target"}),
		ReportPackets: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_report_packets",
			Help: "The total number of packets sent in the mtr report",
		}, []string{"target"}),
		RouteVolatility: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mtr_route_volatility",
			Help: "Indicates route volatility metrics: route_changed (true/false), hop_count_variance (variance of hop counts), latency_jitter (average latency variance across hops)",
		}, []string{"target", "route_changed", "hop_count_variance", "latency_jitter"}),
	}
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
