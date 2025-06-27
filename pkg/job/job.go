package job

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/psybersonik/tracer/pkg/mtr"
)

// MTRJob runs MTR and collects metrics.
type MTRJob struct {
	runner          *mtr.Runner
	metrics         *mtr.Collector
	reports         []mtr.Report
	duration        time.Duration
	target          string
	lastHopSequence []string
}

// NewMTRJob creates a new MTR job with ASN lookup function.
func NewMTRJob(args []string, asnFunc func(string) (string, string)) *MTRJob {
	target := args[len(args)-1]
	return &MTRJob{
		runner:  mtr.NewRunner(args, asnFunc),
		metrics: mtr.NewCollector(),
		target:  target,
	}
}

// Target returns the target host of the MTR job.
func (j *MTRJob) Target() string {
	return j.target
}

// Describe implements prometheus.Collector.
func (j *MTRJob) Describe(ch chan<- *prometheus.Desc) {
	j.metrics.Describe(ch)
}

// Collect implements prometheus.Collector.
func (j *MTRJob) Collect(ch chan<- prometheus.Metric) {
	j.metrics.Collect(ch)
}

// Run executes the MTR job.
func (j *MTRJob) Run(ctx context.Context) error {
	start := time.Now()
	report, err := j.runner.Run(ctx)
	if err != nil {
		log.Printf("MTR run failed for %s: %v", j.target, err)
		return err
	}
	log.Printf("MTR report generated for %s: %d hops", j.target, len(report.Hops))
	j.duration = time.Since(start)
	j.reports = append([]mtr.Report{report}, j.reports...)
	if len(j.reports) > 10 {
		j.reports = j.reports[:10]
	}

	// Check route change
	currentHopSequence := make([]string, len(report.Hops))
	for i, hop := range report.Hops {
		currentHopSequence[i] = hop.Host
	}
	routeChanged := "false"
	if len(j.lastHopSequence) > 0 && !equalHopSequences(j.lastHopSequence, currentHopSequence) {
		routeChanged = "true"
	}
	j.lastHopSequence = currentHopSequence

	// Calculate hop count variance
	hopCountVariance := calculateHopCountVariance(j.reports)
	// Calculate latency jitter
	latencyJitter := calculateLatencyJitter(j.reports)

	j.metrics.Reset()
	var totalPackets int
	var totalLoss float64
	for i, hop := range report.Hops {
		hopType := "intermediate"
		if i == 0 {
			hopType = "first"
		} else if i == len(report.Hops)-1 {
			hopType = "last"
		}
		hub := mtr.Hub{
			Target:       j.target,
			Hop:          hopType,
			IP:           hop.Host,
			ASN:          hop.ASN,
			Organization: hop.Organization,
		}
		j.metrics.HopLossRatio.WithLabelValues(hub.Target, hub.Hop, hub.IP, hub.ASN, hub.Organization).Set(hop.LossPercent / 100)
		j.metrics.HopSentTotal.WithLabelValues(hub.Target, hub.Hop, hub.IP, hub.ASN, hub.Organization).Add(float64(hop.Sent))
		j.metrics.HopLastMs.WithLabelValues(hub.Target, hub.Hop, hub.IP, hub.ASN, hub.Organization).Set(hop.Last)
		j.metrics.HopAvgMs.WithLabelValues(hub.Target, hub.Hop, hub.IP, hub.ASN, hub.Organization).Set(hop.Avg)
		j.metrics.HopBestMs.WithLabelValues(hub.Target, hub.Hop, hub.IP, hub.ASN, hub.Organization).Set(hop.Best)
		j.metrics.HopWorstMs.WithLabelValues(hub.Target, hub.Hop, hub.IP, hub.ASN, hub.Organization).Set(hop.Wrst)
		j.metrics.HopStddevMs.WithLabelValues(hub.Target, hub.Hop, hub.IP, hub.ASN, hub.Organization).Set(hop.StdDev)
		totalPackets += hop.Sent
		totalLoss += hop.LossPercent / 100
	}
	j.metrics.ReportMs.WithLabelValues(j.target).Set(float64(j.duration.Milliseconds()))
	j.metrics.ReportHops.WithLabelValues(j.target).Set(float64(len(report.Hops)))
	j.metrics.ReportLoss.WithLabelValues(j.target).Set(totalLoss / float64(len(report.Hops)))
	j.metrics.ReportPackets.WithLabelValues(j.target).Set(float64(totalPackets))
	// Set route volatility metric
	j.metrics.RouteVolatility.WithLabelValues(
		j.target,
		routeChanged,
		fmt.Sprintf("%.2f", hopCountVariance),
		fmt.Sprintf("%.2f", latencyJitter),
	).Set(1)

	return nil
}

// equalHopSequences compares two hop sequences for equality.
func equalHopSequences(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// calculateHopCountVariance computes the variance of hop counts across reports.
func calculateHopCountVariance(reports []mtr.Report) float64 {
	if len(reports) < 2 {
		return 0
	}
	var sum, mean float64
	n := float64(len(reports))
	for _, report := range reports {
		hopCount := float64(len(report.Hops))
		sum += hopCount
	}
	mean = sum / n
	var variance float64
	for _, report := range reports {
		hopCount := float64(len(report.Hops))
		variance += (hopCount - mean) * (hopCount - mean)
	}
	return variance / n
}

// calculateLatencyJitter computes the average variance of Avg latency across hops in consecutive reports.
func calculateLatencyJitter(reports []mtr.Report) float64 {
	if len(reports) < 2 {
		return 0
	}
	current := reports[0]
	previous := reports[1]
	var sum, count float64
	for _, currHop := range current.Hops {
		for _, prevHop := range previous.Hops {
			if currHop.Host == prevHop.Host && currHop.Host != "" && currHop.Host != "???" {
				diff := currHop.Avg - prevHop.Avg
				sum += diff * diff
				count++
			}
		}
	}
	if count == 0 {
		return 0
	}
	return sum / count
}
