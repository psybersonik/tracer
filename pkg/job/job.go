package job

import (
	"context"
	"log"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/psybersonik/tracer/pkg/mtr"
)

// MTRJob runs MTR and collects metrics.
type MTRJob struct {
	runner   *mtr.Runner
	metrics  *mtr.Collector
	reports  []mtr.Report
	duration time.Duration
	target   string
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

	return nil
}
