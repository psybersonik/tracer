package mtr

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
)

// Report represents an MTR report.
type Report struct {
	Hops []Hop `json:"hubs"`
}

// MTRReportWrapper wraps the report for nested JSON structure.
type MTRReportWrapper struct {
	Report Report `json:"report"`
}

// Hop represents a single hop in an MTR report.
type Hop struct {
	Host         string  `json:"host"`
	LossPercent  float64 `json:"Loss%"`
	Sent         int     `json:"Snt"`
	Last         float64 `json:"Last"`
	Avg          float64 `json:"Avg"`
	Best         float64 `json:"Best"`
	Wrst         float64 `json:"Wrst"`
	StdDev       float64 `json:"StDev"`
	ASN          string
	Organization string
}

// Runner executes MTR and collects reports.
type Runner struct {
	args     []string
	asnFunc  func(string) (string, string)
	reporter *exec.Cmd
}

// NewRunner creates a new MTR runner with ASN lookup function.
func NewRunner(args []string, asnFunc func(string) (string, string)) *Runner {
	return &Runner{args: args, asnFunc: asnFunc}
}

// Args returns the MTR arguments.
func (r *Runner) Args() []string {
	return r.args
}

// Run executes MTR and returns a report.
func (r *Runner) Run(ctx context.Context) (Report, error) {
	args := append([]string{"--report", "--json"}, r.args...)
	cmd := exec.CommandContext(ctx, "mtr", args...)
	r.reporter = cmd

	output, err := cmd.Output()
	if err != nil {
		log.Printf("MTR command failed: %v, output: %s", err, string(output))
		return Report{}, fmt.Errorf("mtr failed: %w", err)
	}

	var wrapper MTRReportWrapper
	if err := json.Unmarshal(output, &wrapper); err != nil {
		log.Printf("Failed to parse MTR JSON: %v, output: %s", err, string(output))
		return Report{}, fmt.Errorf("failed to parse mtr output: %w", err)
	}
	report := wrapper.Report
	log.Printf("MTR report parsed: %d hops", len(report.Hops))

	for i := range report.Hops {
		if report.Hops[i].Host != "" && report.Hops[i].Host != "???" {
			asn, org := r.asnFunc(report.Hops[i].Host)
			report.Hops[i].ASN = asn
			report.Hops[i].Organization = org
		} else {
			report.Hops[i].ASN = "unknown"
			report.Hops[i].Organization = "unknown"
		}
	}

	return report, nil
}
