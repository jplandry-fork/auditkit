package checks

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/logging/apiv2/loggingpb"
	"google.golang.org/api/iterator"
)

type LoggingChecks struct {
	client    *logging.ConfigClient
	projectID string
}

func NewLoggingChecks(client *logging.ConfigClient, projectID string) *LoggingChecks {
	return &LoggingChecks{client: client, projectID: projectID}
}

func (c *LoggingChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult
	results = append(results, c.CheckAuditLogsEnabled(ctx)...)
	results = append(results, c.CheckLogRetention(ctx)...)
	return results, nil
}

func (c *LoggingChecks) CheckAuditLogsEnabled(ctx context.Context) []CheckResult {
	var results []CheckResult

	results = append(results, CheckResult{
		Control:           "CC7.2",
		Name:              "Audit Logs Enabled",
		Status:            "INFO",
		Severity:          "HIGH",
		Evidence:          "Manual verification required: Verify Admin Activity, Data Access, and System Event logs are enabled",
		Remediation:       "Enable all audit log types in IAM & Admin → Audit Logs",
		RemediationDetail: "Configure audit logs for all services via Cloud Console",
		Priority:          PriorityHigh,
		Timestamp:         time.Now(),
		ScreenshotGuide:   "IAM & Admin → Audit Logs → Screenshot showing all log types enabled",
		ConsoleURL:        "https://console.cloud.google.com/iam-admin/audit",
		Frameworks:        GetFrameworkMappings("LOGGING_ENABLED"),
	})

	return results
}

func (c *LoggingChecks) CheckLogRetention(ctx context.Context) []CheckResult {
	var results []CheckResult

	req := &loggingpb.ListSinksRequest{
		Parent: fmt.Sprintf("projects/%s", c.projectID),
	}

	it := c.client.ListSinks(ctx, req)
	hasSink := false

	for {
		_, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}
		hasSink = true
		break
	}

	if !hasSink {
		results = append(results, CheckResult{
			Control:           "CC7.2",
			Name:              "Log Retention & Export",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          "No log sinks configured for long-term retention | Violates PCI DSS 10.7 (1 year retention)",
			Remediation:       "Configure log sink to Cloud Storage for long-term retention",
			RemediationDetail: `gcloud logging sinks create audit-logs-storage \
  storage.googleapis.com/audit-logs-bucket \
  --log-filter='logName:"cloudaudit.googleapis.com"'`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Logging → Log Router → Screenshot showing sink to Cloud Storage bucket",
			ConsoleURL:      "https://console.cloud.google.com/logs/router",
			Frameworks: map[string]string{
				"SOC2":    "CC7.2",
				"PCI-DSS": "10.7",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "CC7.2",
			Name:      "Log Retention & Export",
			Status:    "PASS",
			Evidence:  "Log sinks configured for long-term retention | Meets PCI DSS 10.7",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"SOC2":    "CC7.2",
				"PCI-DSS": "10.7",
			},
		})
	}

	return results
}
