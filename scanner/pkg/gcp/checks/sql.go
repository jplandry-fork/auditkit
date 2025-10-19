package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/sqladmin/v1"
)

type SQLChecks struct {
	service   *sqladmin.Service
	projectID string
}

func NewSQLChecks(service *sqladmin.Service, projectID string) *SQLChecks {
	return &SQLChecks{service: service, projectID: projectID}
}

func (c *SQLChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult
	results = append(results, c.CheckPublicIP(ctx)...)
	results = append(results, c.CheckBackupEnabled(ctx)...)
	results = append(results, c.CheckSSLRequired(ctx)...)
	return results, nil
}

func (c *SQLChecks) CheckPublicIP(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	publicInstances := []string{}
	for _, instance := range instanceList.Items {
		if instance.Settings != nil && instance.Settings.IpConfiguration != nil {
			if instance.Settings.IpConfiguration.Ipv4Enabled {
				publicInstances = append(publicInstances, instance.Name)
			}
		}
	}

	if len(publicInstances) > 0 {
		results = append(results, CheckResult{
			Control:           "CC6.6",
			Name:              "Cloud SQL - Public IP",
			Status:            "FAIL",
			Severity:          "CRITICAL",
			Evidence:          fmt.Sprintf("CRITICAL: %d Cloud SQL instances have public IPs: %s | Violates PCI DSS 1.3.1", len(publicInstances), strings.Join(publicInstances, ", ")),
			Remediation:       "Disable public IP and use private IP or Cloud SQL Proxy",
			RemediationDetail: "gcloud sql instances patch INSTANCE_NAME --no-assign-ip",
			Priority:          PriorityCritical,
			Timestamp:         time.Now(),
			ScreenshotGuide:   "SQL → Connections → Public IP address = Not enabled",
			ConsoleURL:        "https://console.cloud.google.com/sql/instances",
			Frameworks:        GetFrameworkMappings("SQL_PUBLIC_IP"),
		})
	} else if len(instanceList.Items) > 0 {
		results = append(results, CheckResult{
			Control:   "CC6.6",
			Name:      "Cloud SQL - Public IP",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("All %d SQL instances use private IPs | Meets PCI DSS 1.3.1", len(instanceList.Items)),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: GetFrameworkMappings("SQL_PUBLIC_IP"),
		})
	}

	return results
}

func (c *SQLChecks) CheckBackupEnabled(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	noBackup := []string{}
	for _, instance := range instanceList.Items {
		if instance.Settings != nil && instance.Settings.BackupConfiguration != nil {
			if !instance.Settings.BackupConfiguration.Enabled {
				noBackup = append(noBackup, instance.Name)
			}
		} else {
			noBackup = append(noBackup, instance.Name)
		}
	}

	if len(noBackup) > 0 {
		results = append(results, CheckResult{
			Control:           "A1.2",
			Name:              "Cloud SQL - Automated Backups",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d SQL instances without automated backups: %s | Violates PCI DSS 9.5.1", len(noBackup), strings.Join(noBackup, ", ")),
			Remediation:       "Enable automated daily backups",
			RemediationDetail: "gcloud sql instances patch INSTANCE_NAME --backup-start-time=03:00",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			ScreenshotGuide:   "SQL → Backups → Automated backups enabled",
			ConsoleURL:        "https://console.cloud.google.com/sql/instances",
			Frameworks:        GetFrameworkMappings("SQL_BACKUP_ENABLED"),
		})
	} else if len(instanceList.Items) > 0 {
		results = append(results, CheckResult{
			Control:   "A1.2",
			Name:      "Cloud SQL - Automated Backups",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("All %d SQL instances have automated backups | Meets PCI DSS 9.5.1", len(instanceList.Items)),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: GetFrameworkMappings("SQL_BACKUP_ENABLED"),
		})
	}

	return results
}

func (c *SQLChecks) CheckSSLRequired(ctx context.Context) []CheckResult {
	var results []CheckResult
	instanceList, err := c.service.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	noSSL := []string{}
	for _, instance := range instanceList.Items {
		if instance.Settings != nil && instance.Settings.IpConfiguration != nil {
			if !instance.Settings.IpConfiguration.RequireSsl {
				noSSL = append(noSSL, instance.Name)
			}
		}
	}

	if len(noSSL) > 0 {
		results = append(results, CheckResult{
			Control:           "CC6.1",
			Name:              "Cloud SQL - SSL Enforcement",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d SQL instances do not require SSL: %s | Violates PCI DSS 4.1", len(noSSL), strings.Join(noSSL, ", ")),
			Remediation:       "Require SSL for all connections",
			RemediationDetail: "gcloud sql instances patch INSTANCE_NAME --require-ssl",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			ScreenshotGuide:   "SQL → Connections → Require SSL = Enabled",
			ConsoleURL:        "https://console.cloud.google.com/sql/instances",
			Frameworks: map[string]string{
				"SOC2":    "CC6.1",
				"PCI-DSS": "4.1",
			},
		})
	} else if len(instanceList.Items) > 0 {
		results = append(results, CheckResult{
			Control:   "CC6.1",
			Name:      "Cloud SQL - SSL Enforcement",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("All %d SQL instances require SSL | Meets PCI DSS 4.1", len(instanceList.Items)),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"SOC2":    "CC6.1",
				"PCI-DSS": "4.1",
			},
		})
	}

	return results
}
