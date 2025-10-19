package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"
)

type ComputeChecks struct {
	service   *compute.Service
	projectID string
}

func NewComputeChecks(service *compute.Service, projectID string) *ComputeChecks {
	return &ComputeChecks{service: service, projectID: projectID}
}

func (c *ComputeChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult
	results = append(results, c.CheckDiskEncryption(ctx)...)
	results = append(results, c.CheckPublicIPs(ctx)...)
	results = append(results, c.CheckOSPatchManagement(ctx)...)
	return results, nil
}

func (c *ComputeChecks) CheckDiskEncryption(ctx context.Context) []CheckResult {
	var results []CheckResult
	zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	unencryptedDisks := []string{}
	totalDisks := 0

	for _, zone := range zones.Items {
		diskList, err := c.service.Disks.List(c.projectID, zone.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, disk := range diskList.Items {
			totalDisks++
			if disk.DiskEncryptionKey == nil || disk.DiskEncryptionKey.KmsKeyName == "" {
				unencryptedDisks = append(unencryptedDisks, disk.Name)
			}
		}
	}

	if len(unencryptedDisks) > 0 {
		displayDisks := unencryptedDisks
		if len(unencryptedDisks) > 3 {
			displayDisks = unencryptedDisks[:3]
		}

		results = append(results, CheckResult{
			Control:           "CC6.7",
			Name:              "Disk Encryption with CMEK",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d disks using Google-managed keys instead of customer-managed keys: %s | Violates PCI DSS 3.4", len(unencryptedDisks), strings.Join(displayDisks, ", ")),
			Remediation:       "Use customer-managed encryption keys (CMEK) for sensitive data",
			RemediationDetail: "Create new disk with --kms-key flag or enable default CMEK for project",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			ScreenshotGuide:   "Compute Engine → Disks → Select disk → Encryption showing KMS key",
			ConsoleURL:        "https://console.cloud.google.com/compute/disks",
			Frameworks: map[string]string{
				"SOC2":    "CC6.7",
				"PCI-DSS": "3.4",
			},
		})
	} else if totalDisks > 0 {
		results = append(results, CheckResult{
			Control:   "CC6.7",
			Name:      "Disk Encryption with CMEK",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("All %d disks use customer-managed encryption | Meets PCI DSS 3.4", totalDisks),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	}

	return results
}

func (c *ComputeChecks) CheckPublicIPs(ctx context.Context) []CheckResult {
	var results []CheckResult
	zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	instancesWithPublicIP := []string{}
	totalInstances := 0

	for _, zone := range zones.Items {
		instances, err := c.service.Instances.List(c.projectID, zone.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, instance := range instances.Items {
			totalInstances++
			for _, networkInterface := range instance.NetworkInterfaces {
				if networkInterface.AccessConfigs != nil && len(networkInterface.AccessConfigs) > 0 {
					instancesWithPublicIP = append(instancesWithPublicIP, instance.Name)
					break
				}
			}
		}
	}

	if len(instancesWithPublicIP) > 0 {
		displayInstances := instancesWithPublicIP
		if len(instancesWithPublicIP) > 3 {
			displayInstances = instancesWithPublicIP[:3]
		}

		results = append(results, CheckResult{
			Control:           "CC6.6",
			Name:              "Compute Instances - Public IP Addresses",
			Status:            "FAIL",
			Severity:          "HIGH",
			Evidence:          fmt.Sprintf("%d instances have public IP addresses: %s | Violates PCI DSS 1.3.1", len(instancesWithPublicIP), strings.Join(displayInstances, ", ")),
			Remediation:       "Use Cloud NAT or VPN for outbound connectivity",
			RemediationDetail: "Remove external IPs and configure Cloud NAT for internet access",
			Priority:          PriorityHigh,
			Timestamp:         time.Now(),
			ScreenshotGuide:   "Compute Engine → VM instances → External IP column showing 'None'",
			ConsoleURL:        "https://console.cloud.google.com/compute/instances",
			Frameworks: map[string]string{
				"SOC2":    "CC6.6",
				"PCI-DSS": "1.3.1",
			},
		})
	} else if totalInstances > 0 {
		results = append(results, CheckResult{
			Control:   "CC6.6",
			Name:      "Compute Instances - Public IP Addresses",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("All %d instances use private IPs only | Meets PCI DSS 1.3.1", totalInstances),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
		})
	}

	return results
}

func (c *ComputeChecks) CheckOSPatchManagement(ctx context.Context) []CheckResult {
	var results []CheckResult

	results = append(results, CheckResult{
		Control:           "CC7.1",
		Name:              "OS Patch Management",
		Status:            "INFO",
		Severity:          "MEDIUM",
		Evidence:          "Manual verification required: Verify OS Config patch management is enabled",
		Remediation:       "Enable OS patch management via OS Config API",
		RemediationDetail: "gcloud compute os-config patch-deployments create monthly-patches --project=PROJECT_ID",
		Priority:          PriorityMedium,
		Timestamp:         time.Now(),
		ScreenshotGuide:   "Compute Engine → VM Manager → Patch management → Screenshot of patch policies",
		ConsoleURL:        "https://console.cloud.google.com/compute/osconfig",
		Frameworks: map[string]string{
			"SOC2":    "CC7.1",
			"PCI-DSS": "6.2",
		},
	})

	return results
}
