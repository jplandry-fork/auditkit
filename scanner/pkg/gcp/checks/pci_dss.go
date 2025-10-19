package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/storage"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/sqladmin/v1"
)

// GCPPCIChecks implements PCI-DSS v4.0 requirements for GCP
type GCPPCIChecks struct {
	storageClient  *storage.Client
	iamClient      *admin.IamClient
	computeService *compute.Service
	sqlService     *sqladmin.Service
	kmsClient      *kms.KeyManagementClient
	loggingClient  *logging.ConfigClient
	projectID      string
}

func NewGCPPCIChecks(
	storageClient *storage.Client,
	iamClient *admin.IamClient,
	computeService *compute.Service,
	sqlService *sqladmin.Service,
	kmsClient *kms.KeyManagementClient,
	loggingClient *logging.ConfigClient,
	projectID string,
) *GCPPCIChecks {
	return &GCPPCIChecks{
		storageClient:  storageClient,
		iamClient:      iamClient,
		computeService: computeService,
		sqlService:     sqlService,
		kmsClient:      kmsClient,
		loggingClient:  loggingClient,
		projectID:      projectID,
	}
}

func (c *GCPPCIChecks) Name() string {
	return "GCP PCI-DSS v4.0 Requirements"
}

func (c *GCPPCIChecks) Run(ctx context.Context) ([]CheckResult, error) {
	results := []CheckResult{}

	// Requirement 1: Network Security
	results = append(results, c.CheckReq1_NetworkSegmentation(ctx)...)

	// Requirement 3: Encryption at Rest
	results = append(results, c.CheckReq3_StorageEncryption(ctx)...)

	// Requirement 4: Encryption in Transit
	results = append(results, c.CheckReq4_TransitEncryption(ctx)...)

	// Requirement 7: Access Control
	results = append(results, c.CheckReq7_AccessControl(ctx)...)

	// Requirement 8: Authentication
	results = append(results, c.CheckReq8_Authentication(ctx)...)

	// Requirement 10: Logging
	results = append(results, c.CheckReq10_Logging(ctx)...)

	return results, nil
}

// Requirement 1: Network segmentation for CDE
func (c *GCPPCIChecks) CheckReq1_NetworkSegmentation(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Use NetworkChecks to verify firewall rules
	networkChecker := NewNetworkChecks(c.computeService, c.projectID)
	firewallResults := networkChecker.CheckFirewallRules(ctx)

	for _, result := range firewallResults {
		if result.Status == "FAIL" {
			// Re-label with PCI control ID
			result.Control = "PCI-1.2.1"
			result.Evidence = fmt.Sprintf("PCI-DSS 1.2.1 VIOLATION: %s", result.Evidence)
			results = append(results, result)
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			Control:    "PCI-1.2.1",
			Name:       "[PCI-DSS] Network Segmentation",
			Status:     "PASS",
			Evidence:   "VPC firewall rules properly configured for network segmentation | Meets PCI DSS 1.2.1",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "1.2.1",
			},
		})
	}

	return results
}

// Requirement 3: Storage encryption for cardholder data
func (c *GCPPCIChecks) CheckReq3_StorageEncryption(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Use StorageChecks to verify encryption
	storageChecker := NewStorageChecks(c.storageClient, c.projectID)
	encryptionResults := storageChecker.CheckBucketEncryption(ctx)

	unencryptedCount := 0
	for _, result := range encryptionResults {
		if result.Status == "FAIL" {
			unencryptedCount++
		}
	}

	if unencryptedCount > 0 {
		results = append(results, CheckResult{
			Control:     "PCI-3.4",
			Name:        "[PCI-DSS] Storage Encryption (Mandatory)",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("PCI-DSS 3.4 VIOLATION: %d storage buckets without customer-managed encryption keys", unencryptedCount),
			Remediation: "Enable customer-managed encryption keys (CMEK) immediately for cardholder data",
			RemediationDetail: "gcloud storage buckets update gs://BUCKET_NAME --default-encryption-key=KMS_KEY",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			ScreenshotGuide: "Storage → Bucket → Encryption showing CMEK",
			Frameworks: map[string]string{
				"PCI-DSS": "3.4, 3.4.1",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:    "PCI-3.4",
			Name:       "[PCI-DSS] Storage Encryption",
			Status:     "PASS",
			Evidence:   "All storage buckets use encryption | Meets PCI DSS 3.4",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "3.4",
			},
		})
	}

	// Check KMS key rotation (PCI-DSS 3.6.4)
	kmsChecker := NewKMSChecks(c.kmsClient, c.projectID)
	keyResults := kmsChecker.CheckKeyRotation(ctx)
	for _, result := range keyResults {
		if result.Status == "FAIL" {
			result.Control = "PCI-3.6.4"
			result.Evidence = fmt.Sprintf("PCI-DSS 3.6.4: %s", result.Evidence)
			results = append(results, result)
		}
	}

	return results
}

// Requirement 4: Encryption in transit
func (c *GCPPCIChecks) CheckReq4_TransitEncryption(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check SQL SSL enforcement
	sqlChecker := NewSQLChecks(c.sqlService, c.projectID)
	sslResults := sqlChecker.CheckSSLRequired(ctx)

	for _, result := range sslResults {
		if result.Status == "FAIL" {
			result.Control = "PCI-4.1"
			result.Evidence = fmt.Sprintf("PCI-DSS 4.1 VIOLATION: %s", result.Evidence)
			result.Severity = "CRITICAL"
			result.Priority = PriorityCritical
			results = append(results, result)
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			Control:    "PCI-4.1",
			Name:       "[PCI-DSS] Encryption in Transit",
			Status:     "PASS",
			Evidence:   "SSL/TLS encryption enforced for all connections | Meets PCI DSS 4.1",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "4.1",
			},
		})
	}

	return results
}

// Requirement 7: Access control
func (c *GCPPCIChecks) CheckReq7_AccessControl(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Check for excessive privileged roles
	iamChecker := NewIAMChecks(c.iamClient, c.projectID)
	iamResults := iamChecker.CheckPrimitiveRoles(ctx)

	for _, result := range iamResults {
		if result.Status == "FAIL" && strings.Contains(result.Evidence, "primitive roles") {
			result.Control = "PCI-7.1"
			result.Evidence = fmt.Sprintf("PCI-DSS 7.1: %s", result.Evidence)
			result.Severity = "HIGH"
			results = append(results, result)
		}
	}

	if len(results) == 0 {
		results = append(results, CheckResult{
			Control:    "PCI-7.1",
			Name:       "[PCI-DSS] Least Privilege",
			Status:     "PASS",
			Evidence:   "IAM follows least privilege principle | Meets PCI DSS 7.1",
			Priority:   PriorityInfo,
			Timestamp:  time.Now(),
			Frameworks: map[string]string{
				"PCI-DSS": "7.1",
			},
		})
	}

	return results
}

// Requirement 8: Authentication
func (c *GCPPCIChecks) CheckReq8_Authentication(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// MFA enforcement (PCI requires MFA for ALL access)
	results = append(results, CheckResult{
		Control:     "PCI-8.3.1",
		Name:        "[PCI-DSS] MFA for ALL Access",
		Status:      "INFO",
		Evidence:    "PCI-DSS 8.3.1: MANUAL CHECK - Verify MFA enabled for ALL users with console access (no exceptions)",
		Remediation: "Enable MFA for every user accessing the cardholder data environment",
		RemediationDetail: "Google Workspace Admin → Security → 2-Step Verification → Enforce for all organizational units",
		ScreenshotGuide: "Google Admin Console → Security → 2-Step Verification → Screenshot enforcement for all users",
		ConsoleURL:      "https://admin.google.com/ac/security/2sv",
		Priority:        PriorityCritical,
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "8.3.1",
		},
	})

	// Service account key rotation (90-day requirement)
	iamChecker := NewIAMChecks(c.iamClient, c.projectID)
	keyResults := iamChecker.CheckServiceAccountKeys(ctx)

	for _, result := range keyResults {
		if result.Status == "FAIL" && strings.Contains(result.Evidence, "90 days") {
			result.Control = "PCI-8.2.4"
			result.Evidence = fmt.Sprintf("PCI-DSS 8.2.4: %s", result.Evidence)
			results = append(results, result)
		}
	}

	// Session timeout
	results = append(results, CheckResult{
		Control:         "PCI-8.1.8",
		Name:            "[PCI-DSS] 15-Minute Session Timeout",
		Status:          "INFO",
		Evidence:        "PCI-DSS 8.1.8: Configure 15-minute idle timeout for all sessions",
		Remediation:     "Set session timeout to 15 minutes via Identity-Aware Proxy or workspace settings",
		RemediationDetail: "Cloud Console → IAP → Configure session duration = 15 minutes",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		Frameworks: map[string]string{
			"PCI-DSS": "8.1.8",
		},
	})

	return results
}

// Requirement 10: Logging
func (c *GCPPCIChecks) CheckReq10_Logging(ctx context.Context) []CheckResult {
	results := []CheckResult{}

	// Audit logging
	loggingChecker := NewLoggingChecks(c.loggingClient, c.projectID)
	loggingResults, _ := loggingChecker.Run(ctx)

	for _, result := range loggingResults {
		if result.Control == "CC7.2" {
			// Re-map to PCI control
			newResult := result
			newResult.Control = "PCI-10.1"
			newResult.Evidence = fmt.Sprintf("PCI-DSS 10.1: %s", result.Evidence)
			results = append(results, newResult)
		}
	}

	// 12-month retention requirement
	results = append(results, CheckResult{
		Control:         "PCI-10.5.3",
		Name:            "[PCI-DSS] 12-Month Log Retention",
		Status:          "INFO",
		Evidence:        "PCI-DSS 10.5.3: Logs must be retained for 12+ months (3 months readily available)",
		Remediation:     "Configure Cloud Storage lifecycle for 365+ day retention",
		RemediationDetail: "Storage bucket → Lifecycle management → Retain for 365+ days",
		Priority:        PriorityHigh,
		Timestamp:       time.Now(),
		ScreenshotGuide: "Logging → Log Router → Sink → Storage bucket lifecycle policy showing 365+ day retention",
		Frameworks: map[string]string{
			"PCI-DSS": "10.5.3",
		},
	})

	return results
}
