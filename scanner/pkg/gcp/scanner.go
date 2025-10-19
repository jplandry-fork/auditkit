package gcp

import (
	"context"
	"fmt"
	"os"

	"cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/storage"
	"github.com/guardian-nexus/auditkit/scanner/pkg/gcp/checks"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/sqladmin/v1"
)

// GCPScanner handles GCP compliance scanning
type GCPScanner struct {
	projectID      string
	storageClient  *storage.Client
	iamClient      *admin.IamClient
	computeService *compute.Service
	sqlService     *sqladmin.Service
	kmsClient      *kms.KeyManagementClient
	loggingClient  *logging.ConfigClient
}

// ScanResult matches the interface expected by main.go
type ScanResult struct {
	Control           string
	Status            string
	Evidence          string
	Remediation       string
	RemediationDetail string
	Severity          string
	ScreenshotGuide   string
	ConsoleURL        string
	Frameworks        map[string]string
}

// NewScanner creates a new GCP scanner instance
// Uses Application Default Credentials (ADC) for authentication
func NewScanner(projectID string) (*GCPScanner, error) {
	ctx := context.Background()

	// If no project ID provided, try to get from environment
	if projectID == "" {
		projectID = os.Getenv("GOOGLE_CLOUD_PROJECT")
		if projectID == "" {
			projectID = os.Getenv("GCP_PROJECT")
		}
		if projectID == "" {
			return nil, fmt.Errorf("no GCP project ID provided. Set GOOGLE_CLOUD_PROJECT or use -profile flag")
		}
	}

	// Initialize Storage client
	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %v", err)
	}

	// Initialize IAM client
	iamClient, err := admin.NewIamClient(ctx)
	if err != nil {
		storageClient.Close()
		return nil, fmt.Errorf("failed to create IAM client: %v", err)
	}

	// Initialize Compute service
	computeService, err := compute.NewService(ctx, option.WithScopes(compute.CloudPlatformScope))
	if err != nil {
		storageClient.Close()
		iamClient.Close()
		return nil, fmt.Errorf("failed to create Compute service: %v", err)
	}

	// Initialize Cloud SQL service
	sqlService, err := sqladmin.NewService(ctx, option.WithScopes(sqladmin.CloudPlatformScope))
	if err != nil {
		storageClient.Close()
		iamClient.Close()
		return nil, fmt.Errorf("failed to create SQL service: %v", err)
	}

	// Initialize KMS client
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		storageClient.Close()
		iamClient.Close()
		return nil, fmt.Errorf("failed to create KMS client: %v", err)
	}

	// Initialize Logging client
	loggingClient, err := logging.NewConfigClient(ctx)
	if err != nil {
		storageClient.Close()
		iamClient.Close()
		kmsClient.Close()
		return nil, fmt.Errorf("failed to create Logging client: %v", err)
	}

	return &GCPScanner{
		projectID:      projectID,
		storageClient:  storageClient,
		iamClient:      iamClient,
		computeService: computeService,
		sqlService:     sqlService,
		kmsClient:      kmsClient,
		loggingClient:  loggingClient,
	}, nil
}

// GetAccountID returns the GCP project ID
func (s *GCPScanner) GetAccountID(ctx context.Context) string {
	return s.projectID
}

// ScanServices runs compliance checks for specified GCP services
func (s *GCPScanner) ScanServices(ctx context.Context, services []string, verbose bool, framework string) ([]interface{}, error) {
	var results []interface{}

	for _, service := range services {
		if verbose {
			fmt.Fprintf(os.Stderr, "Scanning GCP service: %s\n", service)
		}

		var serviceResults []ScanResult
		var err error

		switch service {
		case "storage", "gcs":
			serviceResults, err = s.scanStorage(ctx, verbose, framework)
		case "iam":
			serviceResults, err = s.scanIAM(ctx, verbose, framework)
		case "compute", "gce":
			serviceResults, err = s.scanCompute(ctx, verbose, framework)
		case "network", "vpc":
			serviceResults, err = s.scanNetwork(ctx, verbose, framework)
		case "sql":
			serviceResults, err = s.scanSQL(ctx, verbose, framework)
		case "kms":
			serviceResults, err = s.scanKMS(ctx, verbose, framework)
		case "logging":
			serviceResults, err = s.scanLogging(ctx, verbose, framework)
		default:
			return nil, fmt.Errorf("unknown GCP service: %s", service)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning scanning %s: %v\n", service, err)
		}

		for _, r := range serviceResults {
			results = append(results, r)
		}
	}

	return results, nil
}

// Framework-specific scan methods
func (s *GCPScanner) runSOC2Checks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	// Run all SOC2 check modules
	// TODO: Implement SOC2-specific checks
	
	if verbose {
		fmt.Println("GCP SOC2 scan complete")
	}

	return results
}

func (s *GCPScanner) runPCIChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	// Run all PCI-DSS check modules
	// TODO: Implement PCI-specific checks
	
	if verbose {
		fmt.Println("GCP PCI-DSS scan complete")
	}

	return results
}

func (s *GCPScanner) runCMMCChecks(ctx context.Context, verbose bool) []ScanResult {
	var results []ScanResult

	// CMMC Level 1 checks
	// TODO: Implement CMMC Level 1 checks
	
	if verbose {
		fmt.Println("GCP CMMC Level 1 scan complete")
		fmt.Println("\nUpgrade to AuditKit Pro for CMMC Level 2 (110 additional practices)")
		fmt.Println("Visit: auditkit.io/pro")
	}

	return results
}

// Service-specific scan methods
func (s *GCPScanner) scanStorage(ctx context.Context, verbose bool, framework string) ([]ScanResult, error) {
	storagechecker := checks.NewStorageChecks(s.storageClient, s.projectID)
	checkResults, err := storagechecker.Run(ctx)
	if err != nil {
		return nil, err
	}

	var results []ScanResult
	for _, cr := range checkResults {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Priority.Level,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}

	return results, nil
}

func (s *GCPScanner) scanIAM(ctx context.Context, verbose bool, framework string) ([]ScanResult, error) {
	iamChecker := checks.NewIAMChecks(s.iamClient, s.projectID)
	checkResults, err := iamChecker.Run(ctx)
	if err != nil {
		return nil, err
	}

	var results []ScanResult
	for _, cr := range checkResults {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Priority.Level,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}

	return results, nil
}

func (s *GCPScanner) scanCompute(ctx context.Context, verbose bool, framework string) ([]ScanResult, error) {
	computeChecker := checks.NewComputeChecks(s.computeService, s.projectID)
	checkResults, err := computeChecker.Run(ctx)
	if err != nil {
		return nil, err
	}

	var results []ScanResult
	for _, cr := range checkResults {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Priority.Level,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}

	return results, nil
}

func (s *GCPScanner) scanNetwork(ctx context.Context, verbose bool, framework string) ([]ScanResult, error) {
	networkChecker := checks.NewNetworkChecks(s.computeService, s.projectID)
	checkResults, err := networkChecker.Run(ctx)
	if err != nil {
		return nil, err
	}

	var results []ScanResult
	for _, cr := range checkResults {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Priority.Level,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}

	return results, nil
}

func (s *GCPScanner) scanSQL(ctx context.Context, verbose bool, framework string) ([]ScanResult, error) {
	sqlChecker := checks.NewSQLChecks(s.sqlService, s.projectID)
	checkResults, err := sqlChecker.Run(ctx)
	if err != nil {
		return nil, err
	}

	var results []ScanResult
	for _, cr := range checkResults {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Priority.Level,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}

	return results, nil
}

func (s *GCPScanner) scanKMS(ctx context.Context, verbose bool, framework string) ([]ScanResult, error) {
	kmsChecker := checks.NewKMSChecks(s.kmsClient, s.projectID)
	checkResults, err := kmsChecker.Run(ctx)
	if err != nil {
		return nil, err
	}

	var results []ScanResult
	for _, cr := range checkResults {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Priority.Level,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}

	return results, nil
}

func (s *GCPScanner) scanLogging(ctx context.Context, verbose bool, framework string) ([]ScanResult, error) {
	loggingChecker := checks.NewLoggingChecks(s.loggingClient, s.projectID)
	checkResults, err := loggingChecker.Run(ctx)
	if err != nil {
		return nil, err
	}

	var results []ScanResult
	for _, cr := range checkResults {
		results = append(results, ScanResult{
			Control:           cr.Control,
			Status:            cr.Status,
			Evidence:          cr.Evidence,
			Remediation:       cr.Remediation,
			RemediationDetail: cr.RemediationDetail,
			Severity:          cr.Priority.Level,
			ScreenshotGuide:   cr.ScreenshotGuide,
			ConsoleURL:        cr.ConsoleURL,
			Frameworks:        cr.Frameworks,
		})
	}

	return results, nil
}

// Close cleans up all client connections
func (s *GCPScanner) Close() error {
	if s.storageClient != nil {
		s.storageClient.Close()
	}
	if s.iamClient != nil {
		s.iamClient.Close()
	}
	if s.kmsClient != nil {
		s.kmsClient.Close()
	}
	if s.loggingClient != nil {
		s.loggingClient.Close()
	}
	return nil
}
