package checks

import (
	"context"
	"time"
        "fmt"
)

// CheckResult represents the result of a single compliance check
type CheckResult struct {
	Control           string            `json:"control"`
	Name              string            `json:"name"`
	Status            string            `json:"status"` // PASS, FAIL, INFO
	Evidence          string            `json:"evidence"`
	Remediation       string            `json:"remediation,omitempty"`
	RemediationDetail string            `json:"remediation_detail,omitempty"`
	Severity          string            `json:"severity,omitempty"`
	Priority          Priority          `json:"priority"`
	ScreenshotGuide   string            `json:"screenshot_guide,omitempty"`
	ConsoleURL        string            `json:"console_url,omitempty"`
	Timestamp         time.Time         `json:"timestamp"`
	Frameworks        map[string]string `json:"frameworks,omitempty"`
}

// Priority levels for compliance findings
type Priority struct {
	Level     string `json:"level"`
	Impact    string `json:"impact"`
	TimeToFix string `json:"time_to_fix"`
	WillFail  bool   `json:"will_fail"`
}

// Priority definitions matching AWS/Azure
var (
	PriorityCritical = Priority{
		Level:     "CRITICAL",
		Impact:    "AUDIT BLOCKER - Fix immediately or fail audit",
		TimeToFix: "Fix RIGHT NOW",
		WillFail:  true,
	}

	PriorityHigh = Priority{
		Level:     "HIGH",
		Impact:    "Major finding - Auditor will flag this",
		TimeToFix: "Fix this week",
		WillFail:  false,
	}

	PriorityMedium = Priority{
		Level:     "MEDIUM",
		Impact:    "Should fix - Makes audit smoother",
		TimeToFix: "Fix before audit",
		WillFail:  false,
	}

	PriorityLow = Priority{
		Level:     "LOW",
		Impact:    "Nice to have - Strengthens posture",
		TimeToFix: "When convenient",
		WillFail:  false,
	}

	PriorityInfo = Priority{
		Level:     "INFO",
		Impact:    "Good job, this passes",
		TimeToFix: "Already compliant",
		WillFail:  false,
	}
)

// Framework constants
const (
	FrameworkSOC2  = "SOC2"
	FrameworkPCI   = "PCI-DSS"
	FrameworkCMMC  = "CMMC"
	FrameworkNIST  = "NIST-800-53"
	FrameworkHIPAA = "HIPAA"
)

// Check interface that all GCP check implementations must satisfy
type Check interface {
	Run(ctx context.Context) ([]CheckResult, error)
}

// Framework mappings for GCP controls
var FrameworkMappings = map[string]map[string]string{
	"GCS_BUCKET_PUBLIC": {
		FrameworkSOC2:  "CC6.1, CC6.6",
		FrameworkPCI:   "1.2.1, 1.3.1",
		FrameworkCMMC:  "AC.L1-3.1.1",
		FrameworkNIST:  "AC-3, AC-6",
	},
	"GCS_BUCKET_ENCRYPTION": {
		FrameworkSOC2:  "CC6.1, CC6.7",
		FrameworkPCI:   "3.4, 3.5.1",
		FrameworkCMMC:  "SC.L2-3.13.11",
		FrameworkNIST:  "SC-13, SC-28",
	},
	"IAM_MFA_ENABLED": {
		FrameworkSOC2:  "CC6.1, CC6.2",
		FrameworkPCI:   "8.3.1",
		FrameworkCMMC:  "IA.L2-3.5.3",
		FrameworkNIST:  "IA-2(1)",
	},
	"IAM_SERVICE_ACCOUNT_KEYS": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "8.2.4",
		FrameworkCMMC:  "IA.L2-3.5.7",
		FrameworkNIST:  "IA-5",
	},
	"KMS_ROTATION_ENABLED": {
		FrameworkSOC2:  "CC6.1",
		FrameworkPCI:   "3.6.4",
		FrameworkCMMC:  "SC.L2-3.13.11",
		FrameworkNIST:  "SC-12",
	},
	"LOGGING_ENABLED": {
		FrameworkSOC2:  "CC7.2",
		FrameworkPCI:   "10.2.1, 10.3.1",
		FrameworkCMMC:  "AU.L2-3.3.1",
		FrameworkNIST:  "AU-2, AU-12",
	},
	"VPC_FIREWALL_OPEN": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "1.2.1, 1.3.1",
		FrameworkCMMC:  "SC.L1-3.13.1",
		FrameworkNIST:  "SC-7",
	},
	"SQL_BACKUP_ENABLED": {
		FrameworkSOC2:  "A1.2",
		FrameworkPCI:   "9.5.1",
		FrameworkCMMC:  "SC.L2-3.13.6",
		FrameworkNIST:  "CP-9",
	},
	"SQL_PUBLIC_IP": {
		FrameworkSOC2:  "CC6.6",
		FrameworkPCI:   "1.3.1",
		FrameworkCMMC:  "SC.L1-3.13.1",
		FrameworkNIST:  "SC-7",
	},
}

// Helper function to get framework mappings for a control
func GetFrameworkMappings(controlType string) map[string]string {
	if mappings, exists := FrameworkMappings[controlType]; exists {
		return mappings
	}
	return make(map[string]string)
}

func FormatFrameworkRequirements(frameworks map[string]string) string {
	if len(frameworks) == 0 {
		return ""
	}

	result := " | Requirements: "
	for fw, requirement := range frameworks {
		result += fmt.Sprintf("%s %s, ", fw, requirement)
	}
	// Remove trailing comma and space
	return result[:len(result)-2]
}
