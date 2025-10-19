package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// IAMChecks handles GCP IAM security checks
type IAMChecks struct {
	client    *admin.IamClient
	projectID string
}

// NewIAMChecks creates a new IAM checker
func NewIAMChecks(client *admin.IamClient, projectID string) *IAMChecks {
	return &IAMChecks{
		client:    client,
		projectID: projectID,
	}
}

// Run executes all IAM security checks
func (c *IAMChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	results = append(results, c.CheckServiceAccountKeys(ctx)...)
	results = append(results, c.CheckUserMFA(ctx)...)
	results = append(results, c.CheckPrimitiveRoles(ctx)...)
	results = append(results, c.CheckServiceAccountPermissions(ctx)...)

	return results, nil
}

// CheckServiceAccountKeys checks for old or excessive service account keys
func (c *IAMChecks) CheckServiceAccountKeys(ctx context.Context) []CheckResult {
	var results []CheckResult

	// List service accounts
	req := &adminpb.ListServiceAccountsRequest{
		Name: fmt.Sprintf("projects/%s", c.projectID),
	}

	it := c.client.ListServiceAccounts(ctx, req)
	totalSAs := 0
	keysOlderThan90Days := []string{}
	tooManyKeys := []string{}

	for {
		sa, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			results = append(results, CheckResult{
				Control:     "CC6.1",
				Name:        "Service Account Key Rotation",
				Status:      "FAIL",
				Severity:    "HIGH",
				Evidence:    fmt.Sprintf("Unable to check service account keys: %v", err),
				Remediation: "Verify IAM API is enabled and credentials have iam.serviceAccounts.list permission",
				Priority:    PriorityHigh,
				Timestamp:   time.Now(),
				Frameworks:  GetFrameworkMappings("IAM_SERVICE_ACCOUNT_KEYS"),
			})
			break
		}

		totalSAs++

		// List keys for this service account
		keyReq := &adminpb.ListServiceAccountKeysRequest{
			Name: sa.Name,
		}

		keyResp, err := c.client.ListServiceAccountKeys(ctx, keyReq)
		if err != nil {
			continue
		}

		keyCount := 0
		for _, key := range keyResp.Keys {
			keyCount++

			// Check key age
			if key.ValidAfterTime != nil {
				keyAge := time.Since(key.ValidAfterTime.AsTime())
				if keyAge > 90*24*time.Hour {
					keysOlderThan90Days = append(keysOlderThan90Days, 
						fmt.Sprintf("%s (%d days old)", sa.Email, int(keyAge.Hours()/24)))
				}
			}
		}

		// Check if too many keys (PCI requires key rotation, having many keys suggests no rotation)
		if keyCount > 2 {
			tooManyKeys = append(tooManyKeys, fmt.Sprintf("%s (%d keys)", sa.Email, keyCount))
		}
	}

	// Report old keys
	if len(keysOlderThan90Days) > 0 {
		displayKeys := keysOlderThan90Days
		if len(keysOlderThan90Days) > 3 {
			displayKeys = keysOlderThan90Days[:3]
		}

		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "Service Account Key Age",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("PCI-DSS 8.2.4: %d service account keys older than 90 days: %s", len(keysOlderThan90Days), strings.Join(displayKeys, ", ")),
			Remediation: "Rotate service account keys every 90 days",
			RemediationDetail: `# Create new key
gcloud iam service-accounts keys create new-key.json \
  --iam-account=SERVICE_ACCOUNT_EMAIL

# Delete old key
gcloud iam service-accounts keys delete KEY_ID \
  --iam-account=SERVICE_ACCOUNT_EMAIL`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Google Cloud Console → IAM & Admin → Service Accounts → Select account → Keys tab → Screenshot key creation dates",
			ConsoleURL:      "https://console.cloud.google.com/iam-admin/serviceaccounts",
			Frameworks:      GetFrameworkMappings("IAM_SERVICE_ACCOUNT_KEYS"),
		})
	}

	// Report excessive keys
	if len(tooManyKeys) > 0 {
		displayAccounts := tooManyKeys
		if len(tooManyKeys) > 3 {
			displayAccounts = tooManyKeys[:3]
		}

		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "Service Account Key Count",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d service accounts have excessive keys (>2): %s", len(tooManyKeys), strings.Join(displayAccounts, ", ")),
			Remediation: "Limit to 2 keys per service account and rotate regularly",
			RemediationDetail: `gcloud iam service-accounts keys delete OLD_KEY_ID \
  --iam-account=SERVICE_ACCOUNT_EMAIL`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM → Service Accounts → Keys tab → Show only 1-2 active keys",
			ConsoleURL:      "https://console.cloud.google.com/iam-admin/serviceaccounts",
			Frameworks:      GetFrameworkMappings("IAM_SERVICE_ACCOUNT_KEYS"),
		})
	}

	if len(keysOlderThan90Days) == 0 && len(tooManyKeys) == 0 && totalSAs > 0 {
		results = append(results, CheckResult{
			Control:   "CC6.1",
			Name:      "Service Account Key Rotation",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("All %d service accounts have properly rotated keys (< 90 days) | Meets PCI DSS 8.2.4", totalSAs),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: GetFrameworkMappings("IAM_SERVICE_ACCOUNT_KEYS"),
		})
	}

	return results
}

// CheckUserMFA verifies 2FA is enforced for users
func (c *IAMChecks) CheckUserMFA(ctx context.Context) []CheckResult {
	var results []CheckResult

	// Get project IAM policy to check for user accounts
	crmService, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformScope))
	if err != nil {
		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "User MFA Enforcement",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("Unable to check MFA status: %v", err),
			Remediation: "Verify Cloud Resource Manager API is enabled",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("IAM_MFA_ENABLED"),
		})
		return results
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "User MFA Enforcement",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("Unable to retrieve IAM policy: %v", err),
			Remediation: "Verify resourcemanager.projects.getIamPolicy permission",
			Priority:    PriorityCritical,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("IAM_MFA_ENABLED"),
		})
		return results
	}

	// Check for user accounts (not service accounts)
	userAccounts := []string{}
	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if strings.HasPrefix(member, "user:") {
				email := strings.TrimPrefix(member, "user:")
				if !contains(userAccounts, email) {
					userAccounts = append(userAccounts, email)
				}
			}
		}
	}

	if len(userAccounts) > 0 {
		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "User MFA Enforcement",
			Status:      "INFO",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("Manual verification required: %d user accounts found. Verify 2-Step Verification is enforced via Workspace admin console", len(userAccounts)),
			Remediation: "Enforce 2-Step Verification in Google Workspace Admin Console",
			RemediationDetail: `1. Go to admin.google.com
2. Security → 2-Step Verification
3. Enable "Allow users to turn on 2-Step Verification"
4. Click "Start enforcing immediately" for all organizational units
5. For PCI: Document MFA enforcement policy`,
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: "Google Admin Console → Security → 2-Step Verification → Screenshot enforcement status for all OUs",
			ConsoleURL:      "https://admin.google.com/ac/security/2sv",
			Frameworks:      GetFrameworkMappings("IAM_MFA_ENABLED"),
		})
	} else {
		results = append(results, CheckResult{
			Control:   "CC6.1",
			Name:      "User MFA Enforcement",
			Status:    "PASS",
			Evidence:  "No user accounts found in project IAM (only service accounts) | Meets SOC2 CC6.1, PCI DSS 8.3.1",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: GetFrameworkMappings("IAM_MFA_ENABLED"),
		})
	}

	return results
}

// CheckPrimitiveRoles checks for overly permissive primitive roles
func (c *IAMChecks) CheckPrimitiveRoles(ctx context.Context) []CheckResult {
	var results []CheckResult

	crmService, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformScope))
	if err != nil {
		return results
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return results
	}

	primitiveRoles := []string{"roles/owner", "roles/editor", "roles/viewer"}
	problematicBindings := []string{}

	for _, binding := range policy.Bindings {
		for _, primitiveRole := range primitiveRoles {
			if binding.Role == primitiveRole {
				for _, member := range binding.Members {
					// Flag if non-service accounts have primitive roles
					if !strings.HasPrefix(member, "serviceAccount:") {
						problematicBindings = append(problematicBindings, 
							fmt.Sprintf("%s has %s", member, binding.Role))
					}
				}
			}
		}
	}

	if len(problematicBindings) > 0 {
		displayBindings := problematicBindings
		if len(problematicBindings) > 3 {
			displayBindings = problematicBindings[:3]
		}

		results = append(results, CheckResult{
			Control:     "CC6.3",
			Name:        "Primitive Role Usage",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("SOC2 CC6.3: %d accounts using primitive roles (Owner/Editor/Viewer): %s", len(problematicBindings), strings.Join(displayBindings, ", ")),
			Remediation: "Replace primitive roles with predefined or custom roles following least privilege",
			RemediationDetail: `# Remove primitive role
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=user:EMAIL \
  --role=roles/editor

# Add specific predefined role
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=user:EMAIL \
  --role=roles/compute.admin`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM & Admin → IAM → Screenshot showing specific roles instead of Owner/Editor/Viewer",
			ConsoleURL:      fmt.Sprintf("https://console.cloud.google.com/iam-admin/iam?project=%s", c.projectID),
			Frameworks: map[string]string{
				"SOC2":    "CC6.3",
				"PCI-DSS": "7.1.2",
				"CMMC":    "AC.L2-3.1.5",
				"NIST":    "AC-6",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "CC6.3",
			Name:      "Primitive Role Usage",
			Status:    "PASS",
			Evidence:  "No primitive roles assigned to user accounts | Meets SOC2 CC6.3, PCI DSS 7.1.2",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"SOC2":    "CC6.3",
				"PCI-DSS": "7.1.2",
				"CMMC":    "AC.L2-3.1.5",
			},
		})
	}

	return results
}

// CheckServiceAccountPermissions checks for overly permissive service accounts
func (c *IAMChecks) CheckServiceAccountPermissions(ctx context.Context) []CheckResult {
	var results []CheckResult

	crmService, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformScope))
	if err != nil {
		return results
	}

	policy, err := crmService.Projects.GetIamPolicy(c.projectID, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return results
	}

	dangerousRoles := []string{"roles/owner", "roles/editor"}
	serviceAccountsWithDangerousRoles := []string{}

	for _, binding := range policy.Bindings {
		for _, dangerousRole := range dangerousRoles {
			if binding.Role == dangerousRole {
				for _, member := range binding.Members {
					if strings.HasPrefix(member, "serviceAccount:") {
						email := strings.TrimPrefix(member, "serviceAccount:")
						serviceAccountsWithDangerousRoles = append(serviceAccountsWithDangerousRoles,
							fmt.Sprintf("%s (%s)", email, binding.Role))
					}
				}
			}
		}
	}

	if len(serviceAccountsWithDangerousRoles) > 0 {
		displayAccounts := serviceAccountsWithDangerousRoles
		if len(serviceAccountsWithDangerousRoles) > 3 {
			displayAccounts = serviceAccountsWithDangerousRoles[:3]
		}

		results = append(results, CheckResult{
			Control:     "CC6.3",
			Name:        "Service Account Permissions",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("%d service accounts have overly broad permissions: %s", len(serviceAccountsWithDangerousRoles), strings.Join(displayAccounts, ", ")),
			Remediation: "Apply least privilege principle to service accounts",
			RemediationDetail: `gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:SA_EMAIL \
  --role=roles/editor

gcloud projects add-iam-policy-binding PROJECT_ID \
  --member=serviceAccount:SA_EMAIL \
  --role=roles/SPECIFIC_ROLE`,
			Priority:        PriorityHigh,
			Timestamp:       time.Now(),
			ScreenshotGuide: "IAM & Admin → Service Accounts → Permissions tab → Screenshot showing specific predefined roles",
			ConsoleURL:      "https://console.cloud.google.com/iam-admin/serviceaccounts",
			Frameworks: map[string]string{
				"SOC2":    "CC6.3",
				"PCI-DSS": "7.1.2",
			},
		})
	} else {
		results = append(results, CheckResult{
			Control:   "CC6.3",
			Name:      "Service Account Permissions",
			Status:    "PASS",
			Evidence:  "Service accounts follow least privilege principle | Meets SOC2 CC6.3",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"SOC2":    "CC6.3",
				"PCI-DSS": "7.1.2",
			},
		})
	}

	return results
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
