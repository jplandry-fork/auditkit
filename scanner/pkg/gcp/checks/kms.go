package checks

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/iterator"
)

type KMSChecks struct {
	client    *kms.KeyManagementClient
	projectID string
}

func NewKMSChecks(client *kms.KeyManagementClient, projectID string) *KMSChecks {
	return &KMSChecks{client: client, projectID: projectID}
}

func (c *KMSChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult
	results = append(results, c.CheckKeyRotation(ctx)...)
	return results, nil
}

func (c *KMSChecks) CheckKeyRotation(ctx context.Context) []CheckResult {
	var results []CheckResult

	req := &kmspb.ListKeyRingsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/global", c.projectID),
	}

	it := c.client.ListKeyRings(ctx, req)
	keysWithoutRotation := []string{}
	totalKeys := 0

	for {
		keyRing, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			break
		}

		// List crypto keys in this key ring
		keyReq := &kmspb.ListCryptoKeysRequest{
			Parent: keyRing.Name,
		}

		keyIt := c.client.ListCryptoKeys(ctx, keyReq)
		for {
			key, err := keyIt.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				break
			}

			totalKeys++
			// Check if automatic rotation is configured
			// GCP KMS uses NextRotationTime to indicate rotation is enabled
			if key.NextRotationTime == nil {
				keysWithoutRotation = append(keysWithoutRotation, key.Name)
			}
		}
	}

	if len(keysWithoutRotation) > 0 {
		results = append(results, CheckResult{
			Control:           "CC6.1",
			Name:              "KMS Key Rotation",
			Status:            "FAIL",
			Severity:          "MEDIUM",
			Evidence:          fmt.Sprintf("%d KMS keys without automatic rotation configured | Violates PCI DSS 3.6.4", len(keysWithoutRotation)),
			Remediation:       "Enable automatic key rotation (90 days recommended)",
			RemediationDetail: "gcloud kms keys update KEY_NAME --location=LOCATION --keyring=KEYRING --rotation-period=90d --next-rotation-time=2025-01-01T00:00:00Z",
			Priority:          PriorityMedium,
			Timestamp:         time.Now(),
			ScreenshotGuide:   "Security → Key Management → Key details → Rotation period",
			ConsoleURL:        "https://console.cloud.google.com/security/kms",
			Frameworks:        GetFrameworkMappings("KMS_ROTATION_ENABLED"),
		})
	} else if totalKeys > 0 {
		results = append(results, CheckResult{
			Control:   "CC6.1",
			Name:      "KMS Key Rotation",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("All %d KMS keys have automatic rotation | Meets PCI DSS 3.6.4", totalKeys),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: GetFrameworkMappings("KMS_ROTATION_ENABLED"),
		})
	}

	return results
}
