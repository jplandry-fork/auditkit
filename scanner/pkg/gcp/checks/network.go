package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"
)

// NetworkChecks handles GCP VPC and firewall security checks
type NetworkChecks struct {
	service   *compute.Service
	projectID string
}

// NewNetworkChecks creates a new network checker
func NewNetworkChecks(service *compute.Service, projectID string) *NetworkChecks {
	return &NetworkChecks{
		service:   service,
		projectID: projectID,
	}
}

// Run executes all network security checks
func (c *NetworkChecks) Run(ctx context.Context) ([]CheckResult, error) {
	var results []CheckResult

	results = append(results, c.CheckFirewallRules(ctx)...)
	results = append(results, c.CheckDefaultNetwork(ctx)...)
	results = append(results, c.CheckPrivateGoogleAccess(ctx)...)

	return results, nil
}

// CheckFirewallRules checks for overly permissive firewall rules
func (c *NetworkChecks) CheckFirewallRules(ctx context.Context) []CheckResult {
	var results []CheckResult

	firewallList, err := c.service.Firewalls.List(c.projectID).Context(ctx).Do()
	if err != nil {
		results = append(results, CheckResult{
			Control:     "CC6.6",
			Name:        "VPC Firewall Rules Check",
			Status:      "FAIL",
			Severity:    "HIGH",
			Evidence:    fmt.Sprintf("Unable to check firewall rules: %v", err),
			Remediation: "Verify Compute Engine API is enabled and credentials have compute.firewalls.list permission",
			Priority:    PriorityHigh,
			Timestamp:   time.Now(),
			Frameworks:  GetFrameworkMappings("VPC_FIREWALL_OPEN"),
		})
		return results
	}

	dangerousPorts := map[string]string{
		"22":   "SSH",
		"3389": "RDP",
		"3306": "MySQL",
		"5432": "PostgreSQL",
		"1433": "MSSQL",
		"27017": "MongoDB",
		"6379": "Redis",
	}

	openToInternet := []string{}
	totalRules := len(firewallList.Items)

	for _, rule := range firewallList.Items {
		// Skip egress rules
		if rule.Direction == "EGRESS" {
			continue
		}

		// Check if rule allows traffic from 0.0.0.0/0
		isOpenToInternet := false
		for _, sourceRange := range rule.SourceRanges {
			if sourceRange == "0.0.0.0/0" {
				isOpenToInternet = true
				break
			}
		}

		if !isOpenToInternet {
			continue
		}

		// Check if rule allows dangerous ports
		for _, allowed := range rule.Allowed {
			if allowed.Ports == nil || len(allowed.Ports) == 0 {
				// No ports specified means all ports
				openToInternet = append(openToInternet, fmt.Sprintf("%s (ALL PORTS - %s)", rule.Name, allowed.IPProtocol))
				continue
			}

			for _, portRange := range allowed.Ports {
				for port, service := range dangerousPorts {
					if strings.Contains(portRange, port) || portRange == port {
						openToInternet = append(openToInternet, fmt.Sprintf("%s (%s on port %s)", rule.Name, service, port))
					}
				}
			}
		}
	}

	if len(openToInternet) > 0 {
		displayRules := openToInternet
		if len(openToInternet) > 3 {
			displayRules = openToInternet[:3]
		}

		results = append(results, CheckResult{
			Control:     "CC6.6",
			Name:        "VPC Firewall Rules - Open to Internet",
			Status:      "FAIL",
			Severity:    "CRITICAL",
			Evidence:    fmt.Sprintf("CRITICAL: %d firewall rules allow dangerous services from 0.0.0.0/0: %s | Violates PCI DSS 1.2.1, 1.3.1", len(openToInternet), strings.Join(displayRules, ", ")),
			Remediation: "Restrict firewall rules to specific IP ranges",
			RemediationDetail: fmt.Sprintf(`# Delete overly permissive rule
gcloud compute firewall-rules delete %s

# Create restricted rule
gcloud compute firewall-rules create restricted-ssh \
  --network=default \
  --allow=tcp:22 \
  --source-ranges=YOUR_OFFICE_IP/32 \
  --description="SSH access from office only"`, strings.Split(openToInternet[0], " ")[0]),
			Priority:        PriorityCritical,
			Timestamp:       time.Now(),
			ScreenshotGuide: fmt.Sprintf("Google Cloud Console → VPC Network → Firewall → Screenshot of %s showing source IP ranges", strings.Split(openToInternet[0], " ")[0]),
			ConsoleURL:      "https://console.cloud.google.com/net-security/firewall-manager/firewall-policies/list",
			Frameworks:      GetFrameworkMappings("VPC_FIREWALL_OPEN"),
		})
	} else if totalRules > 0 {
		results = append(results, CheckResult{
			Control:   "CC6.6",
			Name:      "VPC Firewall Rules - Open to Internet",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("All %d firewall rules have appropriate source restrictions | Meets SOC2 CC6.6, PCI DSS 1.2.1", totalRules),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: GetFrameworkMappings("VPC_FIREWALL_OPEN"),
		})
	} else {
		results = append(results, CheckResult{
			Control:   "CC6.6",
			Name:      "VPC Firewall Rules Check",
			Status:    "INFO",
			Evidence:  "No firewall rules found in project",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: GetFrameworkMappings("VPC_FIREWALL_OPEN"),
		})
	}

	return results
}

// CheckDefaultNetwork checks if default network is still in use
func (c *NetworkChecks) CheckDefaultNetwork(ctx context.Context) []CheckResult {
	var results []CheckResult

	networkList, err := c.service.Networks.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	hasDefaultNetwork := false
	instancesInDefault := 0

	for _, network := range networkList.Items {
		if network.Name == "default" {
			hasDefaultNetwork = true

			// Check how many instances use default network
			zones, err := c.service.Zones.List(c.projectID).Context(ctx).Do()
			if err != nil {
				continue
			}

			for _, zone := range zones.Items {
				instances, err := c.service.Instances.List(c.projectID, zone.Name).Context(ctx).Do()
				if err != nil {
					continue
				}

				for _, instance := range instances.Items {
					for _, networkInterface := range instance.NetworkInterfaces {
						if strings.Contains(networkInterface.Network, "/default") {
							instancesInDefault++
						}
					}
				}
			}
			break
		}
	}

	if hasDefaultNetwork && instancesInDefault > 0 {
		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "Default VPC Network Usage",
			Status:      "FAIL",
			Severity:    "MEDIUM",
			Evidence:    fmt.Sprintf("%d instances using default VPC network. Default networks have overly permissive firewall rules", instancesInDefault),
			Remediation: "Create custom VPC networks with specific firewall rules",
			RemediationDetail: `# Create custom network
gcloud compute networks create custom-vpc \
  --subnet-mode=custom

# Create subnet
gcloud compute networks subnets create custom-subnet \
  --network=custom-vpc \
  --range=10.0.0.0/24 \
  --region=us-central1

# Migrate instances to custom network
# (Requires instance recreation with --network flag)`,
			Priority:        PriorityMedium,
			Timestamp:       time.Now(),
			ScreenshotGuide: "VPC Network → VPC networks → Screenshot showing custom networks instead of 'default'",
			ConsoleURL:      "https://console.cloud.google.com/networking/networks/list",
			Frameworks: map[string]string{
				"SOC2":    "CC6.1",
				"PCI-DSS": "1.2.1",
			},
		})
	} else if !hasDefaultNetwork {
		results = append(results, CheckResult{
			Control:   "CC6.1",
			Name:      "Default VPC Network Usage",
			Status:    "PASS",
			Evidence:  "Default network not in use, custom VPC networks configured | Meets SOC2 CC6.1",
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"SOC2":    "CC6.1",
				"PCI-DSS": "1.2.1",
			},
		})
	}

	return results
}

// CheckPrivateGoogleAccess verifies Private Google Access is enabled
func (c *NetworkChecks) CheckPrivateGoogleAccess(ctx context.Context) []CheckResult {
	var results []CheckResult

	regions, err := c.service.Regions.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return results
	}

	subnetsWithoutPGA := []string{}
	totalSubnets := 0

	for _, region := range regions.Items {
		subnetList, err := c.service.Subnetworks.List(c.projectID, region.Name).Context(ctx).Do()
		if err != nil {
			continue
		}

		for _, subnet := range subnetList.Items {
			totalSubnets++

			if !subnet.PrivateIpGoogleAccess {
				subnetsWithoutPGA = append(subnetsWithoutPGA, subnet.Name)
			}
		}
	}

	if len(subnetsWithoutPGA) > 0 {
		displaySubnets := subnetsWithoutPGA
		if len(subnetsWithoutPGA) > 3 {
			displaySubnets = subnetsWithoutPGA[:3]
		}

		results = append(results, CheckResult{
			Control:     "CC6.1",
			Name:        "Private Google Access",
			Status:      "INFO",
			Severity:    "LOW",
			Evidence:    fmt.Sprintf("%d subnets do not have Private Google Access enabled: %s", len(subnetsWithoutPGA), strings.Join(displaySubnets, ", ")),
			Remediation: "Enable Private Google Access for secure communication with Google APIs",
			RemediationDetail: fmt.Sprintf(`gcloud compute networks subnets update %s \
  --region=REGION \
  --enable-private-ip-google-access`, subnetsWithoutPGA[0]),
			Priority:        PriorityLow,
			Timestamp:       time.Now(),
			ScreenshotGuide: "VPC Network → VPC networks → Subnets → Screenshot showing 'Private Google access: On'",
			ConsoleURL:      "https://console.cloud.google.com/networking/networks/list",
			Frameworks: map[string]string{
				"SOC2": "CC6.1",
			},
		})
	} else if totalSubnets > 0 {
		results = append(results, CheckResult{
			Control:   "CC6.1",
			Name:      "Private Google Access",
			Status:    "PASS",
			Evidence:  fmt.Sprintf("All %d subnets have Private Google Access enabled | Meets SOC2 CC6.1", totalSubnets),
			Priority:  PriorityInfo,
			Timestamp: time.Now(),
			Frameworks: map[string]string{
				"SOC2": "CC6.1",
			},
		})
	}

	return results
}
