# AuditKit - Open-Source Compliance Scanner

**Scan AWS, Azure, GCP, and M365 for SOC2, PCI-DSS, HIPAA, CMMC, and NIST 800-53 compliance. Get audit-ready reports in minutes.**

[![GitHub stars](https://img.shields.io/github/stars/guardian-nexus/auditkit)](https://github.com/guardian-nexus/auditkit/stargazers)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-v0.7.0-green.svg)](https://github.com/guardian-nexus/auditkit/releases)
[![Newsletter](https://img.shields.io/badge/Newsletter-Subscribe-orange)](https://auditkit.substack.com)

---

## Quick Start

```bash
# Install
git clone https://github.com/guardian-nexus/auditkit
cd auditkit/scanner
go build ./cmd/auditkit

# Scan your cloud
./auditkit scan -provider aws -framework soc2      # AWS
./auditkit scan -provider azure -framework soc2    # Azure
./auditkit scan -provider gcp -framework soc2      # GCP

# Generate report
./auditkit scan -provider aws -framework soc2 -format pdf -output report.pdf
```

**Setup:** [AWS](./docs/setup/aws.md) • [Azure](./docs/setup/azure.md) • [GCP](./docs/setup/gcp.md) • [M365](./docs/setup/m365.md)

---

## What It Does

- Scans AWS, Azure, GCP, M365 for compliance gaps
- Checks ~150 automated controls per framework
- Generates audit-ready PDF/HTML reports
- Shows exact CLI commands to fix issues
- Doesn't replace your auditor or scan for vulnerabilities

**[View Examples →](./docs/examples/)** • **[Read Documentation →](./docs/)**

---

## Supported Frameworks

| Framework | AWS | Azure | GCP | Status |
|-----------|-----|-------|-----|--------|
| SOC2 Type II | 64 | 64 | 64 | Production |
| PCI-DSS v4.0 | 30+ | 30+ | 30+ | Production |
| CMMC Level 1 | 17 | 17 | 17 | Production |
| CMMC Level 2 | 110 | 110 | 110 | [Pro](https://auditkit.io/pro) |
| NIST 800-53 Rev 5 | ~150 | ~150 | ~150 | Production |
| HIPAA | ~10 | ~10 | ~10 | Experimental |

**[Framework Details →](./docs/frameworks/)**

---

## Free vs Pro

| Feature | Free | Pro ($297/mo) |
|---------|------|---------------|
| **Cloud Providers** | AWS, Azure, GCP, M365 | Same |
| **GCP Core** | 20 checks | Same |
| **GCP Advanced** | - | GKE + Vertex AI (20 checks) |
| **Multi-Account** | - | AWS Orgs, Azure Mgmt, GCP Folders |
| **CMMC Level 2** | - | 110 practices (CUI) |
| **Support** | Community | Priority + 14-day trial |

**[Compare Features →](./docs/pricing.md)** • **[Start Pro Trial →](https://auditkit.io/pro)**

---

## Why Use AuditKit?

**For Startups:** Free SOC2 prep without $50K consultants  
**For DoD Contractors:** CMMC Level 1 (Free) or Level 2 (Pro) compliance  
**For Multi-Cloud:** Single tool for AWS + Azure + GCP  

---

## Installation

**Pre-built binaries:** [Releases](https://github.com/guardian-nexus/auditkit/releases)

**From source:**
```bash
git clone https://github.com/guardian-nexus/auditkit
cd auditkit/scanner
go build ./cmd/auditkit
```

**Requirements:** Go 1.19+, cloud credentials configured (AWS CLI, Azure CLI, gcloud CLI)

**[Full Installation Guide →](./docs/installation.md)**

---

## Documentation

- **[Getting Started](./docs/getting-started.md)** - First scan in 5 minutes
- **[Cloud Setup](./docs/setup/)** - AWS, Azure, GCP, M365 authentication
- **[Frameworks](./docs/frameworks/)** - SOC2, PCI-DSS, CMMC, NIST 800-53
- **[Examples](./docs/examples/)** - Sample reports and scan outputs
- **[CLI Reference](./docs/cli-reference.md)** - All commands and flags
- **[FAQ](./docs/faq.md)** - Common questions

---

## What's New in v0.7.0

- **GCP Support:** 20 automated checks across Cloud Storage, IAM, Compute, VPC, SQL, KMS, Logging
- **NIST 800-53 Rev 5:** ~150 technical controls mapped from existing frameworks
- **Multi-Cloud:** Scan AWS, Azure, and GCP with the same tool

**[Release Notes →](./CHANGELOG.md)**

---

## Contributing

We need help with:
- Additional framework mappings (FedRAMP, GDPR)
- Prowler integration for complete 800-53 coverage
- Kubernetes compliance scanning
- Automated evidence collection

**[Contributing Guide →](./CONTRIBUTING.md)**

---

## Support

- **Issues:** [GitHub Issues](https://github.com/guardian-nexus/auditkit/issues)
- **Security:** [SECURITY.md](./SECURITY.md)
- **Newsletter:** [auditkit.substack.com](https://auditkit.substack.com)
- **Pro Support:** info@auditkit.io

---

## License

Apache 2.0 - Use freely, even commercially.

## About Guardian Nexus

AuditKit is built by current defense sector professionals with deep expertise 
in compliance and cloud security. Our focus is shipping working software 
instead of enterprise overhead.

- Active security clearance holder
- 15+ years in defense sector compliance
- Former defense contractor (understand CMMC firsthand)
- Monthly releases, responsive support

Questions? Email: hello@auditkit.io
