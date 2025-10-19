# Compliance Frameworks

AuditKit supports multiple compliance frameworks for automated technical control scanning.

---

## Supported Frameworks

| Framework | Status | Automated Controls | Cloud Providers |
|-----------|--------|-------------------|-----------------|
| **[SOC2 Type II](./soc2.md)** | Production | 64 controls | AWS, Azure, GCP |
| **[PCI-DSS v4.0](./pci-dss.md)** | Production | 30+ controls | AWS, Azure, GCP |
| **[CMMC Level 1](./cmmc.md)** | Production | 17 practices | AWS, Azure, GCP |
| **[CMMC Level 2](./cmmc.md)** | Pro Only | 110 practices | AWS, Azure, GCP |
| **[NIST 800-53 Rev 5](./nist-800-53.md)** | Production | ~150 technical controls | AWS, Azure, GCP |
| **[HIPAA](./hipaa.md)** | Experimental | ~10 controls | AWS, Azure, GCP |

---

## Framework Categories

### Production Ready

Fully tested, comprehensive coverage, used in production environments:

- **SOC2 Type II** - For SaaS companies and startups
- **PCI-DSS v4.0** - For payment card processing
- **CMMC Level 1** - For all DoD contractors
- **NIST 800-53** - For federal contractors

### Pro Only

Requires AuditKit Pro subscription:

- **CMMC Level 2** - For DoD contractors handling CUI

### Experimental

Basic coverage, not recommended for certification:

- **HIPAA** - Technical safeguards only

---

## Quick Comparison

### By Industry

**SaaS/Startups:** SOC2 Type II  
**E-commerce/Payment Processing:** PCI-DSS v4.0  
**DoD Contractors (FCI):** CMMC Level 1  
**DoD Contractors (CUI):** CMMC Level 2 (Pro)  
**Federal Contractors:** NIST 800-53 Rev 5  
**Healthcare:** HIPAA (experimental)

### By Requirements

**Customer demands compliance:** SOC2  
**Processing credit cards:** PCI-DSS  
**DoD contract requires it:** CMMC  
**Federal agency requires it:** NIST 800-53  
**Handling PHI:** HIPAA

### By Timeline

**2-4 weeks:** CMMC Level 1, Basic SOC2 prep  
**2-3 months:** SOC2 Type II certification  
**3-6 months:** CMMC Level 2, PCI-DSS  
**6-12 months:** NIST 800-53, HIPAA

---

## Framework Details

### SOC2 Type II

**Purpose:** Trust Services Criteria for service organizations  
**Certification:** Requires CPA firm audit  
**Cost:** $15,000 - $30,000 for audit  
**Timeline:** 3-6 months preparation + 3-12 month observation period

**[Learn more →](./soc2.md)**

### PCI-DSS v4.0

**Purpose:** Payment Card Industry Data Security Standard  
**Certification:** Requires QSA assessment  
**Cost:** $15,000 - $50,000 for assessment  
**Timeline:** 3-6 months preparation

**[Learn more →](./pci-dss.md)**

### CMMC

**Purpose:** Cybersecurity Maturity Model Certification for DoD  
**Certification:**  
- Level 1: Self-assessment  
- Level 2: C3PAO required ($25,000 - $150,000)

**Timeline:**  
- Level 1: 2-4 weeks  
- Level 2: 3-6 months

**[Learn more →](./cmmc.md)**

### NIST 800-53 Rev 5

**Purpose:** Security controls for federal information systems  
**Certification:** Not a certification (used by FedRAMP, FISMA)  
**Coverage:** ~150 automated technical controls  
**Timeline:** 6-12 months for full implementation

**[Learn more →](./nist-800-53.md)**

### HIPAA

**Purpose:** Healthcare data protection  
**Status:** Experimental - technical safeguards only  
**Note:** Does not cover administrative or physical safeguards

**[Learn more →](./hipaa.md)**

---

## Scanning Frameworks

### Single Framework

```bash
# SOC2
auditkit scan -provider aws -framework soc2

# PCI-DSS
auditkit scan -provider aws -framework pci

# CMMC Level 1
auditkit scan -provider aws -framework cmmc

# CMMC Level 2 (Pro only)
auditkit-pro scan -provider aws -framework cmmc-l2

# NIST 800-53
auditkit scan -provider aws -framework 800-53
```

### All Frameworks

```bash
# Scan all frameworks at once
auditkit scan -provider aws -framework all
```

---

## Framework Crosswalks

AuditKit maps controls across frameworks. For example:

**AWS IAM MFA enforcement** maps to:
- SOC2: CC6.6
- PCI-DSS: Requirement 8.3
- CMMC: IA.2.081
- NIST 800-53: IA-2, IA-2(1)
- HIPAA: 164.312(a)(2)(i)

This means fixing one control improves compliance across multiple frameworks.

---

## Choosing the Right Framework

### Multiple Frameworks Required?

Many organizations need multiple frameworks:

**Common combinations:**
- SOC2 + PCI-DSS (SaaS with payment processing)
- CMMC + NIST 800-53 (DoD + federal work)
- SOC2 + HIPAA (Healthcare SaaS)

**Good news:** AuditKit scans once, reports on all frameworks

### Framework Priorities

**If you need multiple frameworks:**

1. Start with broadest: SOC2 or NIST 800-53
2. Add specific: PCI-DSS for payments, CMMC for DoD
3. Last: HIPAA (most organizational policies)

---

## Getting Help

**Framework-specific questions:**
- [SOC2 FAQ](./soc2.md#faq)
- [PCI-DSS FAQ](./pci-dss.md#faq)
- [CMMC FAQ](./cmmc.md#faq)
- [NIST 800-53 FAQ](./nist-800-53.md#faq)

**General support:**
- [Main FAQ](../faq.md)
- [GitHub Issues](https://github.com/guardian-nexus/auditkit/issues)
- Email: info@auditkit.io

---

## Next Steps

- **[Choose your framework →](#framework-details)**
- **[Run your first scan →](../getting-started.md)**
- **[View provider coverage →](../providers/)**
- **[Compare Free vs Pro →](../pricing.md)**
