# SOC2 Type II Compliance

System and Organization Controls (SOC) 2 framework guide.

---

## Overview

**SOC2 Type II** is a compliance framework for service organizations (SaaS, cloud providers, data centers).

**Who needs it:** SaaS companies selling to enterprise customers  
**Auditor:** CPA firm  
**Cost:** $15,000 - $30,000 for audit  
**Timeline:** 3-6 months prep + 3-12 month observation period  
**AuditKit coverage:** 64 automated technical controls

---

## Trust Services Criteria

SOC2 is based on 5 Trust Services Criteria:

### Security (Required)
Controls to protect system resources against unauthorized access

### Availability (Optional)
System is available for operation and use as committed

### Processing Integrity (Optional)
System processing is complete, valid, accurate, timely, and authorized

### Confidentiality (Optional)
Information designated as confidential is protected

### Privacy (Optional)
Personal information is collected, used, retained, disclosed, and disposed properly

**Most companies:** Security + Availability

---

## Common Criteria (CC) Categories

### CC1 - Control Environment
Integrity and ethical values, board oversight, organizational structure

**What AuditKit checks:** Limited - mostly organizational policies

### CC2 - Communication & Information
Internal and external communication of information

**What AuditKit checks:** Limited - mostly organizational policies

### CC3 - Risk Assessment
Risk identification and analysis processes

**What AuditKit checks:** Limited - mostly organizational policies

### CC5 - Control Activities
Policies and procedures to ensure directives are carried out

**What AuditKit checks:** Limited - mostly organizational policies

### CC6 - Logical & Physical Access Controls
**Most technical controls - AuditKit automates 18 checks**

- CC6.1: Access key rotation, unused credentials
- CC6.2: S3 public access, Storage account security
- CC6.6: MFA enforcement for users
- CC6.7: Root/admin MFA
- CC6.8: Least privilege access

**Example scan output:**
```
[FAIL] CC6.6 - User MFA Enforcement
  Issue: 12 users without MFA enabled
  Fix: aws iam enable-mfa-device --user-name USERNAME
  
[FAIL] CC6.2 - S3 Bucket Public Access
  Issue: 3 buckets allow public access: customer-data, invoices, backups
  Fix: aws s3api put-public-access-block --bucket BUCKET_NAME
```

### CC7 - System Operations
**Most automated controls - AuditKit automates 12 checks**

- CC7.1: CloudTrail/logging enabled
- CC7.2: Log retention and monitoring
- CC7.3: Backup and recovery
- CC7.4: Automated backups configured

### CC8 - Change Management
Configuration management, system components, data

- CC8.1: Encryption at rest (S3, RDS, disks)
- CC8.2: Encryption in transit (SSL/TLS)
- CC8.3: Key rotation

### CC9 - Risk Mitigation
System changes, incident management, business continuity

- CC9.1: High availability configurations
- CC9.2: Disaster recovery testing

---

## What AuditKit Automates

**Technical controls (64 total):**
- Access controls (18)
- Logging and monitoring (12)
- Encryption (6)
- Network security (8)
- Backup and recovery (4)
- Vulnerability management (4)
- Change management (6)
- Other technical (6)

**What AuditKit doesn't cover:**
- Organizational policies
- HR procedures
- Vendor management
- Physical security
- Training programs
- Incident response documentation

---

## SOC2 Type I vs Type II

### Type I
- Point-in-time assessment
- "Do you have the right controls?"
- 2-4 weeks
- $10,000 - $15,000

### Type II
- 3-12 month observation period
- "Do your controls work over time?"
- 3-12 months
- $15,000 - $30,000
- **Required by most enterprise customers**

---

## Running SOC2 Scan

```bash
# AWS
auditkit scan -provider aws -framework soc2

# Azure
auditkit scan -provider azure -framework soc2

# GCP
auditkit scan -provider gcp -framework soc2

# All providers
auditkit scan -provider aws -framework soc2 -output aws-soc2.pdf
auditkit scan -provider azure -framework soc2 -output azure-soc2.pdf
auditkit scan -provider gcp -framework soc2 -output gcp-soc2.pdf

# Generate evidence tracker
auditkit evidence -framework soc2 -format html -output evidence.html
```

---

## Typical Timeline

**Month 1-2: Technical prep**
- Run AuditKit scan
- Fix critical findings
- Enable security services
- Configure logging

**Month 3-4: Organizational prep**
- Write policies and procedures
- Implement training
- Document vendor management
- Create incident response plan

**Month 5-6: Pre-audit**
- Re-scan with AuditKit
- Collect evidence
- Conduct internal audit
- Select CPA firm

**Month 7-18: Observation period**
- 3-12 month period (auditor decides)
- Quarterly AuditKit scans
- Track changes and incidents
- Collect evidence continuously

**Month 19: Audit**
- CPA firm conducts audit
- Reviews controls and evidence
- Issues SOC2 report

---

## Common Failures

Based on SOC2 audits, most common technical failures:

1. No MFA enforcement (CC6.6)
2. Public S3 buckets (CC6.2)
3. CloudTrail not enabled (CC7.1)
4. Weak password policies (CC6.1)
5. No log retention (CC7.2)
6. Encryption not enabled (CC8.1)
7. Access keys not rotated (CC6.1)
8. No backup testing (CC7.3)

**AuditKit catches all of these automatically**

---

## Cost Breakdown

| Item | Cost (Estimate) |
|------|-----------------|
| AuditKit Free | $0 |
| Policy templates | $0 - $500 |
| CPA firm audit | $15,000 - $30,000 |
| Consultant (optional) | $0 - $30,000 |
| **Total** | **$15,000 - $60,500** |

**Compare to:** Traditional consultant-led prep: $50,000 - $100,000

---

## FAQ

**Q: Can I use AuditKit's scan results with my auditor?**  
A: Yes. Generate PDF reports to share with your CPA firm.

**Q: Does SOC2 expire?**  
A: Reports are valid for 12 months. Most companies get annual audits.

**Q: What if I fail the audit?**  
A: Address findings and re-audit. Use AuditKit to verify fixes before re-audit.

**Q: Do I need SOC2 Type II or Type I?**  
A: Enterprise customers typically require Type II.

**Q: How long is the observation period?**  
A: 3-12 months. Auditor decides based on your controls maturity.

---

## Next Steps

- **[Run your first SOC2 scan →](../getting-started.md)**
- **[View provider coverage →](../providers/)**
- **[Compare to other frameworks →](./README.md)**
- **[Generate evidence tracker →](../cli-reference.md#evidence)**
