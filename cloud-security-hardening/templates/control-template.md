# Control Documentation Template

Use this template when documenting new security controls for the framework.

---

## Control ID: [CLOUD]-[CATEGORY]-[NUMBER]

**Examples**:
- AZ-IAM-01
- AWS-STORAGE-05
- GCP-NET-03

**CIS Reference**: [CIS Benchmark Control Number]

**CIS Level**: [1 or 2]

**Priority**: [Critical | High | Medium | Low]

---

### Description

[Clear, concise description of what the control does and why it exists]

**Example**: Multi-factor authentication (MFA) must be enabled for all privileged and administrative accounts in Microsoft Entra ID (formerly Azure AD).

---

### Security Impact

[Explain the security benefit and what threats this control mitigates]

**Example**: MFA prevents account takeover from compromised credentials. Privileged accounts have elevated permissions that could compromise the entire environment if stolen.

---

### Threat Scenarios

[List specific attack scenarios this control prevents]

1. **Scenario 1**: [Description]
2. **Scenario 2**: [Description]

---

### Manual Verification

**Step-by-step instructions to verify manually via console**:

1. [Step 1]
2. [Step 2]
3. [Step 3]

**Expected Result**: [What you should see if compliant]

---

### Automated Verification

**Script**: `scripts/[cloud]/check-[category].sh` or `check-[category].ps1`

**Function/Section**: [Name of function that checks this control]

**Expected Output**:
```
[PASS] Control description - CIS X.X
```

---

### Remediation Steps

#### Prerequisites
- [Required permissions]
- [Required tools/modules]
- [Any dependencies]

#### Via Console

1. [Step 1]
2. [Step 2]
3. [Step 3]

#### Via CLI

**Azure**:
```powershell
# Remediation command
[PowerShell code here]
```

**AWS**:
```bash
# Remediation command
[Bash code here]
```

#### Via Infrastructure-as-Code

**Terraform**:
```hcl
# Terraform configuration
resource "..." "..." {
  # Configuration
}
```

**ARM Template** (Azure):
```json
{
  "type": "...",
  "properties": {
    "...": "..."
  }
}
```

**CloudFormation** (AWS):
```yaml
Resources:
  ResourceName:
    Type: AWS::...
    Properties:
      # Configuration
```

---

### Verification After Remediation

1. [Step to verify fix worked]
2. [Step to confirm no regressions]
3. Re-run automated check: `./check-[category].sh`

**Expected Result**: `[PASS] [Control description]`

---

### Risk if Not Implemented

**Severity**: [Critical | High | Medium | Low]

**Potential Impact**:
- [Impact 1]
- [Impact 2]
- [Impact 3]

**Attack Scenario**:
[Detailed description of how an attacker could exploit this gap]

**Business Impact**:
- [Data breach]
- [Service disruption]
- [Compliance violation]
- [Financial loss]

---

### Compliance Mappings

| Framework | Control ID | Description |
|-----------|------------|-------------|
| CIS Benchmark | [X.X] | [Description] |
| NIST CSF | [ID] | [Description] |
| ISO 27001 | [A.X.X] | [Description] |
| PCI DSS | [X.X.X] | [Description] |
| HIPAA | [§164.XXX] | [Description] |

---

### Related Controls

- **[CONTROL-ID-1]**: [How it relates]
- **[CONTROL-ID-2]**: [How it relates]

---

### Dependencies

**Required for this control**:
- [Dependency 1]
- [Dependency 2]

**This control is required for**:
- [Dependent control 1]
- [Dependent control 2]

---

### Cost Implications

**Azure**:
- [Cost impact description]
- Estimated cost: [$X/month]

**AWS**:
- [Cost impact description]
- Estimated cost: [$X/month]

---

### Exceptions and Waivers

**Common exception scenarios**:
1. [Scenario where exception might be granted]
2. [Scenario where exception might be granted]

**Exception approval process**:
1. [Step 1]
2. [Step 2]
3. Document in exception log

---

### References

- [CIS Benchmark PDF link or page number]
- [Cloud provider documentation]
- [Relevant security advisories]
- [Best practice guides]

---

### Changelog

| Date | Version | Author | Changes |
|------|---------|--------|---------|
| YYYY-MM-DD | 1.0.0 | [Name] | Initial version |

---

**Template Version**: 1.0.0
**Last Updated**: December 2025
