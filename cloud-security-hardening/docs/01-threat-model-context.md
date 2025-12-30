# Threat Model and Security Context

## Overview

This document provides the threat modeling context that informs the Cloud Security Hardening Framework. Understanding the threat landscape is essential for prioritizing security controls and understanding their value.

## Cloud Security Threat Landscape

### Primary Threat Actors

#### 1. External Attackers
**Motivation**: Financial gain, data theft, ransomware, cryptocurrency mining

**Common Attack Vectors**:
- Exploitation of publicly exposed resources
- Credential compromise through phishing
- Exploitation of unpatched vulnerabilities
- API abuse and enumeration
- Supply chain attacks

#### 2. Malicious Insiders
**Motivation**: Financial gain, revenge, espionage

**Common Attack Vectors**:
- Abuse of legitimate access privileges
- Data exfiltration
- Resource manipulation
- Privilege escalation
- Credential theft

#### 3. Compromised Accounts
**Motivation**: Varies based on attacker controlling the account

**Common Attack Vectors**:
- Stolen credentials from third-party breaches
- Weak or default passwords
- Lack of multi-factor authentication
- Session hijacking
- Token theft

#### 4. Automated Bots and Scanners
**Motivation**: Opportunistic exploitation, reconnaissance

**Common Attack Vectors**:
- Automated scanning for misconfigurations
- Brute force attacks
- Exploitation of known vulnerabilities
- Resource enumeration
- Credential stuffing

### Cloud-Specific Attack Patterns

#### Misconfiguration Exploitation

**Attack Scenario**: Attacker discovers publicly accessible cloud storage containing sensitive data

**Example**: S3 bucket or Azure Blob Storage with public read access
```
Attacker Actions:
1. Enumerate common bucket/container names
2. Discover publicly accessible storage
3. Exfiltrate sensitive data
4. Potentially modify or delete data
```

**Controls Addressed**:
- AWS-STORAGE-01: S3 Block Public Access
- AZ-STORAGE-01: Disable Storage Account Public Access
- AWS-STORAGE-02: S3 Bucket Policies
- AZ-STORAGE-02: Shared Access Signature Restrictions

#### Privilege Escalation

**Attack Scenario**: Attacker gains initial access with limited privileges and escalates to administrative access

**Example**: IAM role with overly permissive policies
```
Attacker Actions:
1. Compromise low-privilege account
2. Enumerate IAM permissions
3. Discover overly permissive policies (e.g., iam:* or *)
4. Create new administrative user
5. Assume full control of account
```

**Controls Addressed**:
- AWS-IAM-05: IAM Policy Least Privilege
- AZ-IAM-04: Custom Role Permissions Review
- AWS-IAM-06: IAM User Permissions
- AZ-IAM-05: RBAC Assignment Review

#### Persistence Through Backdoors

**Attack Scenario**: Attacker establishes persistence mechanisms to maintain access

**Example**: Creation of unauthorized IAM users, access keys, or service principals
```
Attacker Actions:
1. Gain initial access
2. Create new IAM user or service principal
3. Generate long-term credentials
4. Maintain access even after initial compromise is detected
```

**Controls Addressed**:
- AWS-IAM-02: Root Account Access Keys
- AZ-IAM-06: Service Principal Credential Management
- AWS-LOG-01: CloudTrail Enabled (for detection)
- AZ-LOG-01: Activity Log Retention

#### Lateral Movement

**Attack Scenario**: Attacker moves from compromised resource to other resources in the environment

**Example**: Network misconfiguration allowing unrestricted internal access
```
Attacker Actions:
1. Compromise single EC2 instance or VM
2. Leverage overly permissive Security Groups or NSGs
3. Access other resources on the same network
4. Escalate access to sensitive databases or storage
```

**Controls Addressed**:
- AWS-NET-03: Security Group Ingress Rules
- AZ-NET-02: Network Security Group Rules
- AWS-NET-04: Default VPC Security Groups
- AZ-NET-03: Private Endpoints for PaaS

#### Data Exfiltration

**Attack Scenario**: Attacker extracts sensitive data from the cloud environment

**Example**: Unencrypted data in transit or at rest
```
Attacker Actions:
1. Gain access to unencrypted storage or database
2. Exfiltrate data over unmonitored network paths
3. Sell or publish sensitive information
```

**Controls Addressed**:
- AWS-STORAGE-03: S3 Encryption at Rest
- AZ-STORAGE-03: Storage Account Encryption
- AWS-COMPUTE-02: EBS Encryption
- AZ-COMPUTE-02: VM Disk Encryption
- AWS-LOG-05: VPC Flow Logs (for detection)
- AZ-LOG-04: NSG Flow Logs

#### Cryptojacking

**Attack Scenario**: Attacker deploys cryptocurrency miners on cloud resources

**Example**: Compromised credentials used to launch compute instances for mining
```
Attacker Actions:
1. Compromise cloud account credentials
2. Launch large number of compute instances
3. Install cryptocurrency mining software
4. Generate income while customer pays cloud bill
```

**Controls Addressed**:
- AWS-IAM-01: Root Account MFA
- AZ-IAM-01: Privileged Account MFA
- AWS-LOG-03: GuardDuty Enabled (for detection)
- AZ-LOG-03: Defender for Cloud
- AWS-COMPUTE-04: Instance Metadata Service v2
- AZ-COMPUTE-03: VM Extensions Review

#### Account Takeover

**Attack Scenario**: Complete compromise of cloud account through root/global admin access

**Example**: Root account with no MFA and compromised credentials
```
Attacker Actions:
1. Obtain root account credentials
2. No MFA to prevent unauthorized access
3. Full control of entire cloud environment
4. Create backdoors, exfiltrate data, deploy ransomware
```

**Controls Addressed**:
- AWS-IAM-01: Root Account MFA
- AZ-IAM-01: MFA for Privileged Accounts
- AZ-IAM-02: Permanent Global Admin Assignments
- AWS-IAM-02: Root Account Access Keys
- AWS-LOG-01: CloudTrail Monitoring

## MITRE ATT&CK for Cloud

### Mapped Tactics and Techniques

#### Initial Access
- **T1078**: Valid Accounts
  - Compromised credentials
  - Controls: MFA, password policies, access reviews

- **T1190**: Exploit Public-Facing Application
  - Vulnerable applications exposed to internet
  - Controls: Web application firewalls, patch management

#### Persistence
- **T1098**: Account Manipulation
  - Creating unauthorized IAM users
  - Controls: Access logging, IAM monitoring

- **T1136**: Create Account
  - Adding backdoor accounts
  - Controls: CloudTrail, Activity Logs, alerting

#### Privilege Escalation
- **T1078.004**: Cloud Accounts
  - Escalating privileges through cloud-specific mechanisms
  - Controls: Least privilege, policy review

- **T1548**: Abuse Elevation Control Mechanism
  - Exploiting IAM policies
  - Controls: Permission boundaries, SCPs

#### Defense Evasion
- **T1562.008**: Disable Cloud Logs
  - Disabling CloudTrail or Activity Logs
  - Controls: Log protection, centralized logging

- **T1562.007**: Disable or Modify Cloud Firewall
  - Modifying Security Groups or NSGs
  - Controls: Configuration monitoring, AWS Config, Azure Policy

#### Credential Access
- **T1552.005**: Cloud Instance Metadata API
  - Accessing instance metadata for credentials
  - Controls: IMDSv2, managed identities

- **T1528**: Steal Application Access Token
  - Stealing OAuth tokens or SAS tokens
  - Controls: Token expiration, conditional access

#### Discovery
- **T1580**: Cloud Infrastructure Discovery
  - Enumerating cloud resources
  - Controls: Logging, anomaly detection

- **T1538**: Cloud Service Dashboard
  - Accessing cloud console for reconnaissance
  - Controls: MFA, access logging

#### Lateral Movement
- **T1021**: Remote Services
  - Moving between cloud resources
  - Controls: Network segmentation, just-in-time access

#### Collection
- **T1530**: Data from Cloud Storage Object
  - Accessing cloud storage buckets
  - Controls: Access controls, encryption, logging

#### Exfiltration
- **T1537**: Transfer Data to Cloud Account
  - Exfiltrating to attacker-controlled cloud account
  - Controls: Data loss prevention, network monitoring

#### Impact
- **T1485**: Data Destruction
  - Deleting data or resources
  - Controls: Soft delete, versioning, backups

- **T1486**: Data Encrypted for Impact (Ransomware)
  - Encrypting data and demanding ransom
  - Controls: Backups, access controls, monitoring

## Security Control Priority

### Critical (Immediate Implementation)

These controls prevent the most common and severe attacks:

1. **Multi-Factor Authentication**
   - Prevents account takeover
   - Mitigates credential compromise
   - Controls: AZ-IAM-01, AWS-IAM-01

2. **Logging and Monitoring**
   - Enables threat detection
   - Provides audit trail
   - Controls: AWS-LOG-01, AZ-LOG-01, AWS-LOG-03, AZ-LOG-03

3. **Public Access Prevention**
   - Prevents data exposure
   - Reduces attack surface
   - Controls: AWS-STORAGE-01, AZ-STORAGE-01

4. **Least Privilege Access**
   - Limits blast radius
   - Prevents privilege escalation
   - Controls: AWS-IAM-05, AZ-IAM-04

### High (Near-Term Implementation)

5. **Encryption at Rest**
   - Protects data confidentiality
   - Controls: AWS-STORAGE-03, AZ-STORAGE-03

6. **Network Segmentation**
   - Prevents lateral movement
   - Controls: AWS-NET-03, AZ-NET-02

7. **Encryption in Transit**
   - Prevents data interception
   - Controls: AWS-STORAGE-05, AZ-STORAGE-04

### Medium (Planned Implementation)

8. **Configuration Compliance**
   - Prevents drift from baseline
   - Controls: AWS-GOV-01, AZ-GOV-01

9. **Patch Management**
   - Reduces vulnerability exposure
   - Controls: AWS-COMPUTE-03, AZ-COMPUTE-04

### Low (Ongoing Improvement)

10. **Advanced Monitoring**
    - Enhanced threat detection
    - Controls: Additional security services

## Shared Responsibility Model

### Cloud Provider Responsibility

**Security OF the Cloud**:
- Physical datacenter security
- Hardware and network infrastructure
- Hypervisor and host OS
- Managed service security (for PaaS/SaaS)

### Customer Responsibility

**Security IN the Cloud**:
- IAM and access control
- Data encryption
- Network configuration
- Application security
- Guest OS and patches (for IaaS)
- Data classification and protection

### Critical Understanding

**Customer is responsible for**:
- All security controls in this framework
- Proper configuration of cloud services
- Access management
- Data protection
- Logging and monitoring configuration

**Misconfiguration is the customer's responsibility** even if the cloud provider offers the capability.

## Compliance and Regulatory Context

### Common Compliance Frameworks

- **CIS Benchmarks**: Industry consensus security baselines
- **NIST CSF**: Cybersecurity Framework
- **ISO 27001**: Information security management
- **SOC 2**: Service organization controls
- **PCI DSS**: Payment card security
- **HIPAA**: Healthcare data protection
- **GDPR**: European data protection

### Framework Alignment

This hardening framework primarily aligns with:
- **CIS Benchmarks** (direct mapping)
- **NIST CSF** (Protect and Detect functions)
- **ISO 27001** (technical controls)

## Conclusion

Understanding the threat landscape and attack patterns enables effective prioritization of security controls. The framework addresses real-world threats observed in cloud environments and provides defense-in-depth protection.

**Key Takeaways**:
1. Misconfiguration is the leading cause of cloud security incidents
2. Multi-factor authentication is the most effective single control
3. Logging enables detection and response
4. Defense in depth provides resilient security
5. Continuous validation prevents configuration drift

---

**Next**: Review [02-cis-mapping.md](02-cis-mapping.md) for CIS Benchmark alignment details.
