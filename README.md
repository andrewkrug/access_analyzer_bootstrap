# AWS IAM Access Analyzer Bootstrap

An open-source educational project demonstrating AWS IAM Access Analyzer capabilities for cloud security students and practitioners. Designed to run in AWS CloudShell with zero setup.

## 🎓 Educational Purpose

This project provides hands-on examples of:
- **External Access Analysis**: Identify resources shared outside your AWS account
- **Policy Validation**: Check IAM policies for errors, warnings, and security issues
- **Permissions Analysis**: Understand effective permissions (requires paid features - see below)

## 📋 Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Understanding IAM Boundaries](#understanding-iam-boundaries)
- [Policy Validation](#policy-validation)
- [Free vs Paid Features](#free-vs-paid-features)
- [Usage Examples](#usage-examples)
- [License](#license)

## ✨ Features

### Included (Free Tier)

- **Analyzer Creation**: Set up account-scoped analyzers
- **External Access Findings**: Detect resources accessible outside your account
- **Policy Validation**: Validate IAM policies against AWS best practices
- **CloudShell Compatible**: Run directly in AWS CloudShell

### Not Included (Paid Features - Info Only)

- **Unused Access Analysis**: Requires IAM Access Analyzer premium ($$$)
- **Custom Policy Checks**: Advanced policy validation rules
- **Organization-wide Analysis**: Requires AWS Organizations setup

## 🚀 Quick Start

### Run in AWS CloudShell

1. Open [AWS CloudShell](https://console.aws.amazon.com/cloudshell) in your AWS account

2. Clone and run:
```bash
git clone <your-repo-url>
cd access_analyzer_bootstrap
chmod +x deploy.sh
./deploy.sh
```

3. Or run directly with Python:
```bash
python3 access_analyzer.py --help
```

### Prerequisites

- AWS Account with CloudShell access
- IAM permissions for Access Analyzer (see `iam-permissions.json`)
- Python 3.7+ (pre-installed in CloudShell)
- boto3 (pre-installed in CloudShell)

## 🔒 Understanding IAM Boundaries

### What are Permissions Boundaries?

A **permissions boundary** is an advanced IAM feature that sets the maximum permissions an identity-based policy can grant to an IAM entity (user or role). Think of it as a safety guardrail.

#### Key Concepts:

1. **Maximum Permissions**: Boundaries define what an entity CAN'T do, not what it CAN do
2. **Dual Evaluation**: Effective permissions = Identity Policy ∩ Permissions Boundary
3. **Delegation Safety**: Allow safe delegation of admin tasks without full admin access

#### Visual Example:

```
Identity Policy        Permissions Boundary      Effective Permissions
┌──────────────┐      ┌──────────────┐           ┌──────────────┐
│ S3: *        │  ∩   │ S3: Read*    │     =     │ S3: Read*    │
│ EC2: *       │      │ S3: Write*   │           │              │
│ IAM: *       │      │ EC2: Describe│           │ EC2: Describe│
└──────────────┘      └──────────────┘           └──────────────┘
```

Even though the identity policy allows IAM and full EC2, the boundary restricts to S3 and EC2:Describe only.

### Types of Policy Boundaries:

1. **Permissions Boundary**: Applied to users/roles
2. **SCP (Service Control Policy)**: Applied at AWS Organizations level (not covered here)
3. **Session Policies**: Temporary boundary for assumed roles
4. **Resource-based Policies**: Attached to resources (S3 buckets, etc.)

### Real-World Use Case:

```python
# Scenario: Developer team needs S3 access but should never touch IAM
#
# Identity Policy: Grants broad S3 and EC2 permissions
# Permissions Boundary: Blocks all IAM actions
# Result: Developers can work freely in S3/EC2 but can't escalate privileges
```

See `examples/boundary-policy.json` for a complete example.

## ✅ Policy Validation

AWS IAM Access Analyzer includes a policy validation feature that checks policies for:

### Validation Types:

1. **Syntax Errors**: JSON formatting, invalid ARNs, malformed conditions
2. **Security Warnings**: Overly permissive policies, missing conditions
3. **Suggestions**: Best practices and optimization recommendations
4. **Deprecated Features**: Old policy elements that should be updated

### How It Works:

The validator uses the same engine that validates policies in the AWS Console. It checks against:

- IAM policy grammar
- Service-specific policy requirements
- AWS security best practices
- Known anti-patterns

### Policy Validation Example:

```bash
# Validate a local policy file
python3 access_analyzer.py validate-policy --file examples/sample-policy.json

# Validate with specific policy type
python3 access_analyzer.py validate-policy --file examples/boundary-policy.json --type RESOURCE_POLICY
```

### Understanding Validation Results:

- **ERROR**: Policy will not work, must be fixed
- **SECURITY_WARNING**: Policy works but may be overly permissive
- **SUGGESTION**: Policy works but could be improved
- **WARNING**: Deprecated features or non-critical issues

See the [AWS Policy Validation Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html) for complete details.

## 💰 Free vs Paid Features

### ✅ Free Features (Included in this project)

| Feature | Description | Cost |
|---------|-------------|------|
| External Access Analysis | Find resources shared outside account | Free |
| Policy Validation | Validate IAM, S3, KMS policies | Free |
| Archive Rules | Auto-archive expected findings | Free |
| Account Analyzer | Single account scope | Free |

### 💵 Paid Features (Info only - NOT enabled)

| Feature | Description | Estimated Cost |
|---------|-------------|----------------|
| Unused Access | Analyze last accessed info | ~$0.20 per IAM resource/month |
| Custom Policy Checks | Write custom validation rules | Varies |
| Organization Analyzer | Cross-account analysis | Free but requires Org setup |

**Note**: This project uses ACCOUNT analyzer type only, scoped to your individual AWS account. Organization-wide analysis requires AWS Organizations configuration.

### Why Organization Analyzers Aren't Included:

- Requires AWS Organizations setup (complexity)
- Most students/learners work in single accounts
- Account-level analysis demonstrates all core concepts
- You can extend this project for Org-level analysis

## 📖 Usage Examples

### Create an Analyzer

```bash
python3 access_analyzer.py create-analyzer --name my-security-analyzer
```

### List All Findings

```bash
python3 access_analyzer.py list-findings --analyzer my-security-analyzer
```

### Validate a Policy

```bash
# Basic validation
python3 access_analyzer.py validate-policy --file examples/sample-policy.json

# Validate resource policy (S3, KMS, etc.)
python3 access_analyzer.py validate-policy \
  --file examples/s3-bucket-policy.json \
  --type RESOURCE_POLICY

# Validate with verbose output
python3 access_analyzer.py validate-policy \
  --file examples/boundary-policy.json \
  --verbose
```

### Check for Overly Permissive Policies

```bash
python3 access_analyzer.py validate-policy --file examples/bad-policy.json
# Returns security warnings about overly broad permissions
```

### Example Validation Output:

```
Validating policy: examples/sample-policy.json
Policy Type: IDENTITY_POLICY

✅ PASSED - No errors found

⚠️  SECURITY WARNINGS (2):
  - Line 8: Action "s3:*" is overly permissive. Consider limiting to specific actions.
  - Line 12: Resource "*" grants access to all resources. Specify ARNs when possible.

💡 SUGGESTIONS (1):
  - Consider using conditions to restrict access by IP or MFA.

Validation Complete.
```

## 📁 Project Structure

```
access_analyzer_bootstrap/
├── README.md                          # This file
├── LICENSE                            # MIT License
├── access_analyzer.py                 # Main script
├── deploy.sh                          # CloudShell deployment
├── requirements.txt                   # Python dependencies
├── iam-permissions.json              # Required IAM permissions
└── examples/
    ├── sample-policy.json            # Basic IAM policy for validation
    ├── boundary-policy.json          # Permissions boundary example
    ├── s3-bucket-policy.json         # Resource policy example
    ├── bad-policy.json               # Policy with intentional issues
    └── README.md                     # Examples documentation
```

## 🔐 Required IAM Permissions

Minimum permissions needed (see `iam-permissions.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "access-analyzer:CreateAnalyzer",
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings",
        "access-analyzer:GetFinding",
        "access-analyzer:ValidatePolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

## 🎯 Learning Objectives

After using this project, you should understand:

1. How to identify external access to AWS resources
2. How to validate IAM policies before deployment
3. The difference between identity and resource policies
4. How permissions boundaries work
5. The limitations of free vs paid Access Analyzer features

## 🤝 Contributing

This is an educational project. Contributions welcome:

- Additional policy examples
- Improved documentation
- Bug fixes
- Feature requests

## 📚 Additional Resources

- [AWS Access Analyzer User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [Policy Validation Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Permissions Boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)

## ⚠️ Security Note

This tool is for educational purposes in your own AWS account. Always:

- Review findings before taking action
- Understand policies before deploying them
- Use least privilege principles
- Test in non-production accounts first

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

**Built for cloud security education** | **Runs in AWS CloudShell** | **Open Source MIT License**
