# Policy Examples

This directory contains example IAM policies for testing AWS IAM Access Analyzer policy validation features.

## Files

### 1. `sample-policy.json`
**Purpose**: Well-formed, secure IAM policy
**Use Case**: Basic validation test - should pass with no errors

This policy demonstrates:
- Specific actions (no wildcards)
- Scoped resources where possible
- Read-only permissions for most actions
- Good security practices

**Test it:**
```bash
python3 ../access_analyzer.py validate-policy --file sample-policy.json
```

**Expected Result**: ✅ Should pass validation with minimal or no warnings

---

### 2. `boundary-policy.json`
**Purpose**: Permissions boundary example
**Use Case**: Demonstrates how to restrict maximum permissions

This policy shows:
- **Allow Statement**: Defines services the user CAN access (S3, EC2, Lambda, etc.)
- **Deny Statements**: Explicitly blocks IAM, billing, and destructive actions
- Real-world use case: Safe delegation to developers without risk of privilege escalation

**How Boundaries Work:**
```
Effective Permissions = Identity Policy ∩ Permissions Boundary

Example:
- Identity Policy: Grants "s3:*", "ec2:*", "iam:*"
- Boundary Policy: Allows "s3:*", "ec2:Describe*", DENIES "iam:*"
- Result: User gets "s3:*" and "ec2:Describe*" only
```

**Test it:**
```bash
python3 ../access_analyzer.py validate-policy --file boundary-policy.json
```

**Expected Result**: ✅ Should pass - boundaries can use broad denies

---

### 3. `s3-bucket-policy.json`
**Purpose**: Resource policy example (S3 bucket)
**Use Case**: Demonstrates resource-based policies and external access

This policy demonstrates:
- **Public access**: Allows anonymous reads (GetObject)
- **Cross-account access**: Grants another AWS account full access
- **Security control**: Requires SSL/TLS for all connections

**Important**: This policy will be flagged by Access Analyzer if used on a real bucket because it allows external access!

**Test it:**
```bash
python3 ../access_analyzer.py validate-policy \
  --file s3-bucket-policy.json \
  --type RESOURCE_POLICY
```

**Expected Result**: ✅ Valid syntax, but Access Analyzer will flag this as allowing external access if deployed

---

### 4. `bad-policy.json`
**Purpose**: Intentionally insecure policy for learning
**Use Case**: Demonstrates common security anti-patterns

This policy contains multiple security issues:
1. **Wildcard Action & Resource**: `"Action": "*"` on `"Resource": "*"` (full admin!)
2. **IAM Wildcards**: `"iam:*"` allows privilege escalation
3. **No MFA**: Destructive actions without MFA requirement
4. **Meaningless Condition**: IP restriction of `0.0.0.0/0` allows all IPs

**Test it:**
```bash
python3 ../access_analyzer.py validate-policy --file bad-policy.json --verbose
```

**Expected Result**: ⚠️ Multiple SECURITY_WARNINGS about overly permissive policies

---

## Policy Types

AWS IAM Access Analyzer validates two types of policies:

### IDENTITY_POLICY (default)
- Attached to IAM users, groups, or roles
- Defines what the identity CAN do
- Examples: Managed policies, inline policies, permissions boundaries

### RESOURCE_POLICY
- Attached to AWS resources (S3 buckets, KMS keys, Lambda functions, etc.)
- Defines who can access the resource
- Examples: S3 bucket policies, KMS key policies

**Choose the right type when validating:**
```bash
# For IAM user/role policies
python3 ../access_analyzer.py validate-policy --file policy.json --type IDENTITY_POLICY

# For S3/KMS/Lambda policies
python3 ../access_analyzer.py validate-policy --file policy.json --type RESOURCE_POLICY
```

---

## Validation Finding Types

When you validate policies, you'll see these finding types:

| Type | Severity | Meaning |
|------|----------|---------|
| **ERROR** | 🔴 Critical | Policy syntax error - will not work |
| **SECURITY_WARNING** | 🟡 High | Policy is overly permissive - security risk |
| **WARNING** | 🟠 Medium | Deprecated or potentially problematic |
| **SUGGESTION** | 🔵 Low | Best practice recommendation |

---

## Common Issues Found by Validator

### 1. Overly Broad Permissions
```json
{
  "Action": "*",
  "Resource": "*"
}
```
**Issue**: Grants admin access to everything
**Fix**: Specify exact actions and resources

### 2. Missing Resource Constraints
```json
{
  "Action": "s3:PutObject",
  "Resource": "*"
}
```
**Issue**: Can write to ANY S3 bucket
**Fix**: Use specific bucket ARNs

### 3. No Conditions on Sensitive Actions
```json
{
  "Action": "iam:CreateUser",
  "Resource": "*"
}
```
**Issue**: No MFA or IP restrictions
**Fix**: Add conditions for sensitive actions

### 4. Principal Wildcards in Resource Policies
```json
{
  "Principal": "*",
  "Action": "s3:GetObject"
}
```
**Issue**: Public access to resource
**Fix**: Only use if truly needed (like public websites)

---

## Learning Exercises

### Exercise 1: Fix the Bad Policy
1. Run validation on `bad-policy.json`
2. Identify all security warnings
3. Create a new policy that fixes each issue
4. Re-validate until it passes cleanly

### Exercise 2: Create a Boundary
1. Imagine a junior developer who needs:
   - Full S3 access
   - Read-only EC2
   - CloudWatch logs access
   - NO access to IAM, billing, or deleting resources
2. Create a permissions boundary policy
3. Validate it

### Exercise 3: Secure S3 Bucket Policy
1. Start with `s3-bucket-policy.json`
2. Modify it to:
   - Allow public read only for `/public/*` prefix
   - Require MFA for delete operations
   - Restrict admin actions to specific AWS account
3. Validate it as RESOURCE_POLICY

---

## Additional Resources

- [IAM Policy Grammar](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html)
- [Policy Validation Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html)
- [Permissions Boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)

---

**Tip**: Always validate policies before deploying them to production!
