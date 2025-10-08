#!/usr/bin/env python3
"""
AWS IAM Access Analyzer Bootstrap Tool
Educational project for cloud security learning
MIT License
"""

import argparse
import boto3
import json
import sys
from datetime import datetime
from typing import Dict, List, Optional


class AccessAnalyzerBootstrap:
    """Main class for Access Analyzer operations"""

    def __init__(self, region: Optional[str] = None):
        """Initialize boto3 clients"""
        self.region = region or 'us-east-1'
        self.session = boto3.Session(region_name=self.region)
        self.analyzer_client = self.session.client('accessanalyzer')
        self.sts_client = self.session.client('sts')
        self.account_id = self._get_account_id()

    def _get_account_id(self) -> str:
        """Get current AWS account ID"""
        try:
            return self.sts_client.get_caller_identity()['Account']
        except Exception as e:
            print(f"❌ Error getting account ID: {e}")
            sys.exit(1)

    def create_analyzer(self, analyzer_name: str, tags: Optional[Dict] = None) -> Dict:
        """
        Create an account-scoped Access Analyzer

        Note: This creates an ACCOUNT analyzer, not ORGANIZATION.
        Organization analyzers require AWS Organizations setup.
        """
        try:
            print(f"🔍 Creating analyzer: {analyzer_name}")
            print(f"📍 Region: {self.region}")
            print(f"🏢 Account: {self.account_id}")
            print(f"📊 Type: ACCOUNT (free tier)")

            response = self.analyzer_client.create_analyzer(
                analyzerName=analyzer_name,
                type='ACCOUNT',  # Free tier, account-scoped only
                tags=tags or {}
            )

            print(f"✅ Analyzer created successfully!")
            print(f"🆔 ARN: {response['arn']}")
            print("\n💡 The analyzer will now scan your account for:")
            print("   • S3 buckets with external access")
            print("   • IAM roles that can be assumed externally")
            print("   • KMS keys shared with other accounts")
            print("   • Lambda functions with external permissions")
            print("   • And more...")
            print("\n⏳ Initial scan may take a few minutes to complete.")

            return response

        except self.analyzer_client.exceptions.ConflictException:
            print(f"⚠️  Analyzer '{analyzer_name}' already exists in this region.")
            return self._get_analyzer(analyzer_name)
        except Exception as e:
            print(f"❌ Error creating analyzer: {e}")
            sys.exit(1)

    def _get_analyzer(self, analyzer_name: str) -> Dict:
        """Get existing analyzer details"""
        try:
            response = self.analyzer_client.get_analyzer(
                analyzerName=analyzer_name
            )
            return response['analyzer']
        except Exception as e:
            print(f"❌ Error getting analyzer: {e}")
            return {}

    def list_analyzers(self) -> List[Dict]:
        """List all analyzers in the current region"""
        try:
            print(f"📋 Listing analyzers in {self.region}...\n")

            response = self.analyzer_client.list_analyzers()
            analyzers = response.get('analyzers', [])

            if not analyzers:
                print("ℹ️  No analyzers found in this region.")
                print("💡 Create one with: python3 access_analyzer.py create-analyzer --name my-analyzer")
                return []

            for analyzer in analyzers:
                print(f"📊 Name: {analyzer['name']}")
                print(f"   Type: {analyzer['type']}")
                print(f"   Status: {analyzer['status']}")
                print(f"   ARN: {analyzer['arn']}")
                print(f"   Created: {analyzer['createdAt']}")
                print()

            return analyzers

        except Exception as e:
            print(f"❌ Error listing analyzers: {e}")
            return []

    def list_findings(self, analyzer_arn: str, max_results: int = 50) -> List[Dict]:
        """
        List findings from an analyzer

        Findings represent resources that can be accessed from outside your account.
        """
        try:
            print(f"🔎 Fetching findings from analyzer...\n")

            response = self.analyzer_client.list_findings(
                analyzerArn=analyzer_arn,
                maxResults=max_results
            )

            findings = response.get('findings', [])

            if not findings:
                print("✅ No findings! Your account has no externally accessible resources.")
                print("💡 This is good - it means no resources are shared outside your account.")
                return []

            print(f"⚠️  Found {len(findings)} findings:\n")

            for idx, finding in enumerate(findings, 1):
                print(f"{idx}. Resource: {finding.get('resource', 'Unknown')}")
                print(f"   Type: {finding.get('resourceType', 'Unknown')}")
                print(f"   Status: {finding.get('status', 'Unknown')}")
                print(f"   Principal: {finding.get('principal', {}).get('AWS', 'External')}")
                print(f"   Updated: {finding.get('updatedAt', 'Unknown')}")
                print()

            return findings

        except Exception as e:
            print(f"❌ Error listing findings: {e}")
            return []

    def validate_policy(
        self,
        policy_document: str,
        policy_type: str = 'IDENTITY_POLICY',
        verbose: bool = False
    ) -> Dict:
        """
        Validate an IAM policy using Access Analyzer

        Policy Types:
        - IDENTITY_POLICY: For IAM users, groups, roles
        - RESOURCE_POLICY: For S3 buckets, KMS keys, etc.

        See: https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html
        """
        try:
            print(f"🔍 Validating policy...")
            print(f"📄 Policy Type: {policy_type}\n")

            # Parse policy if it's a file path
            if isinstance(policy_document, str) and not policy_document.strip().startswith('{'):
                with open(policy_document, 'r') as f:
                    policy_document = f.read()

            response = self.analyzer_client.validate_policy(
                policyDocument=policy_document,
                policyType=policy_type
            )

            findings = response.get('findings', [])

            # Categorize findings
            errors = [f for f in findings if f['findingType'] == 'ERROR']
            security_warnings = [f for f in findings if f['findingType'] == 'SECURITY_WARNING']
            warnings = [f for f in findings if f['findingType'] == 'WARNING']
            suggestions = [f for f in findings if f['findingType'] == 'SUGGESTION']

            # Print results
            if not findings:
                print("✅ PASSED - Policy is valid with no issues!\n")
                return response

            # Errors (blocking)
            if errors:
                print(f"❌ ERRORS ({len(errors)}) - Policy will NOT work:\n")
                for error in errors:
                    self._print_finding(error, verbose)
                print()

            # Security warnings (important)
            if security_warnings:
                print(f"⚠️  SECURITY WARNINGS ({len(security_warnings)}) - Policy may be overly permissive:\n")
                for warning in security_warnings:
                    self._print_finding(warning, verbose)
                print()

            # Warnings (non-critical)
            if warnings:
                print(f"⚡ WARNINGS ({len(warnings)}) - Consider reviewing:\n")
                for warning in warnings:
                    self._print_finding(warning, verbose)
                print()

            # Suggestions (best practices)
            if suggestions:
                print(f"💡 SUGGESTIONS ({len(suggestions)}) - Best practice recommendations:\n")
                for suggestion in suggestions:
                    self._print_finding(suggestion, verbose)
                print()

            # Summary
            if errors:
                print("❌ Validation FAILED - Fix errors before deploying this policy.")
            elif security_warnings:
                print("⚠️  Validation PASSED with security warnings - Review carefully before deploying.")
            else:
                print("✅ Validation PASSED - Policy has minor suggestions but is safe to deploy.")

            return response

        except Exception as e:
            print(f"❌ Error validating policy: {e}")
            sys.exit(1)

    def _print_finding(self, finding: Dict, verbose: bool = False):
        """Print a single validation finding"""
        issue_code = finding.get('issueCode', 'UNKNOWN')
        finding_type = finding.get('findingType', 'UNKNOWN')
        finding_details = finding.get('findingDetails', 'No details available')

        # Get location info
        locations = finding.get('locations', [])
        location_str = ""
        if locations:
            loc = locations[0]
            path = loc.get('path', [])
            span = loc.get('span', {})
            if span:
                location_str = f"[Line {span.get('start', {}).get('line', '?')}] "

        print(f"   {location_str}{issue_code}")
        print(f"   └─ {finding_details}")

        if verbose:
            print(f"      Type: {finding_type}")
            if 'learnMoreLink' in finding:
                print(f"      Learn more: {finding['learnMoreLink']}")
        print()

    def get_finding_details(self, analyzer_arn: str, finding_id: str) -> Dict:
        """Get detailed information about a specific finding"""
        try:
            response = self.analyzer_client.get_finding(
                analyzerArn=analyzer_arn,
                id=finding_id
            )

            finding = response.get('finding', {})

            print(f"📊 Finding Details:\n")
            print(f"ID: {finding.get('id')}")
            print(f"Resource: {finding.get('resource')}")
            print(f"Resource Type: {finding.get('resourceType')}")
            print(f"Status: {finding.get('status')}")
            print(f"Principal: {json.dumps(finding.get('principal', {}), indent=2)}")
            print(f"\nConditions:")
            print(json.dumps(finding.get('condition', {}), indent=2))
            print(f"\nActions: {finding.get('action', [])}")

            return finding

        except Exception as e:
            print(f"❌ Error getting finding details: {e}")
            return {}


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='AWS IAM Access Analyzer Bootstrap - Educational Security Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create an analyzer
  python3 access_analyzer.py create-analyzer --name my-analyzer

  # List all analyzers
  python3 access_analyzer.py list-analyzers

  # List findings
  python3 access_analyzer.py list-findings --analyzer-arn arn:aws:access-analyzer:...

  # Validate a policy
  python3 access_analyzer.py validate-policy --file examples/sample-policy.json

  # Validate with verbose output
  python3 access_analyzer.py validate-policy --file policy.json --verbose

For more information: https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html
        """
    )

    parser.add_argument('--region', default='us-east-1', help='AWS region (default: us-east-1)')

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Create analyzer
    create_parser = subparsers.add_parser('create-analyzer', help='Create a new analyzer')
    create_parser.add_argument('--name', required=True, help='Analyzer name')

    # List analyzers
    subparsers.add_parser('list-analyzers', help='List all analyzers')

    # List findings
    findings_parser = subparsers.add_parser('list-findings', help='List findings from an analyzer')
    findings_parser.add_argument('--analyzer-arn', required=True, help='Analyzer ARN')
    findings_parser.add_argument('--max-results', type=int, default=50, help='Max results (default: 50)')

    # Get finding details
    detail_parser = subparsers.add_parser('get-finding', help='Get details of a specific finding')
    detail_parser.add_argument('--analyzer-arn', required=True, help='Analyzer ARN')
    detail_parser.add_argument('--finding-id', required=True, help='Finding ID')

    # Validate policy
    validate_parser = subparsers.add_parser('validate-policy', help='Validate an IAM policy')
    validate_parser.add_argument('--file', required=True, help='Path to policy JSON file')
    validate_parser.add_argument(
        '--type',
        choices=['IDENTITY_POLICY', 'RESOURCE_POLICY'],
        default='IDENTITY_POLICY',
        help='Policy type (default: IDENTITY_POLICY)'
    )
    validate_parser.add_argument('--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Initialize tool
    tool = AccessAnalyzerBootstrap(region=args.region)

    # Execute command
    if args.command == 'create-analyzer':
        tool.create_analyzer(args.name)

    elif args.command == 'list-analyzers':
        tool.list_analyzers()

    elif args.command == 'list-findings':
        tool.list_findings(args.analyzer_arn, args.max_results)

    elif args.command == 'get-finding':
        tool.get_finding_details(args.analyzer_arn, args.finding_id)

    elif args.command == 'validate-policy':
        with open(args.file, 'r') as f:
            policy_doc = f.read()
        tool.validate_policy(policy_doc, args.type, args.verbose)


if __name__ == '__main__':
    main()
