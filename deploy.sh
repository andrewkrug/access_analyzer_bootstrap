#!/bin/bash

# AWS IAM Access Analyzer Bootstrap - CloudShell Deployment Script
# MIT License

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   AWS IAM Access Analyzer Bootstrap               ║${NC}"
echo -e "${BLUE}║   Educational Security Tool                        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running in CloudShell
if [ -n "$AWS_EXECUTION_ENV" ] && [ "$AWS_EXECUTION_ENV" = "CloudShell" ]; then
    echo -e "${GREEN}✅ Running in AWS CloudShell${NC}"
else
    echo -e "${YELLOW}⚠️  Not running in CloudShell - ensure AWS credentials are configured${NC}"
fi

# Check Python version
echo -e "\n${BLUE}🐍 Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✅ Python $PYTHON_VERSION${NC}"

# Install dependencies
echo -e "\n${BLUE}📦 Installing dependencies...${NC}"
pip3 install --quiet --upgrade boto3 2>&1 | grep -v "Requirement already satisfied" || true
echo -e "${GREEN}✅ Dependencies installed${NC}"

# Make script executable
echo -e "\n${BLUE}🔧 Setting up scripts...${NC}"
chmod +x access_analyzer.py
echo -e "${GREEN}✅ Scripts configured${NC}"

# Get AWS account info
echo -e "\n${BLUE}🔍 Checking AWS credentials...${NC}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "ERROR")
REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")

if [ "$ACCOUNT_ID" = "ERROR" ]; then
    echo -e "${RED}❌ Unable to get AWS account information${NC}"
    echo -e "${RED}   Please ensure AWS credentials are configured${NC}"
    exit 1
fi

echo -e "${GREEN}✅ AWS Account: $ACCOUNT_ID${NC}"
echo -e "${GREEN}✅ Region: $REGION${NC}"

# Check IAM permissions
echo -e "\n${BLUE}🔐 Checking IAM permissions...${NC}"
if aws accessanalyzer list-analyzers --region $REGION >/dev/null 2>&1; then
    echo -e "${GREEN}✅ Access Analyzer permissions confirmed${NC}"
else
    echo -e "${YELLOW}⚠️  Unable to verify Access Analyzer permissions${NC}"
    echo -e "${YELLOW}   You may need to add IAM permissions (see iam-permissions.json)${NC}"
fi

# Summary
echo -e "\n${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Setup Complete!                                  ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}"

echo -e "\n${GREEN}Quick Start Commands:${NC}"
echo -e "
  ${YELLOW}1. Create an analyzer:${NC}
     ./access_analyzer.py create-analyzer --name my-security-analyzer

  ${YELLOW}2. List analyzers:${NC}
     ./access_analyzer.py list-analyzers

  ${YELLOW}3. Validate a policy:${NC}
     ./access_analyzer.py validate-policy --file examples/sample-policy.json

  ${YELLOW}4. Test with bad policy:${NC}
     ./access_analyzer.py validate-policy --file examples/bad-policy.json --verbose

  ${YELLOW}5. Get help:${NC}
     ./access_analyzer.py --help
"

echo -e "${BLUE}📚 Documentation:${NC}"
echo -e "   • README.md - Full project documentation"
echo -e "   • examples/README.md - Policy examples and exercises"
echo -e "   • https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html"

echo -e "\n${GREEN}🎓 Learning Path:${NC}"
echo -e "   1. Read README.md to understand Access Analyzer"
echo -e "   2. Create your first analyzer"
echo -e "   3. Explore policy validation with examples/"
echo -e "   4. Try the exercises in examples/README.md"

echo -e "\n${BLUE}Happy Learning! 🚀${NC}\n"
