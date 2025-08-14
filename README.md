# CloudTrail Security Review Scripts

Two AWS CloudTrail security analysis tools that automatically detect critical security events. Choose the version that best fits your environment complexity.

## Script Options

### Multi-Region Script (`mult-region-security-review.sh`)
**Advanced version** with intelligent multi-region support and comprehensive coverage.

**Best for:** Enterprise environments, distributed resources, complex CloudTrail setups

### Simple Clean Script (`simple-security-review.sh`) 
**Streamlined version** focused on single-region deployments with faster execution.

**Best for:** Development environments, single-region deployments, quick security checks

## Quick Start Guide

### Choose Your Script

**If you're unsure which to use:**
```bash
# Try the simple version first
./simple_clean_script.sh

# If you need multi-region coverage:
./multi_region_security_script.sh -c
```

**Multi-Region Script:**
```bash
# Auto-detect and smart scan
./multi_region_security_script.sh

# Comprehensive scan (all regions with resources)
./multi_region_security_script.sh -c

# Specific region
./multi_region_security_script.sh -r us-west-2
```

**Simple Clean Script:**
```bash
# Single command - scans current region
./simple_clean_script.sh
```

## Overview

This script provides automated security monitoring by analyzing CloudTrail events to detect:
- Root account usage
- Failed login attempts  
- Unauthorized resource changes
- Identity and access management modifications
- Security group changes
- Resource deletions and terminations

The script is designed to work across different AWS environments including commercial, GovCloud, China regions, and region-restricted accounts without any hardcoded assumptions.

## Features

### Multi-Region Intelligence
- **Auto-detects CloudTrail configuration** (single-region vs multi-region trails)
- **Smart region selection** based on where your events are actually stored
- **Comprehensive mode** to scan all regions with resources
- **No hardcoded regions** - works in any AWS partition

### Security Coverage
- **Critical events:** Root usage, failed logins, privilege escalations
- **Identity management:** User/role creation and deletion
- **Resource protection:** EC2, RDS, S3 deletion monitoring
- **Network security:** Security group modifications
- **Monitoring integrity:** CloudTrail tampering detection

### Flexible Deployment
- **Multiple CloudTrail configurations** supported
- **Cross-region resource detection**
- **Rate limiting protection** with automatic retries
- **Cost-optimized** scanning strategies

## Requirements

### Prerequisites
- **AWS CLI** v2.0+ installed and configured
- **jq** JSON processor
- **Valid AWS credentials** with CloudTrail read permissions

### IAM Permissions Required
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:LookupEvents",
                "cloudtrail:DescribeTrails",
                "ec2:DescribeRegions",
                "ec2:DescribeInstances",
                "rds:DescribeDBInstances",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## Installation

### Download Both Scripts
```bash
# Download multi-region script
curl -O https://your-repo/multi_region_security_script.sh
chmod +x multi_region_security_script.sh

# Download simple clean script  
curl -O https://your-repo/simple_clean_script.sh
chmod +x simple_clean_script.sh

# Verify dependencies
aws --version
jq --version
```

### Choose Your Version
| Criteria | Multi-Region Script | Simple Clean Script |
|----------|-------------------|-------------------|
| **Resources in multiple regions** | Recommended | Limited coverage |
| **Single region deployment** | Works but overkill | Perfect fit |
| **Complex CloudTrail setup** | Auto-detects | May miss events |
| **Speed priority** | 1-5 minutes | 30-60 seconds |
| **Development/testing** | Unnecessary complexity | Ideal |
| **Production/enterprise** | Comprehensive |  May miss issues |

## Usage

### Multi-Region Script Usage
```bash
# Auto-detect configuration and run security scan
./multi_region_security_script.sh

# Comprehensive mode - scan all regions with resources (slower but thorough)
./multi_region_security_script.sh -c

# Specify custom region
./multi_region_security_script.sh -r us-west-2

# Show help
./multi_region_security_script.sh -h
```

### Simple Clean Script Usage
```bash
# Single command - scans your current AWS region
./simple_clean_script.sh

# No additional options - designed for simplicity
```

### Command Options (Multi-Region Script Only)
```bash
-c, --comprehensive    Check all regions with resources (slower but thorough)
-r, --region REGION   Set primary region
-h, --help           Show help information
```

### Usage Examples

#### Standard Security Review
```bash
./multi_region_security_script.sh
```
**Best for:** Daily security checks, single-region deployments, multi-region trails

#### Comprehensive Multi-Region Scan
```bash
./multi_region_security_script.sh -c
```
**Best for:** Weekly comprehensive reviews, distributed resources, audit compliance

#### Specific Region Focus
```bash
./multi_region_security_script.sh -r eu-west-1
```
**Best for:** Region-specific investigations, troubleshooting

## Understanding the Output

### Multi-Region Script Output
```
========================================
MULTI-REGION CLOUDTRAIL SECURITY REVIEW
Account: 123456789012
Primary Region: us-west-2
Comprehensive Mode: false
Generated: Thu Aug 14 2025
========================================

Analyzing CloudTrail configuration...
Multi-region trail 'main-trail' in us-east-1 (captures all regions)
Trail regions: us-east-1
Global events in: us-east-1

DETECTION STRATEGY:
Multi-region trail detected - all events captured centrally
   Strategy: Check trail home regions for all events

CRITICAL SECURITY CHECKS:
================================
Checking: ROOT ACCOUNT USAGE
  WARNING: FOUND 2 EVENTS - REVIEW REQUIRED
    Region us-east-1: 2 events
      2025-08-14T10:30:15+00:00 | AssumeRole | 203.0.113.1
      2025-08-13T15:22:33+00:00 | CreateAccessKey | Internal
  TOTAL: 2 events across 1 regions
```

### Simple Clean Script Output
```
========================================
CLOUDTRAIL SECURITY REVIEW
Account: 123456789012
Region: us-west-2
Generated: Thu Aug 14 2025
Period: Last 30 days
========================================

CRITICAL SECURITY CHECKS:
================================
Checking: ROOT ACCOUNT USAGE (Critical)
  WARNING: FOUND 2 EVENTS - REVIEW REQUIRED
    2025-08-14T10:30:15+00:00 | AssumeRole | 203.0.113.1
    2025-08-13T15:22:33+00:00 | CreateAccessKey | Internal

Checking: Failed Login Attempts  
  OK: No failed logins detected
```

### Result Interpretation
- **OK:** Normal activity, no action required
- **WARNING:** Events found that require review
- **CRITICAL:** Immediate investigation required
- **ERROR:** Technical issues with the scan

## Date Ranges

The script uses different time windows based on event criticality:

| Event Type | Time Range | Rationale |
|------------|------------|-----------|
| Root Account Usage | 30 days | Critical events, should be rare |
| Failed Login Attempts | 7 days | Security incidents, recent activity most relevant |
| User/Role Creation | 30 days | Identity changes, medium-term tracking |
| User/Role Deletion | 30 days | Critical changes, longer retention |
| EC2 Terminations | 7 days | High-frequency, recent activity focus |
| RDS/S3 Deletions | 30 days | Critical data operations |
| Security Group Changes | 7 days | Network security, recent changes |
| CloudTrail Tampering | 30 days | Monitoring integrity |

**Note:** CloudTrail LookupEvents API has a maximum 90-day lookback period.

## Cost Information

### AWS API Costs
- **CloudTrail LookupEvents:** ~$0.10 per 1,000 API calls
- **First 1,000 calls/month:** FREE
- **Multi-region script:** 15-50 API calls per run (depending on mode)
- **Simple clean script:** 10-15 API calls per run

### Cost Examples by Script Type

#### Multi-Region Script
| Usage Pattern | Monthly Calls | Cost |
|---------------|---------------|------|
| Daily standard scans | ~500 calls | $0.00 (free tier) |
| Daily comprehensive scans | ~1,500 calls | ~$0.05 |
| Weekly comprehensive scans | ~400 calls | $0.00 (free tier) |

#### Simple Clean Script  
| Usage Pattern | Monthly Calls | Cost |
|---------------|---------------|------|
| Daily scans | ~350 calls | $0.00 (free tier) |
| Multiple daily scans | ~700 calls | $0.00 (free tier) |
| 10 accounts, daily scans | ~3,500 calls | ~$0.25 |

**Bottom line:** Both scripts are essentially free for typical usage patterns. Simple clean script uses ~30% fewer API calls.

## Troubleshooting

### Common Issues (Both Scripts)

#### "Unable to determine AWS region"
```bash
# Solution: Set region explicitly
aws configure set region us-west-2
# OR
export AWS_DEFAULT_REGION=us-west-2
```

#### "No active CloudTrail found" (Multi-region script)
```bash
# Check CloudTrail status
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name YOUR_TRAIL_NAME
```

#### Rate limiting errors
```bash
# Multi-region script: Use single region mode
./multi_region_security_script.sh -r us-west-2

# Simple clean script: Wait 10-15 minutes between runs
./simple_clean_script.sh
```

#### Permission denied errors (Both scripts)
```bash
# Verify credentials and permissions
aws sts get-caller-identity
aws cloudtrail lookup-events --max-items 1
```

### Script-Specific Issues

#### Multi-Region Script: "All checks show errors"
**Likely cause:** Complex CloudTrail configuration not detected properly
**Solution:** Try simple clean script or specify region manually:
```bash
./multi_region_security_script.sh -r your-known-region
```

#### Simple Clean Script: "Missing events you expect to see"
**Likely cause:** Events are in a different region than your current one
**Solution:** Try multi-region script or check other regions manually:
```bash
./multi_region_security_script.sh -c
```

### Debug Mode
```bash
# Add debug output
set -x
./multi_region_security_script.sh
set +x
```

## Which Script Should You Use?

### Decision Tree

```
Do you have resources in multiple AWS regions?
├─ YES → Do you need comprehensive coverage?
│   ├─ YES → Use Multi-Region Script with -c flag
│   └─ NO → Use Multi-Region Script (standard mode)
└─ NO → Do you prioritize speed and simplicity?
    ├─ YES → Use Simple Clean Script
    └─ NO → Either script works (Simple Clean recommended)
```

### Detailed Comparison

| Your Situation | Recommended Script | Command |
|----------------|-------------------|---------|
| **Single region, development** | Simple Clean | `./simple_clean_script.sh` |
| **Single region, production** | Either (Simple Clean faster) | `./simple_clean_script.sh` |
| **Multi-region, not sure where resources are** | Multi-Region comprehensive | `./multi_region_security_script.sh -c` |
| **Multi-region, know your CloudTrail setup** | Multi-Region standard | `./multi_region_security_script.sh` |
| **Complex organization/enterprise** | Multi-Region comprehensive | `./multi_region_security_script.sh -c` |
| **Quick daily security check** | Simple Clean | `./simple_clean_script.sh` |
| **Weekly comprehensive audit** | Multi-Region comprehensive | `./multi_region_security_script.sh -c` |
| **Troubleshooting specific region** | Multi-Region with region flag | `./multi_region_security_script.sh -r us-west-2` |

### Migration Path
**Start simple, scale up as needed:**
1. **Begin with Simple Clean Script** for daily monitoring
2. **Add Multi-Region Script** when you expand to multiple regions
3. **Use comprehensive mode** for periodic deep audits

### Scenario 1: Single-Region Trail
**Setup:** CloudTrail enabled in us-west-2 only  
**Script behavior:** Checks us-west-2 for all events  
**Coverage:** Regional events only (may miss some global events)

### Scenario 2: Multi-Region Trail  
**Setup:** Trail in us-east-1 with multi-region enabled  
**Script behavior:** Checks us-east-1 for all events worldwide  
**Coverage:** Complete global coverage

### Scenario 3: Multiple Trails
**Setup:** Trails in us-east-1 and eu-west-1  
**Script behavior:** Checks both regions  
**Coverage:** Complete for both regions

### Scenario 4: Distributed Resources
**Setup:** Resources across multiple regions, single-region trail  
**Script behavior:** With `-c` flag, scans all resource regions  
**Coverage:** Complete with comprehensive mode

## Security Considerations

### Data Privacy
- Script only reads CloudTrail metadata
- No sensitive data is stored or transmitted
- All analysis performed locally

### Access Control  
- Requires read-only CloudTrail permissions
- Cannot modify any AWS resources
- Safe to run in production environments

### Audit Trail
- Script execution doesn't generate CloudTrail events
- Uses read-only AWS APIs
- Maintains compliance with monitoring requirements

## Best Practices

### Frequency Recommendations

#### Simple Clean Script
- **Development accounts:** Daily scans
- **Single-region production:** Daily scans  
- **Testing environments:** Weekly scans

#### Multi-Region Script
- **Multi-region production:** Daily standard, weekly comprehensive
- **Enterprise environments:** Daily comprehensive  
- **Compliance audits:** Comprehensive mode as needed
- **Post-incident analysis:** Immediate comprehensive scan

### Integration Examples

#### Simple Clean Script
```bash
# Daily cron job
0 8 * * * /path/to/simple_clean_script.sh > /var/log/aws-security-$(date +\%Y\%m\%d).log

# Quick Slack alert for critical findings
./simple_clean_script.sh | grep -q "CRITICAL" && curl -X POST $SLACK_WEBHOOK -d "Security alert in $(aws configure get region)"
```

#### Multi-Region Script
```bash
# Weekly comprehensive review
0 8 * * 1 /path/to/multi_region_security_script.sh -c > /var/log/aws-security-comprehensive-$(date +\%Y\%m\%d).log

# Daily smart scan with email report
./multi_region_security_script.sh | mail -s "AWS Security Review $(date)" security@company.com

# Multi-account scanning
for account in prod staging dev; do
  aws-vault exec $account -- ./multi_region_security_script.sh -c
done
```


### Feature Requests
- Additional event types to monitor
- Integration with other AWS services
- Output format improvements

## Changelog

### v2.0 (Current)
**Two Script Options:**
- **Multi-Region Script:** Advanced version with intelligent multi-region support
- **Simple Clean Script:** Streamlined version for single-region deployments

**New Features:**
- Multi-region resource detection
- Eliminated hardcoded regions (works in GovCloud, China, etc.)
- Enhanced error handling and retry logic
- Comprehensive mode for distributed deployments
- Simplified alternative for faster execution

**Improvements:**
- Region auto-detection works in all AWS partitions
- Better CloudTrail configuration analysis
- Reduced API costs with smart querying
- Professional emoji-free output

### v1.0
- Basic CloudTrail event scanning
- Single-region focus
- Core security event detection

