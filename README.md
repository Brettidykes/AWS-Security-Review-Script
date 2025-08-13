# AWS-Security-Review-Script

A comprehensive bash script for analyzing AWS CloudTrail logs to detect suspicious security activities across your AWS environment.

## Overview

This script performs automated security analysis of CloudTrail events to identify potential security threats, policy violations, and suspicious activities. It's designed for monthly security reviews and can be run directly in AWS CloudShell.

## Prerequisites

- AWS CLI configured with appropriate permissions
- Access to CloudTrail Event History API
- `jq` installed (available by default in AWS CloudShell)
- CloudTrail enabled in your AWS account

## Required Permissions

The script requires the following IAM permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudtrail:LookupEvents",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

## Installation

1. Clone this repository or download the script
2. Make the script executable:
   ```bash
   chmod +x enhanced_security_review.sh
   ```

## Usage

### AWS CloudShell (Recommended)
1. Open AWS CloudShell from the AWS Console
2. Upload or create the script file
3. Run the script:
   ```bash
   ./enhanced_security_review.sh
   ```

### Local Environment
1. Ensure AWS CLI is configured with proper credentials
2. Set your target region:
   ```bash
   aws configure set region us-east-1
   ```
3. Run the script:
   ```bash
   ./enhanced_security_review.sh
   ```

## Security Checks Performed

### Critical Security Checks
- **Root Account Usage**: Detects any root account activity (should be zero)
- **Failed Login Attempts**: Identifies brute force or unauthorized access attempts

### Identity & Access Management
- IAM policy modifications and attachments
- User creation and deletion events
- Role creation and deletion events
- Group membership changes

### Network & Security
- Security group rule changes (ingress/egress)
- VPC creation and deletion events
- Network access control modifications

### Resource Management
- EC2 instance terminations and stops
- RDS database deletions
- S3 bucket deletions
- EBS volume deletions

### Monitoring & Logging
- CloudTrail logging disabled events
- CloudTrail deletion attempts

## Output Interpretation

### Status Indicators
- **OK**: No suspicious events found - normal operation
- **WARNING**: Events found that require review and verification
- **CRITICAL**: Events found that require immediate investigation

### Event Details
For each flagged event, the script displays:
- Timestamp of the event
- Username or service that performed the action
- Source IP address (or "Internal" for AWS service calls)

## Sample Output

```
========================================
ENHANCED CLOUDTRAIL SECURITY REVIEW
Account: 123456789012
Region: us-east-1
Generated: Wed Aug 13 18:30:00 UTC 2025
Period: Last 30 days
========================================

CRITICAL SECURITY CHECKS:
================================
Checking: ROOT ACCOUNT USAGE
  OK: No events found

Checking: Failed Login Attempts (Critical)
  OK: No failed logins

IDENTITY & ACCESS MANAGEMENT:
================================
Checking: IAM Policy Modifications
  WARNING: FOUND 2 EVENTS - REVIEW REQUIRED
    2025-08-10T14:30:20+00:00 | admin.user@company.com | 203.0.113.1
    2025-08-08T09:15:45+00:00 | admin.user@company.com | 203.0.113.1
```

## Best Practices

1. **Run Monthly**: Execute this script as part of your monthly security review process
2. **Multi-Region Analysis**: Run the script in each AWS region where you have resources
3. **Document Findings**: Keep records of legitimate activities to establish baselines
4. **Investigate Anomalies**: Always verify the business justification for flagged events
5. **Time-Based Analysis**: Pay special attention to off-hours administrative activities

## Limitations

- **90-Day History**: CloudTrail Event History API is limited to the last 90 days
- **Region-Specific**: Events are analyzed only for the currently configured AWS region
- **API Rate Limits**: The script includes timeout protection but may need to be re-run if rate limited
- **Event Volume**: High-activity accounts may experience timeouts on certain queries

## Troubleshooting

### "Error querying events"
- Verify CloudTrail is enabled in your account and region
- Check that your AWS credentials have the required permissions
- Ensure you're in the correct AWS region

### Script Hangs or Times Out
- The script includes 30-second timeouts for each query
- High-activity accounts may need manual investigation of specific event types
- Consider analyzing shorter time periods for busy environments

### No Events Found for Expected Activities
- Verify the time period (script analyzes last 30 days by default)
- Check that you're analyzing the correct AWS region
- Confirm CloudTrail is capturing the event types you're looking for


## Security Notice

This script is designed for security analysis and should be run by authorized personnel only. Always follow your organization's security policies and procedures when analyzing CloudTrail logs.
