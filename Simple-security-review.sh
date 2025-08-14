#!/bin/bash

# Simple CloudTrail Security Review Script - Clean Version

# Detect current region
CURRENT_REGION=$(aws configure get region 2>/dev/null)
if [ -z "$CURRENT_REGION" ]; then
    if [ -n "$AWS_DEFAULT_REGION" ]; then
        CURRENT_REGION="$AWS_DEFAULT_REGION"
    else
        # Try to get any available region
        CURRENT_REGION=$(aws ec2 describe-regions --query 'Regions[0].RegionName' --output text 2>/dev/null)
        if [ -z "$CURRENT_REGION" ] || [ "$CURRENT_REGION" = "None" ]; then
            echo "ERROR: Cannot determine AWS region. Please set:"
            echo "  aws configure set region YOUR_REGION"
            exit 1
        fi
    fi
fi

export AWS_DEFAULT_REGION="$CURRENT_REGION"

echo "========================================"
echo "CLOUDTRAIL SECURITY REVIEW"
echo "Account: $(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo 'Unknown')"
echo "Region: $CURRENT_REGION"
echo "Generated: $(date)"
echo "Period: Last 30 days"
echo "========================================"
echo ""

# Function to get start time
get_start_time() {
    local days_ago="$1"
    if date -d "1 day ago" >/dev/null 2>&1; then
        date -d "$days_ago days ago" --iso-8601
    else
        date -v-${days_ago}d +%Y-%m-%dT%H:%M:%S
    fi
}

# Function to check events
check_events() {
    local event_name="$1"
    local username="$2"
    local description="$3"
    local days="${4:-30}"
    local region="${5:-$CURRENT_REGION}"
    
    echo "Checking: $description"
    
    local start_time=$(get_start_time "$days")
    local EVENTS
    
    if [ -n "$username" ]; then
        EVENTS=$(aws cloudtrail lookup-events \
            --region "$region" \
            --lookup-attributes AttributeKey=Username,AttributeValue="$username" \
            --start-time "$start_time" \
            --max-items 20 \
            --query 'Events' --output json 2>/dev/null)
    else
        EVENTS=$(aws cloudtrail lookup-events \
            --region "$region" \
            --lookup-attributes AttributeKey=EventName,AttributeValue="$event_name" \
            --start-time "$start_time" \
            --max-items 20 \
            --query 'Events' --output json 2>/dev/null)
    fi
    
    if [ $? -ne 0 ] || [ -z "$EVENTS" ] || [ "$EVENTS" = "null" ] || [ "$EVENTS" = "[]" ]; then
        echo "  OK: No events found"
    else
        local COUNT=$(echo "$EVENTS" | jq -r 'length' 2>/dev/null || echo "0")
        
        if [ "$COUNT" -gt 0 ]; then
            echo "  WARNING: FOUND $COUNT EVENTS - REVIEW REQUIRED"
            echo "$EVENTS" | jq -r '.[] | "    \(.EventTime) | \(.Username // "N/A") | \(.SourceIPAddress // "Internal")"' 2>/dev/null | head -5
            if [ "$COUNT" -gt 5 ]; then
                echo "    ... and $((COUNT - 5)) more events"
            fi
        else
            echo "  OK: No events found"
        fi
    fi
    echo ""
    sleep 0.5
}

# Check prerequisites
if ! command -v aws >/dev/null 2>&1; then
    echo "ERROR: AWS CLI not found"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq not found"  
    exit 1
fi

echo "CRITICAL SECURITY CHECKS:"
echo "================================"

# Root account usage
check_events "" "root" "ROOT ACCOUNT USAGE (Critical)" 30

# Failed logins
echo "Checking: Failed Login Attempts"
LOGIN_EVENTS=$(aws cloudtrail lookup-events \
    --region "$CURRENT_REGION" \
    --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
    --start-time $(get_start_time 7) \
    --max-items 20 \
    --query 'Events' --output json 2>/dev/null)

if [ $? -eq 0 ] && [ -n "$LOGIN_EVENTS" ] && [ "$LOGIN_EVENTS" != "null" ] && [ "$LOGIN_EVENTS" != "[]" ]; then
    FAILED=$(echo "$LOGIN_EVENTS" | jq '[.[] | select(.CloudTrailEvent | contains("SigninFailure"))]' 2>/dev/null)
    FAILED_COUNT=$(echo "$FAILED" | jq -r 'length' 2>/dev/null || echo "0")
    
    if [ "$FAILED_COUNT" -gt 0 ]; then
        echo "  CRITICAL: FOUND $FAILED_COUNT FAILED LOGIN ATTEMPTS"
        echo "$FAILED" | jq -r '.[] | "    \(.EventTime) | Failed login from \(.SourceIPAddress // "Unknown IP")"' 2>/dev/null
    else
        echo "  OK: No failed logins detected"
    fi
else
    echo "  OK: No login events found"
fi
echo ""

echo "IDENTITY MANAGEMENT:"
echo "================================"

check_events "CreateUser" "" "New User Creation" 30
check_events "DeleteUser" "" "User Deletions" 30  
check_events "CreateRole" "" "New Role Creation" 7

echo "RESOURCE MANAGEMENT:"
echo "================================"

check_events "TerminateInstances" "" "EC2 Instance Terminations" 7
check_events "DeleteDBInstance" "" "RDS Database Deletions" 30
check_events "DeleteBucket" "" "S3 Bucket Deletions" 30

echo "SECURITY MONITORING:"
echo "================================"

check_events "AuthorizeSecurityGroupIngress" "" "Security Group Changes" 7
check_events "StopLogging" "" "CloudTrail Logging Disabled" 30

echo "========================================"
echo "SECURITY REVIEW COMPLETE"
echo ""
echo "ACTION ITEMS:"
echo "1. Investigate any CRITICAL or WARNING findings"
echo "2. Verify legitimate business activities"
echo "3. Review auto-scaling terminations for expected behavior"
echo ""
echo "Note: This script checks region '$CURRENT_REGION'"
echo "For multi-region analysis, run in each region with resources"
echo "========================================"
