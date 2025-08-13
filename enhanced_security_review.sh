cat > enhanced_security_review.sh << 'EOF'
#!/bin/bash

echo "========================================"
echo "ENHANCED CLOUDTRAIL SECURITY REVIEW"
echo "Account: $(aws sts get-caller-identity --query Account --output text)"
echo "Region: $(aws configure get region || echo 'Not set')"
echo "Generated: $(date)"
echo "Period: Last 30 days"
echo "========================================"
echo ""

# Function to run check with simpler error handling
run_security_check() {
    local event_name="$1"
    local username="$2"
    local description="$3"
    local days="${4:-30}"
    
    echo "Checking: $description"
    
    if [ -n "$username" ]; then
        # Username-based lookup
        EVENTS=$(aws cloudtrail lookup-events \
            --lookup-attributes AttributeKey=Username,AttributeValue="$username" \
            --start-time $(date -d "$days days ago" --iso-8601) \
            --query 'Events' --output json)
    else
        # Event name-based lookup
        EVENTS=$(aws cloudtrail lookup-events \
            --lookup-attributes AttributeKey=EventName,AttributeValue="$event_name" \
            --start-time $(date -d "$days days ago" --iso-8601) \
            --query 'Events' --output json)
    fi
    
    if [ $? -ne 0 ]; then
        echo "  WARNING: Error querying events for $description"
        echo ""
        return
    fi
    
    COUNT=$(echo "$EVENTS" | jq length)
    
    if [ "$COUNT" -gt 0 ]; then
        echo "  WARNING: FOUND $COUNT EVENTS - REVIEW REQUIRED"
        echo "$EVENTS" | jq -r '.[] | "    \(.EventTime) | \(.Username // "N/A") | \(.SourceIPAddress // "Internal")"' | head -5
        if [ "$COUNT" -gt 5 ]; then
            echo "    ... and $((COUNT - 5)) more events"
        fi
    else
        echo "  OK: No events found"
    fi
    echo ""
}

# Special function for failed logins
check_failed_logins() {
    echo "Checking: Failed Login Attempts (Critical)"
    
    LOGIN_EVENTS=$(aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
        --start-time $(date -d "7 days ago" --iso-8601) \
        --query 'Events' --output json)
    
    if [ $? -ne 0 ]; then
        echo "  WARNING: Error querying login events"
        echo ""
        return
    fi
    
    # Extract failed logins
    FAILED=$(echo "$LOGIN_EVENTS" | jq '[.[] | select(.CloudTrailEvent | contains("SigninFailure"))]')
    FAILED_COUNT=$(echo "$FAILED" | jq length)
    
    if [ "$FAILED_COUNT" -gt 0 ]; then
        echo "  CRITICAL: FOUND $FAILED_COUNT FAILED LOGIN ATTEMPTS - IMMEDIATE REVIEW REQUIRED"
        echo "$FAILED" | jq -r '.[] | "    \(.EventTime) | Failed login from \(.SourceIPAddress // "Unknown IP")"' | head -5
    else
        echo "  OK: No failed logins"
    fi
    echo ""
}

echo "CRITICAL SECURITY CHECKS:"
echo "================================"

# Most critical checks first
run_security_check "" "root" "ROOT ACCOUNT USAGE"
check_failed_logins

echo "AUTHENTICATION & ACCESS:"
echo "================================"

run_security_check "ConsoleLogin" "" "Console Login Activity (Last 7 days)" 7

echo "IDENTITY & ACCESS MANAGEMENT:"
echo "================================"

run_security_check "PutUserPolicy" "" "IAM Policy Modifications"
run_security_check "AttachUserPolicy" "" "IAM Policy Attachments"
run_security_check "CreateUser" "" "New User Creation"
run_security_check "DeleteUser" "" "User Deletions"
run_security_check "CreateRole" "" "New Role Creation"
run_security_check "DeleteRole" "" "Role Deletions"

echo "NETWORK & SECURITY:"
echo "================================"

run_security_check "AuthorizeSecurityGroupIngress" "" "Security Group Ingress Changes"
run_security_check "AuthorizeSecurityGroupEgress" "" "Security Group Egress Changes"
run_security_check "RevokeSecurityGroupIngress" "" "Security Group Ingress Revocations"

echo "RESOURCE MANAGEMENT:"
echo "================================"

run_security_check "TerminateInstances" "" "EC2 Instance Terminations"
run_security_check "DeleteDBInstance" "" "RDS Database Deletions"
run_security_check "DeleteBucket" "" "S3 Bucket Deletions"

echo "MONITORING & LOGGING:"
echo "================================"

run_security_check "StopLogging" "" "CloudTrail Logging Disabled"
run_security_check "DeleteTrail" "" "CloudTrail Deletion"

echo "========================================"
echo "REVIEW COMPLETE"
echo ""
echo "PRIORITY ACTIONS:"
echo "1. Investigate any ROOT ACCOUNT usage immediately"
echo "2. Review all FAILED LOGIN attempts"
echo "3. Verify legitimacy of DELETIONS and TERMINATIONS"
echo ""
echo "Legend:"
echo "OK: Items marked OK are normal"
echo "WARNING: Items marked for review should be investigated"
echo "CRITICAL: Items require immediate attention"
echo "========================================"
EOF

chmod +x enhanced_security_review.sh
