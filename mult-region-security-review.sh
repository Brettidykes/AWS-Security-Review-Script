#!/bin/bash

# Multi-Region CloudTrail Security Review Script

# Detect region without hardcoding us-east-1
detect_current_region() {
    # Method 1: AWS CLI configuration
    local region=$(aws configure get region 2>/dev/null)
    if [ -n "$region" ]; then
        echo "$region"
        return
    fi
    
    # Method 2: Environment variable
    if [ -n "$AWS_DEFAULT_REGION" ]; then
        echo "$AWS_DEFAULT_REGION"
        return
    fi
    
    # Method 3: EC2 metadata (if running on EC2)
    if command -v curl >/dev/null 2>&1; then
        region=$(curl -s --max-time 2 http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null)
        if [ -n "$region" ] && [ "$region" != "404" ]; then
            echo "$region"
            return
        fi
    fi
    
    # Method 4: Try to determine from STS call (without specifying region)
    region=$(aws sts get-caller-identity --query 'Arn' --output text 2>/dev/null | grep -o 'arn:aws[^:]*:sts::[^:]*:' | sed 's/.*sts::\([^:]*\):.*/\1/')
    if [ -n "$region" ]; then
        echo "$region"
        return
    fi
    
    # Method 5: Get any available region from EC2 (let AWS CLI figure out the endpoint)
    region=$(aws ec2 describe-regions --query 'Regions[0].RegionName' --output text 2>/dev/null)
    if [ -n "$region" ] && [ "$region" != "None" ]; then
        echo "$region"
        return
    fi
    
    # Last resort: This should rarely happen, but if it does, we can't proceed
    echo ""
}

CURRENT_REGION=$(detect_current_region)

if [ -z "$CURRENT_REGION" ]; then
    echo "ERROR: Unable to determine AWS region. Please set it manually:"
    echo "  aws configure set region YOUR_REGION"
    echo "  export AWS_DEFAULT_REGION=YOUR_REGION"
    exit 1
fi

export AWS_DEFAULT_REGION="$CURRENT_REGION"

COMPREHENSIVE_MODE=${COMPREHENSIVE_MODE:-"false"}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--comprehensive)
            COMPREHENSIVE_MODE="true"
            shift
            ;;
        -r|--region)
            CURRENT_REGION="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -c, --comprehensive    Check all regions with resources (slower but thorough)"
            echo "  -r, --region REGION   Set primary region"
            echo "  -h, --help           Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                    # Smart mode - check CloudTrail regions"
            echo "  $0 -c                 # Comprehensive - check all resource regions"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h for help"
            exit 1
            ;;
    esac
done

echo "========================================"
echo "MULTI-REGION CLOUDTRAIL SECURITY REVIEW"
echo "Account: $(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo 'Unable to determine')"
echo "Primary Region: $CURRENT_REGION"
echo "Comprehensive Mode: $COMPREHENSIVE_MODE"
echo "Generated: $(date)"
echo "========================================"
echo ""

# Function to get date
get_start_time() {
    local days_ago="$1"
    if date -d "1 day ago" >/dev/null 2>&1; then
        date -d "$days_ago days ago" --iso-8601
    else
        date -v-${days_ago}d +%Y-%m-%dT%H:%M:%S
    fi
}

# Function to detect CloudTrail configuration
detect_cloudtrail_config() {
    echo "Analyzing CloudTrail configuration..."
    
    # Get all trails with their configuration
    local trail_info
    trail_info=$(aws cloudtrail describe-trails \
        --query 'trailList[?IsLogging==`true`].[Name,HomeRegion,IsMultiRegionTrail,IncludeGlobalServiceEvents]' \
        --output text 2>/dev/null)
    
    if [ -z "$trail_info" ]; then
        echo "WARNING: No active CloudTrail found"
        return 1
    fi
    
    local has_multi_region=false
    local trail_regions=()
    local global_event_regions=()
    
    while IFS=$'\t' read -r name home_region is_multi_region include_global; do
        if [ -n "$home_region" ]; then
            trail_regions+=("$home_region")
            
            if [ "$is_multi_region" = "True" ]; then
                has_multi_region=true
                echo "Multi-region trail '$name' in $home_region (captures all regions)"
            else
                echo "Single-region trail '$name' in $home_region"
            fi
            
            if [ "$include_global" = "True" ]; then
                global_event_regions+=("$home_region")
            fi
        fi
    done <<< "$trail_info"
    
    # Export for use by other functions
    export TRAIL_REGIONS=$(printf '%s\n' "${trail_regions[@]}" | sort -u | tr '\n' ' ')
    export GLOBAL_EVENT_REGIONS=$(printf '%s\n' "${global_event_regions[@]}" | sort -u | tr '\n' ' ')
    export HAS_MULTI_REGION="$has_multi_region"
    
    echo "Trail regions: $TRAIL_REGIONS"
    echo "Global events in: $GLOBAL_EVENT_REGIONS"
    echo ""
}

# Function to detect regions with resources
detect_resource_regions() {
    if [ "$COMPREHENSIVE_MODE" = "false" ]; then
        return
    fi
    
    echo "Scanning for resources across all regions..."
    local resource_regions=()
    
    # Get list of available regions using current region as base
    local all_regions
    all_regions=$(aws ec2 describe-regions --region "$CURRENT_REGION" --query 'Regions[].RegionName' --output text 2>/dev/null)
    
    if [ -z "$all_regions" ]; then
        echo "WARNING: Could not retrieve region list, using current region only: $CURRENT_REGION"
        export RESOURCE_REGIONS="$CURRENT_REGION"
        return
    fi
    
    # Limit to reasonable number to avoid timeout
    local regions_to_check
    regions_to_check=$(echo "$all_regions" | tr '\t' '\n' | head -10)
    
    for region in $regions_to_check; do
        # Quick check for any resources in this region
        local has_resources=false
        
        # Check for EC2 instances (quick indicator of regional activity)
        if aws ec2 describe-instances --region "$region" --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null | grep -q "i-"; then
            has_resources=true
        fi
        
        # Check for RDS instances
        if [ "$has_resources" = "false" ]; then
            if aws rds describe-db-instances --region "$region" --query 'DBInstances[0].DBInstanceIdentifier' --output text 2>/dev/null | grep -v "None"; then
                has_resources=true
            fi
        fi
        
        if [ "$has_resources" = "true" ]; then
            resource_regions+=("$region")
            echo "Found resources in $region"
        fi
        
        # Small delay to avoid rate limiting
        sleep 0.2
    done
    
    if [ "${#resource_regions[@]}" -eq 0 ]; then
        echo "No resources detected, using current region: $CURRENT_REGION"
        resource_regions+=("$CURRENT_REGION")
    fi
    
    export RESOURCE_REGIONS=$(printf '%s\n' "${resource_regions[@]}" | sort -u | tr '\n' ' ')
    echo "Resource regions: $RESOURCE_REGIONS"
    echo ""
}

# Function to determine which regions to check for specific event types
get_regions_for_event_type() {
    local event_type="$1"  # "global" or "regional"
    
    if [ "$event_type" = "global" ]; then
        if [ -n "$GLOBAL_EVENT_REGIONS" ]; then
            echo "$GLOBAL_EVENT_REGIONS"
        else
            echo "$CURRENT_REGION"
        fi
    else
        # For regional events
        if [ "$HAS_MULTI_REGION" = "true" ]; then
            # Multi-region trail captures everything in its home region
            echo "$TRAIL_REGIONS"
        elif [ "$COMPREHENSIVE_MODE" = "true" ] && [ -n "$RESOURCE_REGIONS" ]; then
            # Check regions where we found resources
            echo "$RESOURCE_REGIONS"
        else
            # Check trail regions and current region
            echo "$TRAIL_REGIONS $CURRENT_REGION" | tr ' ' '\n' | sort -u | tr '\n' ' '
        fi
    fi
}

# Enhanced security check function
run_security_check() {
    local event_name="$1"
    local username="$2"
    local description="$3"
    local days="${4:-30}"
    local event_type="${5:-regional}"  # "global" or "regional"
    
    echo "Checking: $description"
    
    local regions_to_check
    regions_to_check=$(get_regions_for_event_type "$event_type")
    
    if [ "$COMPREHENSIVE_MODE" = "true" ]; then
        echo "  Regions to check: $regions_to_check"
    fi
    
    local start_time
    start_time=$(get_start_time "$days")
    local total_events=0
    local regions_with_events=()
    
    for region in $regions_to_check; do
        local EVENTS
        if [ -n "$username" ]; then
            EVENTS=$(aws cloudtrail lookup-events \
                --region "$region" \
                --lookup-attributes AttributeKey=Username,AttributeValue="$username" \
                --start-time "$start_time" \
                --max-items 15 \
                --query 'Events' --output json 2>/dev/null)
        else
            EVENTS=$(aws cloudtrail lookup-events \
                --region "$region" \
                --lookup-attributes AttributeKey=EventName,AttributeValue="$event_name" \
                --start-time "$start_time" \
                --max-items 15 \
                --query 'Events' --output json 2>/dev/null)
        fi
        
        if [ $? -eq 0 ] && [ -n "$EVENTS" ] && [ "$EVENTS" != "null" ] && [ "$EVENTS" != "[]" ]; then
            local COUNT
            COUNT=$(echo "$EVENTS" | jq -r 'length' 2>/dev/null || echo "0")
            
            if [ "$COUNT" -gt 0 ]; then
                regions_with_events+=("$region:$COUNT")
                total_events=$((total_events + COUNT))
                
                if [ "${#regions_with_events[@]}" -eq 1 ]; then
                    echo "  WARNING: FOUND EVENTS - REVIEW REQUIRED"
                fi
                
                echo "    Region $region: $COUNT events"
                echo "$EVENTS" | jq -r '.[] | "      \(.EventTime) | \(.Username // "N/A") | \(.SourceIPAddress // "Internal")"' 2>/dev/null | head -2
                
                if [ "$COUNT" -gt 2 ]; then
                    echo "      ... and $((COUNT - 2)) more events in this region"
                fi
            fi
        fi
        
        # Delay between regions
        sleep 0.3
    done
    
    if [ "$total_events" -eq 0 ]; then
        echo "  OK: No events found"
    else
        echo "  TOTAL: $total_events events across ${#regions_with_events[@]} regions"
    fi
    echo ""
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

# Analyze configuration
detect_cloudtrail_config
if [ "$COMPREHENSIVE_MODE" = "true" ]; then
    detect_resource_regions
fi

# Determine strategy
echo "DETECTION STRATEGY:"
if [ "$HAS_MULTI_REGION" = "true" ]; then
    echo "Multi-region trail detected - all events captured centrally"
    echo "   Strategy: Check trail home regions for all events"
elif [ "$COMPREHENSIVE_MODE" = "true" ]; then
    echo "Comprehensive mode - checking all regions with resources"
    echo "   Strategy: Check each region where resources exist"
else
    echo "Smart mode - checking CloudTrail regions"
    echo "   Strategy: Check configured trail regions"
    echo "   TIP: Use -c flag for comprehensive multi-region scan"
fi
echo ""

echo "CRITICAL SECURITY CHECKS:"
echo "================================"

# Root account (global events)
run_security_check "" "root" "ROOT ACCOUNT USAGE" 30 "global"

# Failed logins (global events)
echo "Checking: Failed Login Attempts"
for region in $(get_regions_for_event_type "global"); do
    LOGIN_EVENTS=$(aws cloudtrail lookup-events \
        --region "$region" \
        --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
        --start-time $(get_start_time 7) \
        --max-items 20 \
        --query 'Events' --output json 2>/dev/null)

    if [ $? -eq 0 ] && [ -n "$LOGIN_EVENTS" ] && [ "$LOGIN_EVENTS" != "null" ] && [ "$LOGIN_EVENTS" != "[]" ]; then
        FAILED=$(echo "$LOGIN_EVENTS" | jq '[.[] | select(.CloudTrailEvent | contains("SigninFailure"))]' 2>/dev/null)
        FAILED_COUNT=$(echo "$FAILED" | jq -r 'length' 2>/dev/null || echo "0")
        
        if [ "$FAILED_COUNT" -gt 0 ]; then
            echo "  CRITICAL: $FAILED_COUNT failed logins in $region"
            echo "$FAILED" | jq -r '.[] | "    \(.EventTime) | \(.SourceIPAddress // "Unknown")"' 2>/dev/null
        else
            echo "  OK: No failed logins in $region"
        fi
        break
    fi
done
echo ""

echo "IDENTITY & ACCESS MANAGEMENT:"
echo "================================"

run_security_check "CreateUser" "" "New User Creation" 30 "global"
run_security_check "DeleteUser" "" "User Deletions" 30 "global"
run_security_check "CreateRole" "" "New Role Creation" 7 "global"

echo "RESOURCE MANAGEMENT:"
echo "================================"

run_security_check "TerminateInstances" "" "EC2 Instance Terminations" 7 "regional"
run_security_check "DeleteDBInstance" "" "RDS Database Deletions" 30 "regional"
run_security_check "DeleteBucket" "" "S3 Bucket Deletions" 30 "regional"

echo "SECURITY CHANGES:"
echo "================================"

run_security_check "AuthorizeSecurityGroupIngress" "" "Security Group Changes" 7 "regional"
run_security_check "StopLogging" "" "CloudTrail Logging Disabled" 30 "regional"

echo "========================================"
echo "ANALYSIS COMPLETE"
echo ""
echo "COVERAGE SUMMARY:"
if [ "$HAS_MULTI_REGION" = "true" ]; then
    echo "Complete coverage - multi-region trail captures all events"
elif [ "$COMPREHENSIVE_MODE" = "true" ]; then
    echo "Comprehensive scan across resource regions"
else
    echo "Limited to CloudTrail regions: $TRAIL_REGIONS"
    echo "TIP: Run with -c flag to scan all regions with resources"
fi
echo ""
echo "ACTION ITEMS:"
echo "1. Investigate any CRITICAL findings immediately"
echo "2. Review WARNING items for legitimacy"
echo "3. Verify auto-scaling events are expected"
if [ "$HAS_MULTI_REGION" = "false" ] && [ "$COMPREHENSIVE_MODE" = "false" ]; then
    echo "4. Consider running with -c flag for complete coverage"
fi
echo "========================================"
