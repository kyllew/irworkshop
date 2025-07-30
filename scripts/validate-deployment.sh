#!/bin/bash

# AWS Threat Intelligence Analyzer - Deployment Validation Script

set -e

# Configuration
INFRASTRUCTURE_STACK="threat-analyzer-infrastructure"
CICD_STACK="threat-analyzer-cicd"
REGION="us-east-1"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[ℹ]${NC} $1"
}

# Function to check if stack exists and is healthy
check_stack() {
    local stack_name="$1"
    local stack_status
    
    print_info "Checking stack: $stack_name"
    
    if aws cloudformation describe-stacks --stack-name "$stack_name" --region "$REGION" &> /dev/null; then
        stack_status=$(aws cloudformation describe-stacks \
            --stack-name "$stack_name" \
            --region "$REGION" \
            --query 'Stacks[0].StackStatus' \
            --output text)
        
        case "$stack_status" in
            "CREATE_COMPLETE"|"UPDATE_COMPLETE")
                print_status "Stack $stack_name is healthy ($stack_status)"
                return 0
                ;;
            "CREATE_IN_PROGRESS"|"UPDATE_IN_PROGRESS")
                print_warning "Stack $stack_name is updating ($stack_status)"
                return 1
                ;;
            *)
                print_error "Stack $stack_name has issues ($stack_status)"
                return 1
                ;;
        esac
    else
        print_error "Stack $stack_name does not exist"
        return 1
    fi
}

# Function to get stack output
get_stack_output() {
    local stack_name="$1"
    local output_key="$2"
    
    aws cloudformation describe-stacks \
        --stack-name "$stack_name" \
        --region "$REGION" \
        --query "Stacks[0].Outputs[?OutputKey=='$output_key'].OutputValue" \
        --output text
}

# Function to test HTTP endpoint
test_endpoint() {
    local url="$1"
    local expected_status="${2:-200}"
    
    print_info "Testing endpoint: $url"
    
    local response_code
    response_code=$(curl -s -o /dev/null -w "%{http_code}" "$url" --max-time 10 --insecure)
    
    if [ "$response_code" = "$expected_status" ]; then
        print_status "Endpoint $url returned $response_code"
        return 0
    else
        print_error "Endpoint $url returned $response_code (expected $expected_status)"
        return 1
    fi
}

# Function to check ECS service
check_ecs_service() {
    local cluster_name="$1"
    local service_name="$2"
    
    print_info "Checking ECS service: $service_name in cluster: $cluster_name"
    
    local running_count
    local desired_count
    
    running_count=$(aws ecs describe-services \
        --cluster "$cluster_name" \
        --services "$service_name" \
        --region "$REGION" \
        --query 'services[0].runningCount' \
        --output text)
    
    desired_count=$(aws ecs describe-services \
        --cluster "$cluster_name" \
        --services "$service_name" \
        --region "$REGION" \
        --query 'services[0].desiredCount' \
        --output text)
    
    if [ "$running_count" = "$desired_count" ] && [ "$running_count" -gt 0 ]; then
        print_status "ECS service is healthy ($running_count/$desired_count tasks running)"
        return 0
    else
        print_error "ECS service has issues ($running_count/$desired_count tasks running)"
        return 1
    fi
}

# Function to check ALB target health
check_alb_targets() {
    local target_group_arn="$1"
    
    print_info "Checking ALB target group health"
    
    local healthy_targets
    healthy_targets=$(aws elbv2 describe-target-health \
        --target-group-arn "$target_group_arn" \
        --region "$REGION" \
        --query 'TargetHealthDescriptions[?TargetHealth.State==`healthy`]' \
        --output json | jq length)
    
    if [ "$healthy_targets" -gt 0 ]; then
        print_status "ALB has $healthy_targets healthy targets"
        return 0
    else
        print_error "ALB has no healthy targets"
        return 1
    fi
}

# Function to validate application functionality
validate_application() {
    local alb_dns="$1"
    
    print_info "Validating application functionality"
    
    # Try HTTPS first, then HTTP
    local base_url="https://$alb_dns"
    local protocol="HTTPS"
    
    # Test health endpoint with HTTPS
    if ! test_endpoint "$base_url/health" 200; then
        print_info "HTTPS failed, trying HTTP..."
        base_url="http://$alb_dns"
        protocol="HTTP"
        
        if ! test_endpoint "$base_url/health" 200; then
            print_error "Health check failed on both HTTP and HTTPS"
            return 1
        fi
    fi
    
    print_status "Health check passed ($protocol)"
    
    # Test main dashboard
    if test_endpoint "$base_url/" 200; then
        print_status "Dashboard accessible ($protocol)"
    else
        print_error "Dashboard not accessible"
        return 1
    fi
    
    # Test API endpoint
    if test_endpoint "$base_url/api/database/stats" 200; then
        print_status "API endpoint accessible ($protocol)"
    else
        print_error "API endpoint not accessible"
        return 1
    fi
    
    print_info "Application URL: $base_url"
    return 0
}

# Main validation function
main() {
    echo "AWS Threat Intelligence Analyzer - Deployment Validation"
    echo "========================================================"
    echo
    
    local validation_failed=0
    
    # Check infrastructure stack
    if check_stack "$INFRASTRUCTURE_STACK"; then
        print_status "Infrastructure stack validation passed"
        
        # Get infrastructure outputs
        ALB_DNS=$(get_stack_output "$INFRASTRUCTURE_STACK" "LoadBalancerDNS")
        ECS_CLUSTER=$(get_stack_output "$INFRASTRUCTURE_STACK" "ECSClusterName")
        ECS_SERVICE=$(get_stack_output "$INFRASTRUCTURE_STACK" "ECSServiceName")
        
        print_info "ALB DNS: $ALB_DNS"
        print_info "ECS Cluster: $ECS_CLUSTER"
        print_info "ECS Service: $ECS_SERVICE"
        
        # Check ECS service
        if check_ecs_service "$ECS_CLUSTER" "$ECS_SERVICE"; then
            print_status "ECS service validation passed"
        else
            print_error "ECS service validation failed"
            validation_failed=1
        fi
        
        # Test application endpoints
        if [ -n "$ALB_DNS" ]; then
            if validate_application "$ALB_DNS"; then
                print_status "Application validation passed"
            else
                print_error "Application validation failed"
                validation_failed=1
            fi
        fi
        
    else
        print_error "Infrastructure stack validation failed"
        validation_failed=1
    fi
    
    echo
    
    # Check CI/CD stack
    if check_stack "$CICD_STACK"; then
        print_status "CI/CD stack validation passed"
        
        # Get CI/CD outputs
        PIPELINE_NAME=$(get_stack_output "$CICD_STACK" "CodePipelineName")
        ECR_URI=$(get_stack_output "$CICD_STACK" "ECRRepositoryURI")
        
        print_info "Pipeline: $PIPELINE_NAME"
        print_info "ECR Repository: $ECR_URI"
        
        # Check pipeline status
        if [ -n "$PIPELINE_NAME" ]; then
            PIPELINE_STATUS=$(aws codepipeline get-pipeline-state \
                --name "$PIPELINE_NAME" \
                --region "$REGION" \
                --query 'stageStates[0].latestExecution.status' \
                --output text 2>/dev/null || echo "Unknown")
            
            print_info "Latest pipeline status: $PIPELINE_STATUS"
        fi
        
    else
        print_warning "CI/CD stack not found or unhealthy (this is optional)"
    fi
    
    echo
    echo "Validation Summary"
    echo "=================="
    
    if [ $validation_failed -eq 0 ]; then
        print_status "All validations passed! 🎉"
        echo
        echo "Your AWS Threat Intelligence Analyzer is deployed and running!"
        echo
        if [ -n "$ALB_DNS" ]; then
            # Get the application URL from stack outputs
            APP_URL=$(get_stack_output "$INFRASTRUCTURE_STACK" "ApplicationURL")
            if [ -n "$APP_URL" ]; then
                echo "Access your application at: $APP_URL"
            else
                echo "Access your application at: http://$ALB_DNS (or https:// if certificate configured)"
            fi
        fi
        echo
        echo "Next steps:"
        echo "1. Configure your domain DNS to point to the ALB"
        echo "2. Test the application functionality"
        echo "3. Set up monitoring and alerting"
        echo "4. Configure backup and disaster recovery"
        
        exit 0
    else
        print_error "Some validations failed! ❌"
        echo
        echo "Please check the errors above and:"
        echo "1. Review CloudFormation stack events"
        echo "2. Check ECS service logs"
        echo "3. Verify security group configurations"
        echo "4. Ensure certificate is valid"
        
        exit 1
    fi
}

# Check prerequisites
if ! command -v aws &> /dev/null; then
    print_error "AWS CLI is not installed"
    exit 1
fi

if ! command -v curl &> /dev/null; then
    print_error "curl is not installed"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    print_warning "jq is not installed - some checks may be limited"
fi

# Run main validation
main "$@"