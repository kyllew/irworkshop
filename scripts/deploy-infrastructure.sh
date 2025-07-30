#!/bin/bash

# AWS Threat Intelligence Analyzer - Infrastructure Deployment Script

set -e

# Configuration
STACK_NAME="threat-analyzer-infrastructure"
TEMPLATE_FILE="infrastructure/cloudformation-infrastructure.yaml"
REGION="us-east-1"
ENVIRONMENT="prod"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

# Function to check if AWS CLI is installed
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
}

# Function to check if jq is installed
check_jq() {
    if ! command -v jq &> /dev/null; then
        print_warning "jq is not installed. Some features may not work properly."
    fi
}

# Function to validate parameters
validate_parameters() {
    print_info "Deployment mode: HTTP (simplified)"
    print_info "Application will be accessible via ALB DNS name"
}

# Function to check if stack exists
stack_exists() {
    aws cloudformation describe-stacks --stack-name "$1" --region "$REGION" &> /dev/null
}

# Function to deploy stack
deploy_stack() {
    local action="$1"
    
    print_status "Starting CloudFormation $action for stack: $STACK_NAME"
    
    # Prepare parameters
    PARAMETERS="ParameterKey=Environment,ParameterValue=$ENVIRONMENT"
    
    if [ -n "$CONTAINER_IMAGE" ]; then
        PARAMETERS="$PARAMETERS ParameterKey=ContainerImage,ParameterValue=$CONTAINER_IMAGE"
    fi
    
    if [ -n "$DESIRED_COUNT" ]; then
        PARAMETERS="$PARAMETERS ParameterKey=DesiredCount,ParameterValue=$DESIRED_COUNT"
    fi
    
    if [ -n "$HOSTED_ZONE_ID" ]; then
        PARAMETERS="$PARAMETERS ParameterKey=HostedZoneId,ParameterValue=$HOSTED_ZONE_ID"
    fi
    
    # Deploy stack
    aws cloudformation "$action-stack" \
        --stack-name "$STACK_NAME" \
        --template-body "file://$TEMPLATE_FILE" \
        --parameters $PARAMETERS \
        --capabilities CAPABILITY_NAMED_IAM \
        --region "$REGION" \
        --tags Key=Project,Value=ThreatAnalyzer Key=Environment,Value="$ENVIRONMENT"
    
    print_status "Waiting for stack $action to complete..."
    
    if [ "$action" = "create" ]; then
        aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME" --region "$REGION"
    else
        aws cloudformation wait stack-update-complete --stack-name "$STACK_NAME" --region "$REGION"
    fi
    
    if [ $? -eq 0 ]; then
        print_status "Stack $action completed successfully!"
        
        # Get outputs
        print_status "Stack outputs:"
        aws cloudformation describe-stacks \
            --stack-name "$STACK_NAME" \
            --region "$REGION" \
            --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
            --output table
    else
        print_error "Stack $action failed!"
        exit 1
    fi
}

# Function to show stack status
show_status() {
    print_status "Current stack status:"
    aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].[StackName,StackStatus,CreationTime]' \
        --output table
}

# Function to delete stack
delete_stack() {
    print_warning "This will delete the entire infrastructure stack!"
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_status "Deleting stack: $STACK_NAME"
        
        aws cloudformation delete-stack \
            --stack-name "$STACK_NAME" \
            --region "$REGION"
        
        print_status "Waiting for stack deletion to complete..."
        aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --region "$REGION"
        
        print_status "Stack deleted successfully!"
    else
        print_status "Stack deletion cancelled."
    fi
}

# Main script
main() {
    print_status "AWS Threat Intelligence Analyzer - Simplified Infrastructure Deployment"
    print_status "Architecture: ALB + ECS Fargate (No CloudFront)"
    print_status "=================================================================="
    
    # Check prerequisites
    check_aws_cli
    check_jq
    
    # Parse command line arguments
    case "${1:-deploy}" in
        "deploy")
            validate_parameters
            if stack_exists "$STACK_NAME"; then
                print_status "Stack exists. Updating..."
                deploy_stack "update"
            else
                print_status "Stack does not exist. Creating..."
                deploy_stack "create"
            fi
            ;;
        "status")
            if stack_exists "$STACK_NAME"; then
                show_status
            else
                print_error "Stack $STACK_NAME does not exist"
                exit 1
            fi
            ;;
        "delete")
            if stack_exists "$STACK_NAME"; then
                delete_stack
            else
                print_error "Stack $STACK_NAME does not exist"
                exit 1
            fi
            ;;
        "outputs")
            if stack_exists "$STACK_NAME"; then
                print_status "Stack outputs:"
                aws cloudformation describe-stacks \
                    --stack-name "$STACK_NAME" \
                    --region "$REGION" \
                    --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
                    --output table
            else
                print_error "Stack $STACK_NAME does not exist"
                exit 1
            fi
            ;;
        *)
            echo "Usage: $0 [deploy|status|delete|outputs]"
            echo ""
            echo "Environment variables for deploy:"
            echo "  All parameters are optional:"
            echo ""
            echo "  CONTAINER_IMAGE   - ECR container image URI (optional)"
            echo "  DESIRED_COUNT     - Number of ECS tasks (default: 2)"
            echo ""
            echo "Examples:"
            echo "  # Simple deployment (HTTP only)"
            echo "  $0 deploy"
            echo ""
            echo "  # With custom container image"
            echo "  CONTAINER_IMAGE=123456789012.dkr.ecr.us-east-1.amazonaws.com/threat-analyzer:latest $0 deploy"
            echo ""
            echo "  # Other commands"
            echo "  $0 status"
            echo "  $0 outputs"
            echo "  $0 delete"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"