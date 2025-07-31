#!/bin/bash

# AWS Threat Intelligence Analyzer - CI/CD Pipeline Deployment Script

set -e

# Configuration
STACK_NAME="threat-analyzer-cicd"
TEMPLATE_FILE="infrastructure/cloudformation-cicd.yaml"
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

# Function to validate parameters
validate_parameters() {
    if [ -z "$INFRASTRUCTURE_STACK_NAME" ]; then
        print_warning "INFRASTRUCTURE_STACK_NAME not set, using default: threat-analyzer-infrastructure"
        INFRASTRUCTURE_STACK_NAME="threat-analyzer-infrastructure"
    fi
    
    # S3 source bucket and key are now optional with defaults
    if [ -z "$SOURCE_BUCKET" ]; then
        SOURCE_BUCKET="wkkamaru-irworkshop"
        print_info "Using default source bucket: $SOURCE_BUCKET"
    fi
    
    if [ -z "$SOURCE_KEY" ]; then
        SOURCE_KEY="source.zip"
        print_info "Using default source key: $SOURCE_KEY"
    fi
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
    PARAMETERS="$PARAMETERS ParameterKey=InfrastructureStackName,ParameterValue=$INFRASTRUCTURE_STACK_NAME"
    PARAMETERS="$PARAMETERS ParameterKey=SourceBucket,ParameterValue=$SOURCE_BUCKET"
    PARAMETERS="$PARAMETERS ParameterKey=SourceKey,ParameterValue=$SOURCE_KEY"
    
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
            
        # Get ECR repository URI
        ECR_URI=$(aws cloudformation describe-stacks \
            --stack-name "$STACK_NAME" \
            --region "$REGION" \
            --query 'Stacks[0].Outputs[?OutputKey==`ECRRepositoryURI`].OutputValue' \
            --output text)
        
        if [ -n "$ECR_URI" ]; then
            print_status "ECR Repository URI: $ECR_URI"
            print_status "To push your first image:"
            echo "  aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR_URI"
            echo "  docker build -t threat-analyzer ."
            echo "  docker tag threat-analyzer:latest $ECR_URI:latest"
            echo "  docker push $ECR_URI:latest"
        fi
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
    print_warning "This will delete the entire CI/CD pipeline stack!"
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

# Function to trigger pipeline
trigger_pipeline() {
    PIPELINE_NAME=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`CodePipelineName`].OutputValue' \
        --output text)
    
    if [ -n "$PIPELINE_NAME" ]; then
        print_status "Triggering pipeline: $PIPELINE_NAME"
        aws codepipeline start-pipeline-execution --name "$PIPELINE_NAME" --region "$REGION"
        print_status "Pipeline execution started!"
    else
        print_error "Could not find pipeline name in stack outputs"
        exit 1
    fi
}

# Main script
main() {
    print_status "AWS Threat Intelligence Analyzer - CI/CD Pipeline Deployment"
    print_status "============================================================="
    
    # Check prerequisites
    check_aws_cli
    
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
        "trigger")
            if stack_exists "$STACK_NAME"; then
                trigger_pipeline
            else
                print_error "Stack $STACK_NAME does not exist"
                exit 1
            fi
            ;;
        *)
            echo "Usage: $0 [deploy|status|delete|outputs|trigger]"
            echo ""
            echo "Environment variables for deploy:"
            echo "  All parameters are optional with defaults:"
            echo ""
            echo "  INFRASTRUCTURE_STACK_NAME - Name of infrastructure stack (default: threat-analyzer-infrastructure)"
            echo "  SOURCE_BUCKET             - S3 bucket with source code (default: wkkamaru-irworkshop)"
            echo "  SOURCE_KEY                - S3 key for source zip (default: source.zip)"
            echo ""
            echo "Examples:"
            echo "  # Simple deployment with defaults"
            echo "  $0 deploy"
            echo ""
            echo "  # Custom source location"
            echo "  SOURCE_BUCKET=my-bucket SOURCE_KEY=my-source.zip $0 deploy"
            echo ""
            echo "  # Other commands"
            echo "  $0 status"
            echo "  $0 outputs"
            echo "  $0 trigger"
            echo "  $0 delete"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"