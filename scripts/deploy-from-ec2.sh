#!/bin/bash

# AWS Threat Intelligence Analyzer - EC2 Deployment Script
# This script is designed to run on an EC2 instance with proper AWS credentials

set -e

# Configuration
STACK_NAME="threat-analyzer-infrastructure"
CICD_STACK_NAME="threat-analyzer-cicd"
TEMPLATE_FILE="infrastructure/cloudformation-infrastructure.yaml"
CICD_TEMPLATE_FILE="infrastructure/cloudformation-cicd.yaml"
REGION="us-east-1"
ENVIRONMENT="prod"
ECR_REPOSITORY="threat-analyzer"
IMAGE_TAG="latest"

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

# Function to check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check and install Git
    if ! command -v git &> /dev/null; then
        print_info "Git is not installed. Installing..."
        sudo yum update -y
        sudo yum install -y git
    fi
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Installing..."
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
        unzip awscliv2.zip
        sudo ./aws/install
        rm -rf aws awscliv2.zip
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Installing..."
        sudo yum update -y
        sudo yum install -y docker
        sudo service docker start
        sudo usermod -a -G docker ec2-user
        print_warning "Please log out and log back in for Docker group changes to take effect"
        print_warning "Or run: newgrp docker"
    fi
    
    # Check jq
    if ! command -v jq &> /dev/null; then
        print_info "Installing jq..."
        sudo yum install -y jq
    fi
    
    # Check zip (for creating source archives)
    if ! command -v zip &> /dev/null; then
        print_info "Installing zip..."
        sudo yum install -y zip
    fi
    
    print_status "Prerequisites check completed"
}

# Function to verify AWS credentials
verify_aws_credentials() {
    print_info "Verifying AWS credentials..."
    
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured or invalid"
        print_info "Please configure AWS credentials using one of these methods:"
        echo "1. AWS CLI: aws configure"
        echo "2. IAM Role: Attach IAM role to EC2 instance"
        echo "3. Environment variables: export AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY"
        exit 1
    fi
    
    ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    print_status "Using AWS Account: $ACCOUNT_ID"
}

# Function to create ECR repository if it doesn't exist
create_ecr_repository() {
    print_info "Checking ECR repository..."
    
    if ! aws ecr describe-repositories --repository-names "$ECR_REPOSITORY" --region "$REGION" &> /dev/null; then
        print_info "Creating ECR repository: $ECR_REPOSITORY"
        aws ecr create-repository \
            --repository-name "$ECR_REPOSITORY" \
            --region "$REGION" \
            --image-scanning-configuration scanOnPush=true \
            --encryption-configuration encryptionType=AES256
    else
        print_status "ECR repository already exists"
    fi
}

# Function to build and push Docker image
build_and_push_image() {
    print_info "Building Docker image..."
    
    # Build the image
    docker build -t "$ECR_REPOSITORY:$IMAGE_TAG" .
    
    # Get ECR login token
    print_info "Logging in to ECR..."
    aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com"
    
    # Tag the image for ECR
    ECR_URI="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$ECR_REPOSITORY"
    docker tag "$ECR_REPOSITORY:$IMAGE_TAG" "$ECR_URI:$IMAGE_TAG"
    
    # Push the image
    print_info "Pushing image to ECR..."
    docker push "$ECR_URI:$IMAGE_TAG"
    
    print_status "Image pushed successfully: $ECR_URI:$IMAGE_TAG"
    
    # Export for use in infrastructure deployment
    export CONTAINER_IMAGE="$ECR_URI:$IMAGE_TAG"
}

# Function to deploy infrastructure
deploy_infrastructure() {
    print_info "Deploying infrastructure stack..."
    
    # Check if stack exists
    if aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" &> /dev/null; then
        print_info "Updating existing infrastructure stack..."
        ACTION="update"
    else
        print_info "Creating new infrastructure stack..."
        ACTION="create"
    fi
    
    # Prepare parameters
    PARAMETERS="ParameterKey=Environment,ParameterValue=$ENVIRONMENT"
    if [ -n "$CONTAINER_IMAGE" ]; then
        PARAMETERS="$PARAMETERS ParameterKey=ContainerImage,ParameterValue=$CONTAINER_IMAGE"
    fi
    
    # Deploy stack
    aws cloudformation "$ACTION-stack" \
        --stack-name "$STACK_NAME" \
        --template-body "file://$TEMPLATE_FILE" \
        --parameters $PARAMETERS \
        --capabilities CAPABILITY_NAMED_IAM \
        --region "$REGION" \
        --tags Key=Project,Value=ThreatAnalyzer Key=Environment,Value="$ENVIRONMENT"
    
    print_info "Waiting for stack $ACTION to complete..."
    
    if [ "$ACTION" = "create" ]; then
        aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME" --region "$REGION"
    else
        aws cloudformation wait stack-update-complete --stack-name "$STACK_NAME" --region "$REGION"
    fi
    
    print_status "Infrastructure deployment completed!"
}

# Function to deploy CI/CD pipeline
deploy_cicd() {
    print_info "Deploying CI/CD pipeline..."
    
    # Check if CI/CD stack exists
    if aws cloudformation describe-stacks --stack-name "$CICD_STACK_NAME" --region "$REGION" &> /dev/null; then
        print_info "Updating existing CI/CD stack..."
        ACTION="update"
    else
        print_info "Creating new CI/CD stack..."
        ACTION="create"
    fi
    
    # Prepare parameters
    PARAMETERS="ParameterKey=Environment,ParameterValue=$ENVIRONMENT"
    PARAMETERS="$PARAMETERS ParameterKey=InfrastructureStackName,ParameterValue=$STACK_NAME"
    PARAMETERS="$PARAMETERS ParameterKey=SourceBucket,ParameterValue=wkkamaru-irworkshop"
    PARAMETERS="$PARAMETERS ParameterKey=SourceKey,ParameterValue=source.zip"
    
    # Deploy stack
    aws cloudformation "$ACTION-stack" \
        --stack-name "$CICD_STACK_NAME" \
        --template-body "file://$CICD_TEMPLATE_FILE" \
        --parameters $PARAMETERS \
        --capabilities CAPABILITY_NAMED_IAM \
        --region "$REGION" \
        --tags Key=Project,Value=ThreatAnalyzer Key=Environment,Value="$ENVIRONMENT"
    
    print_info "Waiting for CI/CD stack $ACTION to complete..."
    
    if [ "$ACTION" = "create" ]; then
        aws cloudformation wait stack-create-complete --stack-name "$CICD_STACK_NAME" --region "$REGION"
    else
        aws cloudformation wait stack-update-complete --stack-name "$CICD_STACK_NAME" --region "$REGION"
    fi
    
    print_status "CI/CD pipeline deployment completed!"
}

# Function to show deployment outputs
show_outputs() {
    print_info "Infrastructure Stack Outputs:"
    aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
        --output table
    
    echo
    
    print_info "CI/CD Stack Outputs:"
    aws cloudformation describe-stacks \
        --stack-name "$CICD_STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
        --output table
}

# Function to upload source code to S3
upload_source() {
    print_info "Uploading source code to S3..."
    
    # Create source zip
    SOURCE_ZIP="/tmp/threat-analyzer-source.zip"
    zip -r "$SOURCE_ZIP" . -x "*.git*" "*__pycache__*" "*.pyc" "*.DS_Store*" "node_modules/*" ".env*"
    
    # Upload to S3
    aws s3 cp "$SOURCE_ZIP" "s3://wkkamaru-irworkshop/source.zip"
    
    print_status "Source code uploaded to S3"
    rm -f "$SOURCE_ZIP"
}

# Main deployment function
deploy_all() {
    print_info "Starting complete deployment from EC2..."
    print_info "=========================================="
    
    # Run all deployment steps
    check_prerequisites
    verify_aws_credentials
    create_ecr_repository
    build_and_push_image
    upload_source
    deploy_infrastructure
    deploy_cicd
    show_outputs
    
    print_status "Deployment completed successfully!"
    print_info "Your application should be accessible via the ALB DNS name shown above"
}

# Function to show status
show_status() {
    print_info "Infrastructure Stack Status:"
    aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].[StackName,StackStatus,CreationTime]' \
        --output table
    
    echo
    
    print_info "CI/CD Stack Status:"
    aws cloudformation describe-stacks \
        --stack-name "$CICD_STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].[StackName,StackStatus,CreationTime]' \
        --output table
}

# Function to clean up
cleanup() {
    print_warning "This will delete all deployed resources!"
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_info "Deleting CI/CD stack..."
        aws cloudformation delete-stack --stack-name "$CICD_STACK_NAME" --region "$REGION"
        aws cloudformation wait stack-delete-complete --stack-name "$CICD_STACK_NAME" --region "$REGION"
        
        print_info "Deleting infrastructure stack..."
        aws cloudformation delete-stack --stack-name "$STACK_NAME" --region "$REGION"
        aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --region "$REGION"
        
        print_status "Cleanup completed!"
    else
        print_info "Cleanup cancelled."
    fi
}

# Main script
main() {
    case "${1:-deploy}" in
        "deploy")
            deploy_all
            ;;
        "status")
            show_status
            ;;
        "outputs")
            show_outputs
            ;;
        "cleanup")
            cleanup
            ;;
        "build-push")
            check_prerequisites
            verify_aws_credentials
            create_ecr_repository
            build_and_push_image
            ;;
        "infrastructure")
            check_prerequisites
            verify_aws_credentials
            deploy_infrastructure
            ;;
        "cicd")
            check_prerequisites
            verify_aws_credentials
            deploy_cicd
            ;;
        *)
            echo "Usage: $0 [deploy|status|outputs|cleanup|build-push|infrastructure|cicd]"
            echo ""
            echo "Commands:"
            echo "  deploy        - Complete deployment (default)"
            echo "  build-push    - Build and push Docker image only"
            echo "  infrastructure- Deploy infrastructure stack only"
            echo "  cicd          - Deploy CI/CD pipeline only"
            echo "  status        - Show stack status"
            echo "  outputs       - Show stack outputs"
            echo "  cleanup       - Delete all resources"
            echo ""
            echo "Prerequisites on EC2:"
            echo "  - IAM role with ECR, CloudFormation, S3, ECS permissions"
            echo "  - Or AWS credentials configured"
            echo ""
            echo "Example:"
            echo "  $0 deploy"
            exit 1
            ;;
    esac
}

# Run main function
main "$@" 