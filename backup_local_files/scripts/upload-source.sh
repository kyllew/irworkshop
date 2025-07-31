#!/bin/bash

# AWS Threat Intelligence Analyzer - Source Upload Script

set -e

# Configuration
DEFAULT_BUCKET="wkkamaru-irworkshop"
DEFAULT_KEY="source.zip"
TEMP_DIR="/tmp/threat-analyzer-source"

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

# Function to check if AWS CLI is installed
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
}

# Function to check if zip is installed
check_zip() {
    if ! command -v zip &> /dev/null; then
        print_error "zip command is not installed. Please install it first."
        exit 1
    fi
}

# Function to create source zip
create_source_zip() {
    local zip_file="$1"
    
    print_info "Creating source code zip file..."
    
    # Clean up temp directory
    rm -rf "$TEMP_DIR"
    mkdir -p "$TEMP_DIR"
    
    # Copy source files (excluding unnecessary files)
    print_info "Copying source files..."
    
    # Copy main application files
    cp -r . "$TEMP_DIR/" 2>/dev/null || true
    
    # Remove unnecessary files from temp directory
    cd "$TEMP_DIR"
    
    # Remove git files
    rm -rf .git .gitignore
    
    # Remove IDE files
    rm -rf .vscode .idea __pycache__ *.pyc
    
    # Remove temporary files
    rm -rf .DS_Store *.tmp *.temp
    
    # Remove backup files
    rm -rf *_backup.json threat_catalog_backup.json
    
    # Remove large files that aren't needed
    rm -rf docs/screenshots docs/images
    
    # Create the zip file
    print_info "Creating zip archive..."
    zip -r "$zip_file" . -x "*.git*" "*__pycache__*" "*.pyc" "*.DS_Store*" > /dev/null
    
    # Return to original directory
    cd - > /dev/null
    
    # Clean up temp directory
    rm -rf "$TEMP_DIR"
    
    print_status "Source zip created: $zip_file"
    print_info "Zip file size: $(du -h "$zip_file" | cut -f1)"
}

# Function to upload to S3
upload_to_s3() {
    local zip_file="$1"
    local bucket="$2"
    local key="$3"
    
    print_info "Uploading to S3: s3://$bucket/$key"
    
    # Check if bucket exists
    if ! aws s3 ls "s3://$bucket" > /dev/null 2>&1; then
        print_error "S3 bucket '$bucket' does not exist or is not accessible"
        print_info "Creating bucket '$bucket'..."
        
        # Create bucket
        if aws s3 mb "s3://$bucket" > /dev/null 2>&1; then
            print_status "Bucket '$bucket' created successfully"
        else
            print_error "Failed to create bucket '$bucket'"
            exit 1
        fi
    fi
    
    # Upload the file
    if aws s3 cp "$zip_file" "s3://$bucket/$key"; then
        print_status "Source code uploaded successfully!"
        print_info "S3 Location: s3://$bucket/$key"
        
        # Get file info
        aws s3 ls "s3://$bucket/$key" --human-readable
        
        return 0
    else
        print_error "Failed to upload source code to S3"
        return 1
    fi
}

# Function to trigger pipeline if it exists
trigger_pipeline() {
    local pipeline_name="threat-analyzer-cicd-pipeline"
    
    print_info "Checking if CI/CD pipeline exists..."
    
    if aws codepipeline get-pipeline --name "$pipeline_name" > /dev/null 2>&1; then
        print_info "Triggering CI/CD pipeline..."
        
        if aws codepipeline start-pipeline-execution --name "$pipeline_name" > /dev/null 2>&1; then
            print_status "Pipeline triggered successfully!"
            print_info "Monitor progress at: https://console.aws.amazon.com/codesuite/codepipeline/pipelines/$pipeline_name/view"
        else
            print_warning "Failed to trigger pipeline (this is normal if pipeline doesn't exist yet)"
        fi
    else
        print_info "CI/CD pipeline not found - deploy it first with: ./scripts/deploy-cicd.sh deploy"
    fi
}

# Function to list current source files
list_source_files() {
    local bucket="${1:-$DEFAULT_BUCKET}"
    
    print_info "Listing source files in bucket: $bucket"
    
    if aws s3 ls "s3://$bucket" --human-readable; then
        print_status "Source files listed successfully"
    else
        print_error "Failed to list source files or bucket doesn't exist"
    fi
}

# Main function
main() {
    local bucket="${SOURCE_BUCKET:-$DEFAULT_BUCKET}"
    local key="${SOURCE_KEY:-$DEFAULT_KEY}"
    local zip_file="/tmp/threat-analyzer-source.zip"
    
    print_info "AWS Threat Intelligence Analyzer - Source Upload"
    print_info "=============================================="
    print_info "Target: s3://$bucket/$key"
    echo
    
    # Check prerequisites
    check_aws_cli
    check_zip
    
    # Parse command line arguments
    case "${1:-upload}" in
        "upload")
            # Create source zip
            create_source_zip "$zip_file"
            
            # Upload to S3
            if upload_to_s3 "$zip_file" "$bucket" "$key"; then
                print_status "Upload completed successfully!"
                
                # Clean up local zip file
                rm -f "$zip_file"
                
                # Trigger pipeline if it exists
                trigger_pipeline
                
                echo
                print_info "Next steps:"
                echo "1. Deploy CI/CD pipeline: ./scripts/deploy-cicd.sh deploy"
                echo "2. Monitor deployment: ./scripts/validate-deployment.sh"
                echo "3. Access application via ALB DNS or custom domain"
                
            else
                print_error "Upload failed!"
                rm -f "$zip_file"
                exit 1
            fi
            ;;
        "list")
            list_source_files "$bucket"
            ;;
        "trigger")
            trigger_pipeline
            ;;
        "clean")
            print_info "Cleaning up temporary files..."
            rm -f /tmp/threat-analyzer-source.zip
            rm -rf "$TEMP_DIR"
            print_status "Cleanup completed"
            ;;
        *)
            echo "Usage: $0 [upload|list|trigger|clean]"
            echo ""
            echo "Commands:"
            echo "  upload   - Create zip and upload source code to S3 (default)"
            echo "  list     - List files in source S3 bucket"
            echo "  trigger  - Manually trigger CI/CD pipeline"
            echo "  clean    - Clean up temporary files"
            echo ""
            echo "Environment variables:"
            echo "  SOURCE_BUCKET - S3 bucket name (default: $DEFAULT_BUCKET)"
            echo "  SOURCE_KEY    - S3 object key (default: $DEFAULT_KEY)"
            echo ""
            echo "Examples:"
            echo "  $0 upload"
            echo "  SOURCE_BUCKET=my-bucket $0 upload"
            echo "  $0 list"
            echo "  $0 trigger"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"