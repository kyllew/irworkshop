# S3-Based Deployment Guide

This guide covers deploying the AWS Threat Intelligence Analyzer using S3 as the source code repository instead of GitHub.

## Overview

The S3-based deployment approach:
- Uses S3 bucket `wkkamaru-irworkshop` as the source code repository
- Automatically triggers CI/CD pipeline when source code is updated
- Eliminates the need for GitHub tokens and webhooks
- Provides more control over deployment timing

## Quick Start

### 1. Deploy Infrastructure
```bash
# Simple HTTP deployment
./scripts/deploy-infrastructure.sh deploy
```

### 2. Upload Source Code
```bash
# Upload current directory as source.zip to S3
./scripts/upload-source.sh upload
```

### 3. Deploy CI/CD Pipeline
```bash
# Deploy pipeline that uses S3 as source
./scripts/deploy-cicd.sh deploy
```

### 4. Validate Deployment
```bash
# Check that everything is working
./scripts/validate-deployment.sh
```

## Source Code Management

### Upload New Version
```bash
# Upload updated source code
./scripts/upload-source.sh upload

# The pipeline will automatically trigger and deploy
```

### List Source Files
```bash
# See what's in the S3 bucket
./scripts/upload-source.sh list
```

### Manual Pipeline Trigger
```bash
# Manually trigger the pipeline
./scripts/upload-source.sh trigger
```

## Configuration Options

### Custom S3 Location
```bash
# Use different bucket/key
SOURCE_BUCKET=my-custom-bucket \
SOURCE_KEY=my-source.zip \
./scripts/upload-source.sh upload

# Deploy CI/CD with custom location
SOURCE_BUCKET=my-custom-bucket \
SOURCE_KEY=my-source.zip \
./scripts/deploy-cicd.sh deploy
```

### Environment Variables

**Upload Script (`upload-source.sh`):**
- `SOURCE_BUCKET` - S3 bucket name (default: wkkamaru-irworkshop)
- `SOURCE_KEY` - S3 object key (default: source.zip)

**CI/CD Script (`deploy-cicd.sh`):**
- `SOURCE_BUCKET` - S3 bucket name (default: wkkamaru-irworkshop)
- `SOURCE_KEY` - S3 object key (default: source.zip)
- `INFRASTRUCTURE_STACK_NAME` - Infrastructure stack name

## Pipeline Behavior

### Automatic Triggers
The pipeline automatically triggers when:
- Source code is uploaded to the specified S3 location
- CloudWatch Events detect S3 object creation

### Manual Triggers
You can manually trigger the pipeline:
```bash
# Using the upload script
./scripts/upload-source.sh trigger

# Using AWS CLI directly
aws codepipeline start-pipeline-execution \
    --name threat-analyzer-cicd-pipeline
```

## Deployment Workflow

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Local Code    │───▶│   S3 Bucket     │───▶│   CodePipeline  │
│                 │    │ (wkkamaru-      │    │                 │
└─────────────────┘    │  irworkshop)    │    └─────────────────┘
                       └─────────────────┘             │
                                                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   ECS Service   │◀───│   ECR Registry  │◀───│   CodeBuild     │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Advantages of S3-Based Deployment

### Benefits
- **No GitHub Dependencies**: No need for GitHub tokens or webhooks
- **Controlled Deployment**: Upload when ready to deploy
- **Offline Development**: Work without internet connectivity
- **Version Control**: S3 versioning provides backup
- **Cost Effective**: No GitHub Actions minutes consumed

### Use Cases
- **Corporate Environments**: Where GitHub access is restricted
- **Development/Testing**: Quick iterations without Git commits
- **Temporary Deployments**: One-off deployments or demos
- **Backup Strategy**: Alternative to GitHub-based deployment

## Monitoring and Troubleshooting

### Check Pipeline Status
```bash
# View pipeline status
aws codepipeline get-pipeline-state \
    --name threat-analyzer-cicd-pipeline

# View execution history
aws codepipeline list-pipeline-executions \
    --pipeline-name threat-analyzer-cicd-pipeline
```

### View Build Logs
```bash
# Tail build logs
aws logs tail /aws/codebuild/threat-analyzer-cicd-build --follow
```

### Check S3 Source
```bash
# Verify source file exists
aws s3 ls s3://wkkamaru-irworkshop/source.zip

# Download source for inspection
aws s3 cp s3://wkkamaru-irworkshop/source.zip ./downloaded-source.zip
```

## Security Considerations

### S3 Bucket Security
- Bucket should have versioning enabled
- Use least privilege IAM policies
- Enable server-side encryption
- Monitor access with CloudTrail

### Pipeline Security
- CodeBuild runs in isolated environment
- ECR images are scanned for vulnerabilities
- ECS tasks run with minimal permissions
- All communications use HTTPS/TLS

## Migration from GitHub

If you want to switch from GitHub to S3-based deployment:

### 1. Update Existing Pipeline
```bash
# Delete existing GitHub-based pipeline
./scripts/deploy-cicd.sh delete

# Upload source to S3
./scripts/upload-source.sh upload

# Deploy new S3-based pipeline
./scripts/deploy-cicd.sh deploy
```

### 2. Remove GitHub Webhook
The old GitHub webhook will become inactive automatically.

## Best Practices

### Source Code Management
- Use descriptive filenames: `source-v1.2.3.zip`
- Keep source files organized
- Document changes in commit messages or file metadata
- Use S3 versioning for rollback capability

### Deployment Process
- Test locally before uploading
- Use staging environment for validation
- Monitor pipeline execution
- Validate deployment after completion

### Maintenance
- Regularly clean up old source files
- Monitor S3 storage costs
- Update IAM policies as needed
- Review CloudWatch logs periodically

This S3-based approach provides a flexible and reliable deployment method that works well for various scenarios and environments.