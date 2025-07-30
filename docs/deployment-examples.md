# Deployment Examples

This document provides specific examples for different deployment scenarios.

## Scenario 1: Simple Development/Testing Deployment

**Use Case**: Quick deployment for testing or development without custom domain.

```bash
# Deploy infrastructure (HTTP only, uses ALB DNS)
./scripts/deploy-infrastructure.sh deploy

# Deploy CI/CD pipeline
GITHUB_TOKEN=ghp_your_token_here \
./scripts/deploy-cicd.sh deploy

# Validate deployment
./scripts/validate-deployment.sh
```

**Result**: 
- Application accessible via ALB DNS name (e.g., `http://threat-analyzer-alb-123456789.us-east-1.elb.amazonaws.com`)
- HTTP only (no SSL certificate required)
- Fully functional for testing and development

## Scenario 2: Production Deployment with Custom Domain

**Use Case**: Production deployment with your own domain and HTTPS.

### Step 1: Create SSL Certificate
```bash
# Request ACM certificate
aws acm request-certificate \
    --domain-name threat-analyzer.yourdomain.com \
    --validation-method DNS \
    --region us-east-1

# Note the CertificateArn from output
```

### Step 2: Deploy Infrastructure
```bash
# Deploy with custom domain and HTTPS
DOMAIN_NAME=threat-analyzer.yourdomain.com \
CERTIFICATE_ARN=arn:aws:acm:us-east-1:123456789012:certificate/your-cert-id \
./scripts/deploy-infrastructure.sh deploy
```

### Step 3: Configure DNS
```bash
# Get ALB DNS name
ALB_DNS=$(aws cloudformation describe-stacks \
    --stack-name threat-analyzer-infrastructure \
    --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerDNS`].OutputValue' \
    --output text)

# Create CNAME record in your DNS provider
# threat-analyzer.yourdomain.com -> $ALB_DNS
```

### Step 4: Deploy CI/CD and Validate
```bash
# Deploy CI/CD pipeline
GITHUB_TOKEN=ghp_your_token_here \
./scripts/deploy-cicd.sh deploy

# Validate deployment
./scripts/validate-deployment.sh
```

**Result**:
- Application accessible via your custom domain with HTTPS
- Automatic HTTP to HTTPS redirect
- Production-ready with SSL certificate

## Scenario 3: Production with Route 53 Automation

**Use Case**: Production deployment with automatic DNS record creation.

### Prerequisites
- Domain hosted in Route 53
- ACM certificate validated

```bash
# Get your hosted zone ID
HOSTED_ZONE_ID=$(aws route53 list-hosted-zones \
    --query 'HostedZones[?Name==`yourdomain.com.`].Id' \
    --output text | cut -d'/' -f3)

# Deploy with automatic DNS
DOMAIN_NAME=threat-analyzer.yourdomain.com \
CERTIFICATE_ARN=arn:aws:acm:us-east-1:123456789012:certificate/your-cert-id \
HOSTED_ZONE_ID=$HOSTED_ZONE_ID \
./scripts/deploy-infrastructure.sh deploy

# Deploy CI/CD
GITHUB_TOKEN=ghp_your_token_here \
./scripts/deploy-cicd.sh deploy

# Validate
./scripts/validate-deployment.sh
```

**Result**:
- Automatic Route 53 A record creation
- No manual DNS configuration required
- HTTPS with custom domain

## Scenario 4: Scaling for High Traffic

**Use Case**: Production deployment optimized for high traffic.

```bash
# Deploy with increased capacity
DOMAIN_NAME=threat-analyzer.yourdomain.com \
CERTIFICATE_ARN=arn:aws:acm:us-east-1:123456789012:certificate/your-cert-id \
DESIRED_COUNT=5 \
./scripts/deploy-infrastructure.sh deploy
```

**Additional Optimizations**:
- Increase ECS task CPU/memory in CloudFormation template
- Configure ALB stickiness if needed
- Set up CloudWatch dashboards for monitoring

## Scenario 5: Multi-Environment Deployment

**Use Case**: Separate dev, staging, and production environments.

### Development Environment
```bash
# Deploy dev environment
ENVIRONMENT=dev \
./scripts/deploy-infrastructure.sh deploy

# Use different stack name for isolation
STACK_NAME=threat-analyzer-dev ./scripts/deploy-infrastructure.sh deploy
```

### Staging Environment
```bash
# Deploy staging with domain
ENVIRONMENT=staging \
DOMAIN_NAME=staging-threat-analyzer.yourdomain.com \
CERTIFICATE_ARN=arn:aws:acm:us-east-1:123456789012:certificate/staging-cert \
./scripts/deploy-infrastructure.sh deploy
```

### Production Environment
```bash
# Deploy production
ENVIRONMENT=prod \
DOMAIN_NAME=threat-analyzer.yourdomain.com \
CERTIFICATE_ARN=arn:aws:acm:us-east-1:123456789012:certificate/prod-cert \
DESIRED_COUNT=3 \
./scripts/deploy-infrastructure.sh deploy
```

## Scenario 6: Cost-Optimized Deployment

**Use Case**: Minimize costs for small-scale usage.

```bash
# Deploy with minimal resources
DESIRED_COUNT=1 \
./scripts/deploy-infrastructure.sh deploy
```

**Additional Cost Optimizations**:
- Use single AZ (modify CloudFormation template)
- Use Fargate Spot pricing (modify template)
- Reduce log retention periods
- Use smaller ECS task sizes

## Scenario 7: Updating Existing Deployment

**Use Case**: Update configuration or add HTTPS to existing deployment.

### Add HTTPS to Existing HTTP Deployment
```bash
# Create certificate first
aws acm request-certificate \
    --domain-name threat-analyzer.yourdomain.com \
    --validation-method DNS \
    --region us-east-1

# Update existing stack with HTTPS
DOMAIN_NAME=threat-analyzer.yourdomain.com \
CERTIFICATE_ARN=arn:aws:acm:us-east-1:123456789012:certificate/new-cert \
./scripts/deploy-infrastructure.sh deploy
```

### Scale Up/Down
```bash
# Scale to 5 tasks
DESIRED_COUNT=5 \
./scripts/deploy-infrastructure.sh deploy

# Scale down to 1 task
DESIRED_COUNT=1 \
./scripts/deploy-infrastructure.sh deploy
```

### Update Container Image
```bash
# Update with new image
CONTAINER_IMAGE=123456789012.dkr.ecr.us-east-1.amazonaws.com/threat-analyzer:v2.0 \
./scripts/deploy-infrastructure.sh deploy
```

## Troubleshooting Common Scenarios

### Certificate Validation Issues
```bash
# Check certificate status
aws acm describe-certificate --certificate-arn your-cert-arn

# List certificates
aws acm list-certificates --region us-east-1
```

### DNS Issues
```bash
# Check Route 53 records
aws route53 list-resource-record-sets --hosted-zone-id your-zone-id

# Test DNS resolution
nslookup threat-analyzer.yourdomain.com
dig threat-analyzer.yourdomain.com
```

### Application Not Accessible
```bash
# Check ECS service status
aws ecs describe-services \
    --cluster threat-analyzer-infrastructure-cluster \
    --services threat-analyzer-infrastructure-service

# Check ALB target health
aws elbv2 describe-target-health \
    --target-group-arn your-target-group-arn

# Check security groups
aws ec2 describe-security-groups \
    --group-ids your-security-group-id
```

### Rollback Deployment
```bash
# Rollback to previous version
aws cloudformation cancel-update-stack \
    --stack-name threat-analyzer-infrastructure

# Or delete and redeploy
./scripts/deploy-infrastructure.sh delete
# Wait for deletion to complete, then redeploy
./scripts/deploy-infrastructure.sh deploy
```

## Monitoring and Maintenance

### Regular Health Checks
```bash
# Automated validation
./scripts/validate-deployment.sh

# Manual health check
curl -f https://your-domain.com/health
```

### Log Monitoring
```bash
# View application logs
aws logs tail /ecs/threat-analyzer-infrastructure --follow

# View build logs
aws logs tail /aws/codebuild/threat-analyzer-cicd-build --follow
```

### Cost Monitoring
```bash
# Check current costs
aws ce get-cost-and-usage \
    --time-period Start=2025-01-01,End=2025-01-31 \
    --granularity MONTHLY \
    --metrics BlendedCost \
    --group-by Type=DIMENSION,Key=SERVICE
```

These examples cover the most common deployment scenarios. Choose the one that best fits your requirements and environment.