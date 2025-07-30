# Deployment Guide

This guide covers deploying the AWS Threat Intelligence Analyzer to AWS using the simplified architecture.

## Architecture Overview

The simplified production architecture consists of:

```
Internet → Route 53 (Optional) → Application Load Balancer → ECS Fargate Tasks
```

### Components:
- **Application Load Balancer (ALB)** - HTTPS termination and load balancing
- **ECS Fargate** - Containerized application hosting
- **VPC** - Isolated network environment with public/private subnets
- **Route 53** - DNS management (optional)
- **ECR** - Container image registry
- **CodePipeline** - CI/CD automation

## Prerequisites

### 1. AWS CLI Configuration
```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, and region
```

### 2. Optional Resources
- **SSL Certificate**: Create an ACM certificate for your domain (optional for HTTPS)
- **Domain Name**: A domain you control (optional)
- **GitHub Token**: Personal access token for CI/CD

### 3. Create SSL Certificate (Optional)
```bash
# Only if you want HTTPS with a custom domain
aws acm request-certificate \
    --domain-name threat-analyzer.yourdomain.com \
    --validation-method DNS \
    --region us-east-1

# Note the CertificateArn from the output
```

## Deployment Steps

### Step 1: Deploy Infrastructure

```bash
# Clone the repository
git clone https://github.com/kyllew/irworkshop.git
cd irworkshop

# Make deployment scripts executable
chmod +x scripts/deploy-infrastructure.sh
chmod +x scripts/deploy-cicd.sh

# Simple deployment (HTTP only, uses ALB DNS name)
./scripts/deploy-infrastructure.sh deploy

# OR with custom domain and HTTPS
DOMAIN_NAME=threat-analyzer.yourdomain.com \
CERTIFICATE_ARN=arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012 \
./scripts/deploy-infrastructure.sh deploy
```

**All Environment Variables are Optional:**
- `DOMAIN_NAME` - Your custom domain name
- `CERTIFICATE_ARN` - ACM certificate ARN for HTTPS
- `DESIRED_COUNT` - Number of ECS tasks (default: 2)
- `HOSTED_ZONE_ID` - Route 53 hosted zone ID for automatic DNS
- `CONTAINER_IMAGE` - Initial container image (will be updated by CI/CD)

### Step 2: Upload Source Code to S3

```bash
# Upload source code to S3 bucket
./scripts/upload-source.sh upload
```

### Step 3: Deploy CI/CD Pipeline

```bash
# Deploy CI/CD pipeline (uses S3 as source)
./scripts/deploy-cicd.sh deploy
```

**All Environment Variables are Optional:**
- `SOURCE_BUCKET` - S3 bucket with source code (default: wkkamaru-irworkshop)
- `SOURCE_KEY` - S3 key for source zip (default: source.zip)
- `INFRASTRUCTURE_STACK_NAME` - Name of infrastructure stack (default: threat-analyzer-infrastructure)

### Step 4: Validate Deployment

```bash
# The CI/CD pipeline will automatically build and deploy the container
# Validate that everything is working
./scripts/validate-deployment.sh
```

**The pipeline will automatically:**
1. Download source code from S3
2. Build Docker container
3. Push to ECR
4. Deploy to ECS
5. Update the running service

## Verification

### Check Deployment Status

```bash
# Check infrastructure stack
./scripts/deploy-infrastructure.sh status

# Check CI/CD stack
./scripts/deploy-cicd.sh status

# View stack outputs
./scripts/deploy-infrastructure.sh outputs
./scripts/deploy-cicd.sh outputs
```

### Test Application

```bash
# Get ALB DNS name
ALB_DNS=$(aws cloudformation describe-stacks \
    --stack-name threat-analyzer-infrastructure \
    --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerDNS`].OutputValue' \
    --output text)

# Test health endpoint
curl -k https://$ALB_DNS/health

# Test with your domain (if configured)
curl https://threat-analyzer.yourdomain.com/health
```

## CI/CD Pipeline

The pipeline automatically triggers on GitHub pushes and includes:

1. **Source** - GitHub repository
2. **Build** - Docker image build and test
3. **Deploy** - ECS service update

### Manual Pipeline Trigger

```bash
./scripts/deploy-cicd.sh trigger
```

### Pipeline Monitoring

- **AWS Console**: CodePipeline → threat-analyzer-cicd-pipeline
- **CloudWatch Logs**: `/aws/codebuild/threat-analyzer-cicd-build`
- **ECS Console**: Monitor service and task health

## Configuration

### Environment Variables

The application supports these environment variables:

- `ENVIRONMENT` - Environment name (dev/staging/prod)
- `HOST` - Server host (default: 0.0.0.0)
- `PORT` - Server port (default: 8000)

### Scaling Configuration

Auto-scaling is configured with:
- **Target CPU**: 70%
- **Min Capacity**: 1 task
- **Max Capacity**: 10 tasks
- **Scale Out Cooldown**: 5 minutes
- **Scale In Cooldown**: 5 minutes

### Security

- **VPC**: Isolated network with public/private subnets
- **Security Groups**: Restrictive ingress rules
- **ALB**: HTTPS-only with SSL termination
- **ECS Tasks**: Run in private subnets
- **IAM**: Least privilege roles

## Monitoring and Logging

### CloudWatch Logs
- **Application Logs**: `/ecs/threat-analyzer-infrastructure`
- **Build Logs**: `/aws/codebuild/threat-analyzer-cicd-build`

### CloudWatch Metrics
- **ECS Service**: CPU, Memory, Task count
- **ALB**: Request count, Response time, Error rate
- **Auto Scaling**: Scaling activities

### Alarms
- **Pipeline Failure**: Alerts on build/deploy failures
- **ECS Service**: Health check failures
- **ALB**: High error rates

## Troubleshooting

### Common Issues

**1. Certificate Validation**
```bash
# Check certificate status
aws acm describe-certificate --certificate-arn YOUR_CERT_ARN
```

**2. ECS Task Failures**
```bash
# Check ECS service events
aws ecs describe-services \
    --cluster threat-analyzer-infrastructure-cluster \
    --services threat-analyzer-infrastructure-service

# Check task logs
aws logs tail /ecs/threat-analyzer-infrastructure --follow
```

**3. ALB Health Check Failures**
```bash
# Check target group health
aws elbv2 describe-target-health \
    --target-group-arn YOUR_TARGET_GROUP_ARN
```

**4. Pipeline Failures**
```bash
# Check build logs
aws logs tail /aws/codebuild/threat-analyzer-cicd-build --follow
```

### Debug Commands

```bash
# Connect to running ECS task
aws ecs execute-command \
    --cluster threat-analyzer-infrastructure-cluster \
    --task TASK_ID \
    --container threat-analyzer \
    --interactive \
    --command "/bin/bash"

# View ECS service logs
aws logs tail /ecs/threat-analyzer-infrastructure --follow

# Check ALB access logs (if enabled)
aws s3 ls s3://your-alb-logs-bucket/
```

## Cleanup

### Delete Resources

```bash
# Delete CI/CD stack first
./scripts/deploy-cicd.sh delete

# Delete infrastructure stack
./scripts/deploy-infrastructure.sh delete

# Manually delete ECR images if needed
aws ecr list-images --repository-name threat-analyzer-cicd-threat-analyzer
aws ecr batch-delete-image --repository-name threat-analyzer-cicd-threat-analyzer --image-ids imageTag=latest
```

## Cost Optimization

### Estimated Monthly Costs (us-east-1)

- **ALB**: ~$16/month
- **ECS Fargate** (2 tasks): ~$30/month
- **NAT Gateway** (2 AZs): ~$90/month
- **ECR Storage**: ~$1/month
- **CloudWatch Logs**: ~$5/month
- **Route 53**: ~$0.50/month

**Total**: ~$142/month

### Cost Reduction Options

1. **Single AZ**: Remove second NAT Gateway (-$45/month)
2. **Fargate Spot**: Use spot pricing (-50% on compute)
3. **Smaller Tasks**: Reduce CPU/memory allocation
4. **Log Retention**: Reduce CloudWatch log retention

## Security Best Practices

1. **Network Security**
   - Private subnets for ECS tasks
   - Security groups with minimal access
   - VPC Flow Logs enabled

2. **Application Security**
   - HTTPS-only communication
   - Container runs as non-root user
   - Regular security updates

3. **Access Control**
   - IAM roles with least privilege
   - No hardcoded credentials
   - GitHub token in secure parameter

4. **Monitoring**
   - CloudTrail enabled
   - CloudWatch alarms configured
   - Container image scanning

## Next Steps

1. **Custom Domain**: Configure Route 53 for your domain
2. **Monitoring**: Set up additional CloudWatch dashboards
3. **Backup**: Implement database backup strategy
4. **Security**: Add WAF protection
5. **Performance**: Implement caching strategies