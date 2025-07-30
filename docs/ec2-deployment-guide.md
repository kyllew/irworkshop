# EC2 Deployment Guide

This guide will help you deploy the AWS Threat Intelligence Analyzer from an EC2 instance, avoiding local Docker issues and ensuring reliable deployment.

## Prerequisites

1. **EC2 Instance**: Amazon Linux 2 or Ubuntu 20.04+ recommended
2. **IAM Role**: Attached to EC2 instance with deployment permissions
3. **Security Group**: Allow SSH access (port 22) and outbound internet access
4. **Storage**: At least 10GB free space for Docker builds

## Step 1: Launch EC2 Instance

### Option A: Using AWS Console
1. Launch a new EC2 instance
2. Choose Amazon Linux 2 AMI
3. Select t3.medium or larger (for Docker builds)
4. Configure security group to allow SSH
5. Attach IAM role (create if needed)

### Option B: Using AWS CLI
```bash
# Create IAM role for deployment
aws iam create-role --role-name ThreatAnalyzerDeploymentRole --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

# Attach the deployment policy
aws iam put-role-policy --role-name ThreatAnalyzerDeploymentRole --policy-name DeploymentPolicy --policy-document file://infrastructure/ec2-deployment-role-policy.json

# Create instance profile
aws iam create-instance-profile --instance-profile-name ThreatAnalyzerDeploymentProfile
aws iam add-role-to-instance-profile --instance-profile-name ThreatAnalyzerDeploymentProfile --role-name ThreatAnalyzerDeploymentRole

# Launch EC2 instance (replace with your key pair and security group)
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --count 1 \
  --instance-type t3.medium \
  --key-name your-key-pair \
  --security-group-ids sg-xxxxxxxxx \
  --iam-instance-profile Name=ThreatAnalyzerDeploymentProfile \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=ThreatAnalyzerDeployment}]'
```

## Step 2: Connect to EC2 Instance

```bash
# SSH to your instance
ssh -i your-key.pem ec2-user@your-instance-ip

# Or if using Session Manager
aws ssm start-session --target i-xxxxxxxxx
```

## Step 3: Clone and Setup Project

```bash
# Update system
sudo yum update -y

# Install git (if not already installed by the script)
sudo yum install -y git

# Clone your repository
git clone https://github.com/kyllew/irworkshop.git
cd irworkshop

# Make deployment script executable
chmod +x scripts/deploy-from-ec2.sh
```

## Step 4: Run Deployment

### Complete Deployment (Recommended)
```bash
# Run complete deployment
./scripts/deploy-from-ec2.sh deploy
```

### Step-by-Step Deployment
```bash
# 1. Build and push Docker image only
./scripts/deploy-from-ec2.sh build-push

# 2. Deploy infrastructure only
./scripts/deploy-from-ec2.sh infrastructure

# 3. Deploy CI/CD pipeline only
./scripts/deploy-from-ec2.sh cicd
```

## Step 5: Monitor Deployment

```bash
# Check deployment status
./scripts/deploy-from-ec2.sh status

# View stack outputs (including ALB DNS)
./scripts/deploy-from-ec2.sh outputs
```

## Troubleshooting

### Common Issues

#### 1. Docker Permission Denied
```bash
# Add user to docker group
sudo usermod -a -G docker ec2-user

# Log out and back in, or run:
newgrp docker
```

#### 2. AWS Credentials Not Found
```bash
# Check if IAM role is attached
aws sts get-caller-identity

# If not working, configure credentials manually
aws configure
```

#### 3. ECR Login Failed
```bash
# Verify ECR repository exists
aws ecr describe-repositories --repository-names threat-analyzer

# Check region configuration
aws configure get region
```

#### 4. CloudFormation Stack Creation Failed
```bash
# Check stack events
aws cloudformation describe-stack-events --stack-name threat-analyzer-infrastructure

# Check specific error in CloudFormation console
```

#### 5. Docker Build Failed
```bash
# Check available disk space
df -h

# Clean up Docker images
docker system prune -a

# Check Docker daemon status
sudo systemctl status docker
```

### Logs and Monitoring

#### CloudFormation Logs
```bash
# View stack events
aws cloudformation describe-stack-events --stack-name threat-analyzer-infrastructure --region us-east-1
```

#### ECS Service Logs
```bash
# Get log group name
aws logs describe-log-groups --log-group-name-prefix /ecs/threat-analyzer

# View recent logs
aws logs tail /ecs/threat-analyzer --follow
```

#### Application Logs
```bash
# View application logs in CloudWatch
aws logs describe-log-streams --log-group-name /ecs/threat-analyzer --order-by LastEventTime --descending --max-items 1
```

## Cleanup

### Remove All Resources
```bash
# Delete all deployed resources
./scripts/deploy-from-ec2.sh cleanup
```

### Manual Cleanup
```bash
# Delete stacks manually
aws cloudformation delete-stack --stack-name threat-analyzer-cicd --region us-east-1
aws cloudformation delete-stack --stack-name threat-analyzer-infrastructure --region us-east-1

# Delete ECR repository
aws ecr delete-repository --repository-name threat-analyzer --force --region us-east-1

# Delete S3 bucket contents
aws s3 rm s3://wkkamaru-irworkshop --recursive
```

## Security Best Practices

1. **Use IAM Roles**: Always use IAM roles instead of access keys
2. **Principle of Least Privilege**: Only grant necessary permissions
3. **Security Groups**: Restrict access to minimum required ports
4. **VPC**: Use private subnets for EC2 instances when possible
5. **Logging**: Enable CloudTrail for audit logging

## Cost Optimization

1. **Instance Type**: Use t3.medium for deployment, then stop the instance
2. **Spot Instances**: Consider using spot instances for cost savings
3. **Auto Scaling**: Configure auto scaling for production workloads
4. **Resource Cleanup**: Always clean up resources when not needed

## Next Steps

After successful deployment:

1. **Access Application**: Use the ALB DNS name from stack outputs
2. **Configure Domain**: Set up custom domain if needed
3. **Monitor**: Set up CloudWatch alarms and monitoring
4. **Backup**: Configure automated backups for critical data
5. **Security**: Review and harden security configurations

## Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review CloudFormation stack events
3. Check application logs in CloudWatch
4. Verify IAM permissions
5. Ensure all prerequisites are met 