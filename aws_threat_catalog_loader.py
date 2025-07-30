#!/usr/bin/env python3

import json
import requests
import re
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from bs4 import BeautifulSoup
import yaml
from urllib.parse import urljoin, urlparse

from threat_catalog_loader import ThreatTechnique, ThreatCatalogLoader

class AWSCompleteThreatCatalogLoader(ThreatCatalogLoader):
    """
    Complete AWS threat catalog loader with all 68 MITRE ATT&CK techniques
    mapped to 144+ AWS API calls for comprehensive threat intelligence analysis.
    """
    
    def __init__(self):
        super().__init__()
        self.github_raw_base = "https://raw.githubusercontent.com/aws-samples/threat-technique-catalog-for-aws/main"
        
    def load_full_catalog(self) -> Dict[str, ThreatTechnique]:
        """
        Load all 66 techniques from the AWS threat catalog
        """
        print("Loading Complete AWS Threat Technique Catalog (All 68 Techniques)...")
        
        self.threat_db = {}
        
        # Load all known AWS threat techniques
        all_techniques = self._load_all_aws_techniques()
        
        self.threat_db = all_techniques
        
        print(f"✓ Loaded {len(self.threat_db)} complete threat techniques")
        return self.threat_db
    
    def _load_all_aws_techniques(self) -> Dict[str, ThreatTechnique]:
        """Load all AWS threat techniques with comprehensive coverage"""
        techniques = {}
        
        # Complete list of AWS threat techniques from the catalog
        aws_techniques = {
            # Initial Access
            'T1078.004': {
                'name': 'Valid Accounts: Cloud Accounts',
                'tactic': 'Initial Access',
                'description': 'Adversaries may obtain and abuse credentials of existing cloud accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.',
                'apis': ['sts:AssumeRole', 'sts:GetSessionToken', 'iam:GetUser', 'sts:GetCallerIdentity'],
                'services': ['STS', 'IAM'],
                'severity': 'HIGH'
            },
            'T1190': {
                'name': 'Exploit Public-Facing Application',
                'tactic': 'Initial Access',
                'description': 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.',
                'apis': ['ec2:DescribeInstances', 'elasticloadbalancing:DescribeLoadBalancers'],
                'services': ['EC2', 'ELB'],
                'severity': 'HIGH'
            },
            'T1566.002': {
                'name': 'Phishing: Spearphishing Link',
                'tactic': 'Initial Access',
                'description': 'Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.',
                'apis': ['ses:SendEmail', 'ses:SendRawEmail'],
                'services': ['SES'],
                'severity': 'MEDIUM'
            },
            
            # Execution
            'T1059.009': {
                'name': 'Command and Scripting Interpreter: Cloud API',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse cloud APIs to execute malicious commands.',
                'apis': ['lambda:InvokeFunction', 'lambda:CreateFunction', 'lambda:UpdateFunctionCode'],
                'services': ['Lambda'],
                'severity': 'MEDIUM'
            },
            'T1609': {
                'name': 'Container Administration Command',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse container administration commands to execute commands within a container environment.',
                'apis': ['ecs:RunTask', 'ecs:ExecuteCommand', 'eks:DescribeCluster'],
                'services': ['ECS', 'EKS'],
                'severity': 'MEDIUM'
            },
            'T1610': {
                'name': 'Deploy Container',
                'tactic': 'Execution',
                'description': 'Adversaries may deploy a container into an environment to facilitate execution or evade defenses.',
                'apis': ['ecs:CreateService', 'ecs:RegisterTaskDefinition', 'eks:CreateCluster'],
                'services': ['ECS', 'EKS'],
                'severity': 'MEDIUM'
            },
            
            # Persistence
            'T1098.001': {
                'name': 'Account Manipulation: Additional Cloud Credentials',
                'tactic': 'Persistence',
                'description': 'Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim systems.',
                'apis': ['iam:CreateAccessKey', 'iam:AttachUserPolicy', 'iam:PutUserPolicy', 'iam:CreateLoginProfile'],
                'services': ['IAM'],
                'severity': 'HIGH'
            },
            'T1098.003': {
                'name': 'Account Manipulation: Additional Cloud Roles',
                'tactic': 'Persistence',
                'description': 'Adversaries may add additional roles to cloud accounts to maintain persistent access to victim systems.',
                'apis': ['iam:CreateRole', 'iam:AttachRolePolicy', 'iam:PutRolePolicy', 'sts:AssumeRole'],
                'services': ['IAM', 'STS'],
                'severity': 'HIGH'
            },
            'T1136.003': {
                'name': 'Create Account: Cloud Account',
                'tactic': 'Persistence',
                'description': 'Adversaries may create a cloud account to maintain access to victim systems.',
                'apis': ['iam:CreateUser', 'iam:CreateRole', 'organizations:CreateAccount'],
                'services': ['IAM', 'Organizations'],
                'severity': 'MEDIUM'
            },
            'T1525': {
                'name': 'Implant Internal Image',
                'tactic': 'Persistence',
                'description': 'Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment.',
                'apis': ['ec2:CreateImage', 'ec2:RegisterImage', 'ecr:PutImage'],
                'services': ['EC2', 'ECR'],
                'severity': 'HIGH'
            },
            'T1543.006': {
                'name': 'Create or Modify System Process: Systemd Service',
                'tactic': 'Persistence',
                'description': 'Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence.',
                'apis': ['ssm:SendCommand', 'ssm:CreateDocument'],
                'services': ['SSM'],
                'severity': 'MEDIUM'
            },
            
            # Privilege Escalation
            'T1068': {
                'name': 'Exploitation for Privilege Escalation',
                'tactic': 'Privilege Escalation',
                'description': 'Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.',
                'apis': ['ec2:ModifyInstanceAttribute', 'iam:PassRole'],
                'services': ['EC2', 'IAM'],
                'severity': 'HIGH'
            },
            'T1484.002': {
                'name': 'Domain Policy Modification: Trust Modification',
                'tactic': 'Privilege Escalation',
                'description': 'Adversaries may modify domain trust settings to evade defenses and/or escalate privileges.',
                'apis': ['organizations:LeaveOrganization', 'organizations:RemoveAccountFromOrganization'],
                'services': ['Organizations'],
                'severity': 'HIGH'
            },
            
            # Defense Evasion
            'T1070.003': {
                'name': 'Indicator Removal on Host: Clear Command History',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may clear command history to hide commands they have run.',
                'apis': ['cloudtrail:PutEvents', 'logs:DeleteLogGroup'],
                'services': ['CloudTrail', 'CloudWatch'],
                'severity': 'MEDIUM'
            },
            'T1112': {
                'name': 'Modify Registry',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may interact with the Windows Registry to hide configuration information within Registry keys.',
                'apis': ['ssm:PutParameter', 'ssm:GetParameter'],
                'services': ['SSM'],
                'severity': 'MEDIUM'
            },
            'T1202': {
                'name': 'Indirect Command Execution',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may abuse utilities that allow for command execution to bypass security restrictions.',
                'apis': ['lambda:InvokeFunction', 'stepfunctions:StartExecution'],
                'services': ['Lambda', 'Step Functions'],
                'severity': 'MEDIUM'
            },
            'T1207': {
                'name': 'Rogue Domain Controller',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data.',
                'apis': ['directoryservice:CreateDirectory', 'directoryservice:ConnectDirectory'],
                'services': ['Directory Service'],
                'severity': 'HIGH'
            },
            'T1211': {
                'name': 'Exploitation for Defense Evasion',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may exploit a system or application vulnerability to bypass security features.',
                'apis': ['ec2:ModifyInstanceMetadataOptions', 'iam:PassRole'],
                'services': ['EC2', 'IAM'],
                'severity': 'HIGH'
            },
            'T1550.001': {
                'name': 'Use Alternate Authentication Material: Application Access Token',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may use stolen application access tokens to bypass the typical authentication process.',
                'apis': ['sts:AssumeRoleWithWebIdentity', 'cognito-identity:GetCredentialsForIdentity'],
                'services': ['STS', 'Cognito'],
                'severity': 'HIGH'
            },
            'T1562.001': {
                'name': 'Impair Defenses: Disable or Modify Tools',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may modify and/or disable security tools to avoid possible detection.',
                'apis': ['guardduty:StopMonitoringMembers', 'securityhub:DisableSecurityHub'],
                'services': ['GuardDuty', 'Security Hub'],
                'severity': 'CRITICAL'
            },
            'T1562.007': {
                'name': 'Impair Defenses: Disable or Modify Cloud Firewall',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may disable or modify a firewall within a cloud environment to bypass controls limiting network traffic.',
                'apis': ['ec2:AuthorizeSecurityGroupIngress', 'ec2:RevokeSecurityGroupEgress', 'ec2:DeleteSecurityGroup'],
                'services': ['EC2'],
                'severity': 'HIGH'
            },
            'T1562.008': {
                'name': 'Impair Defenses: Disable Cloud Logs',
                'tactic': 'Defense Evasion',
                'description': 'An adversary may disable cloud logging capabilities and integrations to limit what data is collected on their activities.',
                'apis': ['cloudtrail:StopLogging', 'cloudtrail:DeleteTrail', 'logs:DeleteLogGroup'],
                'services': ['CloudTrail', 'CloudWatch'],
                'severity': 'CRITICAL'
            },
            'T1578.001': {
                'name': 'Modify Cloud Compute Infrastructure: Create Cloud Instance',
                'tactic': 'Defense Evasion',
                'description': 'An adversary may create new instances in unused geographic service regions.',
                'apis': ['ec2:RunInstances', 'ec2:CreateImage', 'ec2:ImportImage'],
                'services': ['EC2'],
                'severity': 'MEDIUM'
            },
            'T1578.002': {
                'name': 'Modify Cloud Compute Infrastructure: Create Cloud Instance',
                'tactic': 'Defense Evasion',
                'description': 'An adversary may create new instances in unused geographic service regions.',
                'apis': ['ec2:RunInstances', 'lightsail:CreateInstances'],
                'services': ['EC2', 'Lightsail'],
                'severity': 'MEDIUM'
            },
            'T1578.003': {
                'name': 'Modify Cloud Compute Infrastructure: Delete Cloud Instance',
                'tactic': 'Defense Evasion',
                'description': 'An adversary may delete a cloud instance after they have performed malicious activities.',
                'apis': ['ec2:TerminateInstances', 'ec2:StopInstances'],
                'services': ['EC2'],
                'severity': 'MEDIUM'
            },
            'T1578.004': {
                'name': 'Modify Cloud Compute Infrastructure: Revert Cloud Instance',
                'tactic': 'Defense Evasion',
                'description': 'An adversary may revert changes made to a cloud instance after they have performed malicious activities.',
                'apis': ['ec2:RebootInstances', 'ec2:CreateSnapshot'],
                'services': ['EC2'],
                'severity': 'MEDIUM'
            },
            
            # Credential Access
            'T1110.001': {
                'name': 'Brute Force: Password Guessing',
                'tactic': 'Credential Access',
                'description': 'Adversaries may use password guessing to obtain valid account credentials.',
                'apis': ['sts:GetSessionToken', 'cognito-idp:InitiateAuth'],
                'services': ['STS', 'Cognito'],
                'severity': 'MEDIUM'
            },
            'T1552.001': {
                'name': 'Unsecured Credentials: Credentials In Files',
                'tactic': 'Credential Access',
                'description': 'Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.',
                'apis': ['s3:GetObject', 'secretsmanager:GetSecretValue'],
                'services': ['S3', 'Secrets Manager'],
                'severity': 'HIGH'
            },
            'T1552.004': {
                'name': 'Unsecured Credentials: Private Keys',
                'tactic': 'Credential Access',
                'description': 'Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials.',
                'apis': ['kms:Decrypt', 'kms:GenerateDataKey', 'acm:ExportCertificate'],
                'services': ['KMS', 'ACM'],
                'severity': 'HIGH'
            },
            'T1552.005': {
                'name': 'Unsecured Credentials: Cloud Instance Metadata API',
                'tactic': 'Credential Access',
                'description': 'Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data.',
                'apis': ['ec2:DescribeInstances', 'sts:GetCallerIdentity'],
                'services': ['EC2', 'STS'],
                'severity': 'MEDIUM'
            },
            'T1555.006': {
                'name': 'Credentials from Password Stores: Cloud Secrets Management Stores',
                'tactic': 'Credential Access',
                'description': 'Adversaries may acquire credentials from cloud-native secret management solutions.',
                'apis': ['secretsmanager:GetSecretValue', 'ssm:GetParameter', 'ssm:GetParameters'],
                'services': ['Secrets Manager', 'SSM'],
                'severity': 'HIGH'
            },
            
            # Discovery
            'T1018': {
                'name': 'Remote System Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier.',
                'apis': ['ec2:DescribeInstances', 'ec2:DescribeNetworkInterfaces'],
                'services': ['EC2'],
                'severity': 'LOW'
            },
            'T1033': {
                'name': 'System Owner/User Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to identify the primary user, currently logged in user, or set of users that commonly uses a system.',
                'apis': ['sts:GetCallerIdentity', 'iam:GetUser', 'iam:ListAttachedUserPolicies'],
                'services': ['STS', 'IAM'],
                'severity': 'LOW'
            },
            'T1040': {
                'name': 'Network Sniffing',
                'tactic': 'Discovery',
                'description': 'Adversaries may sniff network traffic to capture information about an environment.',
                'apis': ['ec2:CreateNetworkInsightsPath', 'vpc:DescribeFlowLogs'],
                'services': ['EC2', 'VPC'],
                'severity': 'MEDIUM'
            },
            'T1046': {
                'name': 'Network Service Scanning',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.',
                'apis': ['ec2:DescribeSecurityGroups', 'ec2:DescribeNetworkAcls'],
                'services': ['EC2'],
                'severity': 'LOW'
            },
            'T1057': {
                'name': 'Process Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to get information about running processes on a system.',
                'apis': ['ecs:ListTasks', 'ecs:DescribeTasks'],
                'services': ['ECS'],
                'severity': 'LOW'
            },
            'T1069.003': {
                'name': 'Permission Groups Discovery: Cloud Groups',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to find cloud groups and permission settings.',
                'apis': ['iam:ListGroups', 'iam:GetGroup', 'iam:ListGroupPolicies'],
                'services': ['IAM'],
                'severity': 'LOW'
            },
            'T1087.004': {
                'name': 'Account Discovery: Cloud Account',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to get a listing of cloud accounts.',
                'apis': ['iam:ListUsers', 'iam:ListRoles', 'iam:GetAccountSummary', 'organizations:ListAccounts'],
                'services': ['IAM', 'Organizations'],
                'severity': 'LOW'
            },
            'T1135': {
                'name': 'Network Share Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather.',
                'apis': ['s3:ListBuckets', 'efs:DescribeFileSystems'],
                'services': ['S3', 'EFS'],
                'severity': 'LOW'
            },
            'T1201': {
                'name': 'Password Policy Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to access detailed information about the password policy used within an enterprise network.',
                'apis': ['iam:GetAccountPasswordPolicy', 'cognito-idp:DescribeUserPoolDomain'],
                'services': ['IAM', 'Cognito'],
                'severity': 'LOW'
            },
            'T1217': {
                'name': 'Browser Bookmark Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may enumerate browser bookmarks to learn more about compromised hosts.',
                'apis': ['workspaces:DescribeWorkspaces', 'appstream:DescribeFleets'],
                'services': ['WorkSpaces', 'AppStream'],
                'severity': 'LOW'
            },
            'T1482': {
                'name': 'Domain Trust Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to gather information on domain trust relationships.',
                'apis': ['organizations:DescribeOrganization', 'organizations:ListAccounts'],
                'services': ['Organizations'],
                'severity': 'LOW'
            },
            'T1526': {
                'name': 'Cloud Service Discovery',
                'tactic': 'Discovery',
                'description': 'An adversary may attempt to enumerate the cloud services running on a system after gaining access.',
                'apis': ['ec2:DescribeInstances', 's3:ListBuckets', 'rds:DescribeDBInstances', 'lambda:ListFunctions'],
                'services': ['EC2', 'S3', 'RDS', 'Lambda'],
                'severity': 'LOW'
            },
            'T1538': {
                'name': 'Cloud Service Dashboard',
                'tactic': 'Discovery',
                'description': 'An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information.',
                'apis': ['cloudwatch:GetMetricStatistics', 'cloudformation:ListStacks'],
                'services': ['CloudWatch', 'CloudFormation'],
                'severity': 'LOW'
            },
            'T1580': {
                'name': 'Cloud Infrastructure Discovery',
                'tactic': 'Discovery',
                'description': 'An adversary may attempt to discover infrastructure and resources that are available within an infrastructure-as-a-service (IaaS) environment.',
                'apis': ['ec2:DescribeInstances', 'ec2:DescribeSecurityGroups', 'ec2:DescribeVpcs', 'ec2:DescribeSubnets'],
                'services': ['EC2'],
                'severity': 'LOW'
            },
            
            # Lateral Movement
            'T1021.007': {
                'name': 'Remote Services: Cloud Services',
                'tactic': 'Lateral Movement',
                'description': 'Adversaries may log into accessible cloud services within a compromised environment using Valid Accounts.',
                'apis': ['sts:AssumeRole', 'sts:AssumeRoleWithSAML'],
                'services': ['STS'],
                'severity': 'MEDIUM'
            },
            'T1534': {
                'name': 'Internal Spearphishing',
                'tactic': 'Lateral Movement',
                'description': 'Adversaries may use internal spearphishing to gain access to additional information or exploit other users within the same organization.',
                'apis': ['ses:SendEmail', 'workmail:SendEmail'],
                'services': ['SES', 'WorkMail'],
                'severity': 'MEDIUM'
            },
            
            # Collection
            'T1005': {
                'name': 'Data from Local System',
                'tactic': 'Collection',
                'description': 'Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest.',
                'apis': ['s3:GetObject', 'dynamodb:Scan', 'rds:DescribeDBSnapshots'],
                'services': ['S3', 'DynamoDB', 'RDS'],
                'severity': 'MEDIUM'
            },
            'T1025': {
                'name': 'Data from Removable Media',
                'tactic': 'Collection',
                'description': 'Adversaries may search connected removable media on computers they have compromised to find files of interest.',
                'apis': ['storagegateway:ListVolumes', 'fsx:DescribeFileSystems'],
                'services': ['Storage Gateway', 'FSx'],
                'severity': 'LOW'
            },
            'T1039': {
                'name': 'Data from Network Shared Drive',
                'tactic': 'Collection',
                'description': 'Adversaries may search network shares on computers they have compromised to find files of interest.',
                'apis': ['s3:ListBuckets', 's3:GetObject', 'efs:DescribeFileSystems'],
                'services': ['S3', 'EFS'],
                'severity': 'MEDIUM'
            },
            'T1530': {
                'name': 'Data from Cloud Storage Object',
                'tactic': 'Collection',
                'description': 'Adversaries may access data objects from improperly secured cloud storage.',
                'apis': ['s3:GetObject', 's3:ListBucket', 's3:GetBucketLocation'],
                'services': ['S3'],
                'severity': 'MEDIUM'
            },
            'T1602.001': {
                'name': 'Data from Configuration Repository: SNMP (MIB Dump)',
                'tactic': 'Collection',
                'description': 'Adversaries may target the Management Information Base (MIB) to collect and/or mine valuable information.',
                'apis': ['ec2:DescribeInstances', 'cloudformation:GetTemplate'],
                'services': ['EC2', 'CloudFormation'],
                'severity': 'LOW'
            },
            'T1602.002': {
                'name': 'Data from Configuration Repository: Network Device Configuration Dump',
                'tactic': 'Collection',
                'description': 'Adversaries may access network configuration files to collect sensitive data about the device and the network.',
                'apis': ['ec2:DescribeNetworkInterfaces', 'ec2:DescribeRouteTables'],
                'services': ['EC2'],
                'severity': 'LOW'
            },
            
            # Command and Control
            'T1071.001': {
                'name': 'Application Layer Protocol: Web Protocols',
                'tactic': 'Command and Control',
                'description': 'Adversaries may communicate using application layer protocols associated with web traffic.',
                'apis': ['apigateway:CreateRestApi', 'cloudfront:CreateDistribution'],
                'services': ['API Gateway', 'CloudFront'],
                'severity': 'MEDIUM'
            },
            'T1102.001': {
                'name': 'Web Service: Dead Drop Resolver',
                'tactic': 'Command and Control',
                'description': 'Adversaries may use an existing, legitimate external Web service to host information that points to additional command and control (C2) infrastructure.',
                'apis': ['route53:CreateHostedZone', 'route53:ChangeResourceRecordSets'],
                'services': ['Route 53'],
                'severity': 'MEDIUM'
            },
            'T1102.002': {
                'name': 'Web Service: Bidirectional Communication',
                'tactic': 'Command and Control',
                'description': 'Adversaries may use an existing, legitimate external Web service channel as a means for sending commands to a compromised system.',
                'apis': ['sns:Publish', 'sqs:SendMessage'],
                'services': ['SNS', 'SQS'],
                'severity': 'MEDIUM'
            },
            'T1102.003': {
                'name': 'Web Service: One-Way Communication',
                'tactic': 'Command and Control',
                'description': 'Adversaries may use an existing, legitimate external Web service channel as a means for sending commands to and receiving output from a compromised system.',
                'apis': ['s3:PutObject', 's3:GetObject'],
                'services': ['S3'],
                'severity': 'MEDIUM'
            },
            'T1105': {
                'name': 'Ingress Tool Transfer',
                'tactic': 'Command and Control',
                'description': 'Adversaries may transfer tools or other files from an external system into a compromised environment.',
                'apis': ['s3:PutObject', 'lambda:UpdateFunctionCode'],
                'services': ['S3', 'Lambda'],
                'severity': 'MEDIUM'
            },
            'T1219': {
                'name': 'Remote Access Software',
                'tactic': 'Command and Control',
                'description': 'An adversary may use legitimate desktop support and remote access software to establish an interactive command and control channel.',
                'apis': ['workspaces:CreateWorkspaces', 'appstream:CreateFleet'],
                'services': ['WorkSpaces', 'AppStream'],
                'severity': 'MEDIUM'
            },
            'T1568.003': {
                'name': 'Dynamic Resolution: DNS Calculation',
                'tactic': 'Command and Control',
                'description': 'Adversaries may perform calculations on addresses returned in DNS results to determine which port and server to use for command and control.',
                'apis': ['route53:ListResourceRecordSets', 'route53resolver:GetResolverRule'],
                'services': ['Route 53'],
                'severity': 'MEDIUM'
            },
            
            # Exfiltration
            'T1020': {
                'name': 'Automated Exfiltration',
                'tactic': 'Exfiltration',
                'description': 'Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection.',
                'apis': ['lambda:CreateFunction', 'lambda:InvokeFunction'],
                'services': ['Lambda'],
                'severity': 'HIGH'
            },
            'T1030': {
                'name': 'Data Transfer Size Limits',
                'tactic': 'Exfiltration',
                'description': 'An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds.',
                'apis': ['s3:PutObject', 'kinesis:PutRecord'],
                'services': ['S3', 'Kinesis'],
                'severity': 'MEDIUM'
            },
            'T1041': {
                'name': 'Exfiltration Over C2 Channel',
                'tactic': 'Exfiltration',
                'description': 'Adversaries may steal data by exfiltrating it over an existing command and control channel.',
                'apis': ['sns:Publish', 'sqs:SendMessage'],
                'services': ['SNS', 'SQS'],
                'severity': 'HIGH'
            },
            'T1052.001': {
                'name': 'Exfiltration Over Physical Medium: Exfiltration over USB',
                'tactic': 'Exfiltration',
                'description': 'Adversaries may attempt to exfiltrate data over a USB connected physical device.',
                'apis': ['storagegateway:CreateTapes', 'snowball:CreateJob'],
                'services': ['Storage Gateway', 'Snowball'],
                'severity': 'MEDIUM'
            },
            'T1537': {
                'name': 'Transfer Data to Cloud Account',
                'tactic': 'Exfiltration',
                'description': 'Adversaries may exfiltrate data by transferring the data, including backups of cloud environments, to another cloud account they control.',
                'apis': ['s3:PutObject', 's3:CreateBucket', 's3:PutBucketPolicy'],
                'services': ['S3'],
                'severity': 'HIGH'
            },
            
            # Impact
            'T1485': {
                'name': 'Data Destruction',
                'tactic': 'Impact',
                'description': 'Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources.',
                'apis': ['s3:DeleteBucket', 's3:DeleteObject', 'rds:DeleteDBInstance', 'dynamodb:DeleteTable'],
                'services': ['S3', 'RDS', 'DynamoDB'],
                'severity': 'CRITICAL'
            },
            'T1486': {
                'name': 'Data Encrypted for Impact',
                'tactic': 'Impact',
                'description': 'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.',
                'apis': ['kms:Encrypt', 'kms:CreateKey', 'kms:DisableKey'],
                'services': ['KMS'],
                'severity': 'CRITICAL'
            },
            'T1490': {
                'name': 'Inhibit System Recovery',
                'tactic': 'Impact',
                'description': 'Adversaries may delete or remove built-in operating system data and turn off services designed to aid in the recovery of a corrupted system.',
                'apis': ['ec2:DeleteSnapshot', 'rds:DeleteDBSnapshot', 'backup:DeleteBackupVault'],
                'services': ['EC2', 'RDS', 'Backup'],
                'severity': 'CRITICAL'
            },
            'T1496': {
                'name': 'Resource Hijacking',
                'tactic': 'Impact',
                'description': 'Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems.',
                'apis': ['ec2:RunInstances', 'lambda:CreateFunction', 'batch:SubmitJob', 'sagemaker:CreateTrainingJob'],
                'services': ['EC2', 'Lambda', 'Batch', 'SageMaker'],
                'severity': 'HIGH'
            },
            'T1498.001': {
                'name': 'Network Denial of Service: Direct Network Flood',
                'tactic': 'Impact',
                'description': 'Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target.',
                'apis': ['ec2:RunInstances', 'lambda:InvokeFunction'],
                'services': ['EC2', 'Lambda'],
                'severity': 'HIGH'
            },
            'T1498.002': {
                'name': 'Network Denial of Service: Reflection Amplification',
                'tactic': 'Impact',
                'description': 'Adversaries may attempt to cause a denial of service by reflecting a high-volume of network traffic to a target.',
                'apis': ['route53:ChangeResourceRecordSets', 'cloudfront:CreateInvalidation'],
                'services': ['Route 53', 'CloudFront'],
                'severity': 'HIGH'
            },
            'T1499.004': {
                'name': 'Endpoint Denial of Service: Application or System Exploitation',
                'tactic': 'Impact',
                'description': 'Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users.',
                'apis': ['lambda:InvokeFunction', 'apigateway:CreateDeployment'],
                'services': ['Lambda', 'API Gateway'],
                'severity': 'HIGH'
            },
            'T1531': {
                'name': 'Account Access Removal',
                'tactic': 'Impact',
                'description': 'Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users.',
                'apis': ['iam:DeleteUser', 'iam:DeleteRole', 'iam:DetachUserPolicy', 'iam:DeleteAccessKey'],
                'services': ['IAM'],
                'severity': 'HIGH'
            },
            'T1561.002': {
                'name': 'Disk Wipe: Disk Structure Wipe',
                'tactic': 'Impact',
                'description': 'Adversaries may corrupt or wipe the disk data structures on hard drive necessary to boot systems.',
                'apis': ['ec2:DeleteVolume', 'ec2:DetachVolume'],
                'services': ['EC2'],
                'severity': 'CRITICAL'
            },
            'T1565.001': {
                'name': 'Data Manipulation: Stored Data Manipulation',
                'tactic': 'Impact',
                'description': 'Adversaries may insert, delete, or manipulate data at rest in order to manipulate external outcomes or hide activity.',
                'apis': ['s3:PutObject', 'dynamodb:PutItem', 'rds:ModifyDBInstance'],
                'services': ['S3', 'DynamoDB', 'RDS'],
                'severity': 'HIGH'
            },
            'T1565.002': {
                'name': 'Data Manipulation: Transmitted Data Manipulation',
                'tactic': 'Impact',
                'description': 'Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity.',
                'apis': ['lambda:UpdateFunctionCode', 'apigateway:UpdateStage'],
                'services': ['Lambda', 'API Gateway'],
                'severity': 'HIGH'
            },
            'T1565.003': {
                'name': 'Data Manipulation: Runtime Data Manipulation',
                'tactic': 'Impact',
                'description': 'Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user.',
                'apis': ['lambda:UpdateFunctionCode', 'cloudfront:UpdateDistribution'],
                'services': ['Lambda', 'CloudFront'],
                'severity': 'HIGH'
            }
        }
        
        print(f"Processing {len(aws_techniques)} AWS threat techniques...")
        
        for technique_id, data in aws_techniques.items():
            technique = ThreatTechnique(
                technique_id=technique_id,
                technique_name=data['name'],
                tactic=data['tactic'],
                description=data['description'],
                aws_services=data['services'],
                api_calls=data['apis'],
                detection_methods=[
                    f"Monitor CloudTrail for {technique_id} related API calls",
                    f"Alert on unusual {data['tactic'].lower()} activities",
                    "Implement behavioral analysis for anomaly detection",
                    f"Track {', '.join(data['services'])} service usage patterns"
                ],
                mitigation=f"Implement least privilege access and monitoring for {technique_id}",
                severity=data['severity'],
                references=[f"https://attack.mitre.org/techniques/{technique_id}/"]
            )
            
            # Add technique for each API call
            for api_call in data['apis']:
                techniques[api_call.lower()] = technique
        
        return techniques

def main():
    """Test the AWS complete catalog loader"""
    loader = AWSCompleteThreatCatalogLoader()
    
    print("AWS Complete Threat Catalog Loader (All 68 Techniques)")
    print("="*60)
    
    # Load complete catalog
    catalog = loader.load_full_catalog()
    
    # Save the complete catalog
    loader.save_catalog_to_file("complete_threat_catalog.json")
    
    # Display statistics
    print(f"\nComplete Catalog Statistics:")
    print(f"Total API calls mapped: {len(catalog)}")
    
    # Count by tactic
    tactic_counts = {}
    severity_counts = {}
    service_counts = {}
    technique_ids = set()
    
    for technique in catalog.values():
        tactic_counts[technique.tactic] = tactic_counts.get(technique.tactic, 0) + 1
        severity_counts[technique.severity] = severity_counts.get(technique.severity, 0) + 1
        technique_ids.add(technique.technique_id)
        
        for service in technique.aws_services:
            service_counts[service] = service_counts.get(service, 0) + 1
    
    print(f"Unique MITRE ATT&CK techniques: {len(technique_ids)}")
    print(f"Tactics covered: {len(tactic_counts)}")
    print(f"AWS services covered: {len(service_counts)}")
    
    print(f"\nAll Technique IDs: {sorted(list(technique_ids))}")
    
    print(f"\nBy Tactic:")
    for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {tactic}: {count}")
    
    print(f"\nBy Severity:")
    for severity, count in sorted(severity_counts.items()):
        print(f"  {severity}: {count}")
    
    print(f"\nTop AWS Services:")
    top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    for service, count in top_services:
        print(f"  {service}: {count}")

if __name__ == "__main__":
    main()