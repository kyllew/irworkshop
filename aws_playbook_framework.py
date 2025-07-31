#!/usr/bin/env python3

"""
AWS Customer Playbook Framework Integration
Integrates incident response playbooks with threat intelligence data
"""

import requests
from bs4 import BeautifulSoup
import json
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

@dataclass
class PlaybookStep:
    """Individual step in a playbook"""
    step_number: str
    title: str
    description: str
    actions: List[str]
    aws_apis: List[str] = None
    mitre_techniques: List[str] = None
    guardduty_findings: List[str] = None
    automation_possible: bool = False

@dataclass
class PlaybookSection:
    """Section of a playbook (e.g., Detection, Analysis, Containment)"""
    section_name: str
    description: str
    steps: List[PlaybookStep]

@dataclass
class IncidentPlaybook:
    """Complete incident response playbook"""
    playbook_id: str
    title: str
    description: str
    incident_type: str
    severity: str
    sections: List[PlaybookSection]
    related_mitre_tactics: List[str] = None
    related_guardduty_findings: List[str] = None
    aws_services: List[str] = None
    last_updated: str = None

class AWSPlaybookFrameworkIntegrator:
    """
    Integrates AWS Customer Playbook Framework with threat intelligence data
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.github_base = "https://raw.githubusercontent.com/aws-samples/aws-customer-playbook-framework/main/docs/"
        self.playbooks = {}
        
        # Mapping of playbook types to MITRE tactics
        self.playbook_to_mitre = {
            'Compromised_IAM_Credentials': [
                'Initial Access', 'Persistence', 'Privilege Escalation', 
                'Defense Evasion', 'Credential Access'
            ],
            'Data_Exfiltration': ['Collection', 'Exfiltration'],
            'DDoS_Response': ['Impact'],
            'EC2_Forensics': ['Discovery', 'Collection'],
            'Ransom_Response': ['Impact'],
            'S3_Public_Read_Access': ['Initial Access', 'Collection'],
            'Unauthorized_Network_Changes': [
                'Defense Evasion', 'Persistence', 'Lateral Movement', 'Impact'
            ]
        }
        
        # Common AWS APIs used in incident response
        self.incident_response_apis = {
            'investigation': [
                'cloudtrail:LookupEvents',
                'logs:FilterLogEvents',
                'iam:GetUser',
                'iam:ListAttachedUserPolicies',
                'sts:GetCallerIdentity',
                'guardduty:GetFindings'
            ],
            'containment': [
                'iam:AttachUserPolicy',
                'iam:DetachUserPolicy',
                'iam:DeleteAccessKey',
                'iam:PutUserPolicy',
                'ec2:StopInstances',
                'ec2:ModifyInstanceAttribute'
            ],
            'eradication': [
                'iam:DeleteUser',
                'iam:DeleteRole',
                'ec2:TerminateInstances',
                's3:DeleteBucket'
            ]
        }
    
    def load_s3_public_access_playbook(self) -> IncidentPlaybook:
        """Load the S3 Public Access playbook"""
        try:
            # Create the playbook structure based on the GitHub content
            playbook = IncidentPlaybook(
                playbook_id="s3_public_access",
                title="S3 Public Access",
                description="Response playbook for suspected or confirmed public access to S3 buckets",
                incident_type="Data Exposure",
                severity="High",
                sections=[],
                related_mitre_tactics=self.playbook_to_mitre.get('S3_Public_Read_Access', []),
                aws_services=['S3', 'CloudTrail', 'GuardDuty', 'Config', 'IAM'],
                last_updated=datetime.now().isoformat()
            )
            
            # Section 1: Incident Classification & Handling
            classification_steps = [
                PlaybookStep(
                    step_number="1.1",
                    title="Determine if this is an S3 public access incident",
                    description="Assess the nature and scope of the S3 bucket public access",
                    actions=[
                        "Review the initial alert or detection",
                        "Identify the affected S3 bucket(s)",
                        "Determine the scope of public access",
                        "Assess the sensitivity of exposed data"
                    ],
                    aws_apis=['s3:GetBucketAcl', 's3:GetBucketPolicy', 's3:GetBucketLocation'],
                    guardduty_findings=['Policy:S3/BucketAnonymousRead', 'Policy:S3/BucketAnonymousWrite']
                ),
                PlaybookStep(
                    step_number="1.2",
                    title="Determine the affected AWS account(s) and regions",
                    description="Identify all AWS accounts and regions that may be impacted",
                    actions=[
                        "Check if buckets are in multiple regions",
                        "Review cross-account bucket policies",
                        "Identify federated access patterns",
                        "Document all affected resources"
                    ],
                    aws_apis=['s3:ListBuckets', 's3:GetBucketLocation', 'organizations:ListAccounts'],
                    mitre_techniques=['T1087.004']  # Account Discovery: Cloud Account
                )
            ]
            
            # Section 2: Detection & Analysis
            detection_steps = [
                PlaybookStep(
                    step_number="2.1",
                    title="Review S3 bucket configuration and permissions",
                    description="Analyze bucket ACLs, policies, and public access settings",
                    actions=[
                        "Check bucket ACL for public read/write permissions",
                        "Review bucket policy for public access statements",
                        "Examine bucket public access block settings",
                        "Identify objects with public permissions",
                        "Review bucket versioning and MFA delete settings"
                    ],
                    aws_apis=[
                        's3:GetBucketAcl',
                        's3:GetBucketPolicy',
                        's3:GetBucketPolicyStatus',
                        's3:GetPublicAccessBlock',
                        's3:ListObjects',
                        's3:GetObjectAcl'
                    ],
                    mitre_techniques=['T1530'],  # Data from Cloud Storage Object
                    automation_possible=True
                ),
                PlaybookStep(
                    step_number="2.2",
                    title="Analyze CloudTrail logs for suspicious S3 activity",
                    description="Review CloudTrail events for unauthorized S3 access and modifications",
                    actions=[
                        "Search for S3 API calls from unknown IP addresses",
                        "Look for bucket policy modifications",
                        "Identify unusual data access patterns",
                        "Check for bulk download activities",
                        "Review object creation and deletion events"
                    ],
                    aws_apis=[
                        'cloudtrail:LookupEvents',
                        'logs:FilterLogEvents',
                        'logs:StartQuery'
                    ],
                    mitre_techniques=['T1530', 'T1041'],  # Data from Cloud Storage, Exfiltration Over C2
                    automation_possible=True
                ),
                PlaybookStep(
                    step_number="2.3",
                    title="Check GuardDuty findings and S3 access logs",
                    description="Review GuardDuty alerts and S3 server access logs for threats",
                    actions=[
                        "Review all GuardDuty findings related to S3",
                        "Analyze S3 server access logs for suspicious patterns",
                        "Check for data exfiltration indicators",
                        "Identify potential data mining activities"
                    ],
                    aws_apis=['guardduty:GetFindings', 'guardduty:ListFindings', 's3:GetBucketLogging'],
                    guardduty_findings=[
                        'Policy:S3/BucketAnonymousRead',
                        'Policy:S3/BucketAnonymousWrite',
                        'Exfiltration:S3/ObjectRead.Unusual'
                    ]
                ),
                PlaybookStep(
                    step_number="2.4",
                    title="Assess data sensitivity and compliance impact",
                    description="Evaluate the sensitivity of exposed data and regulatory implications",
                    actions=[
                        "Catalog the types of data in exposed buckets",
                        "Identify PII, PHI, or other sensitive information",
                        "Assess compliance requirements (GDPR, HIPAA, etc.)",
                        "Document potential business impact",
                        "Determine notification requirements"
                    ],
                    aws_apis=['s3:ListObjects', 's3:GetObject', 'macie:GetFindings']
                )
            ]
            
            # Section 3: Containment
            containment_steps = [
                PlaybookStep(
                    step_number="3.1",
                    title="Block public access to affected S3 buckets",
                    description="Immediately restrict public access to prevent further exposure",
                    actions=[
                        "Enable S3 Block Public Access at bucket level",
                        "Remove public read/write permissions from bucket ACL",
                        "Update bucket policy to remove public access statements",
                        "Document all changes made for audit trail"
                    ],
                    aws_apis=[
                        's3:PutPublicAccessBlock',
                        's3:PutBucketAcl',
                        's3:PutBucketPolicy'
                    ],
                    automation_possible=True
                ),
                PlaybookStep(
                    step_number="3.2",
                    title="Review and secure object-level permissions",
                    description="Check and fix public permissions on individual objects",
                    actions=[
                        "List all objects with public permissions",
                        "Remove public access from individual objects",
                        "Update object ACLs to private",
                        "Verify no objects remain publicly accessible"
                    ],
                    aws_apis=[
                        's3:ListObjects',
                        's3:GetObjectAcl',
                        's3:PutObjectAcl'
                    ],
                    automation_possible=True
                ),
                PlaybookStep(
                    step_number="3.3",
                    title="Implement additional access controls",
                    description="Add extra security measures to prevent future incidents",
                    actions=[
                        "Enable MFA Delete on versioned buckets",
                        "Configure bucket notifications for policy changes",
                        "Set up CloudWatch alarms for public access",
                        "Review and update IAM policies"
                    ],
                    aws_apis=[
                        's3:PutBucketVersioning',
                        's3:PutBucketNotification',
                        'cloudwatch:PutMetricAlarm',
                        'iam:ListPolicies'
                    ]
                )
            ]
            
            # Section 4: Eradication & Recovery
            eradication_steps = [
                PlaybookStep(
                    step_number="4.1",
                    title="Remove unauthorized access and clean up",
                    description="Remove any unauthorized access mechanisms and clean up artifacts",
                    actions=[
                        "Review and remove suspicious IAM users/roles",
                        "Revoke any unauthorized access keys",
                        "Clean up any malicious objects uploaded",
                        "Review cross-account access permissions"
                    ],
                    aws_apis=[
                        'iam:ListUsers',
                        'iam:DeleteUser',
                        'iam:ListAccessKeys',
                        'iam:DeleteAccessKey',
                        's3:DeleteObject'
                    ],
                    mitre_techniques=['T1098.001', 'T1136.003']  # Account Manipulation, Create Account
                ),
                PlaybookStep(
                    step_number="4.2",
                    title="Restore secure bucket configuration",
                    description="Implement proper security configuration for the S3 buckets",
                    actions=[
                        "Configure appropriate bucket policies",
                        "Set up proper IAM roles for legitimate access",
                        "Enable encryption at rest and in transit",
                        "Configure proper logging and monitoring"
                    ],
                    aws_apis=[
                        's3:PutBucketPolicy',
                        's3:PutBucketEncryption',
                        's3:PutBucketLogging',
                        'iam:CreateRole',
                        'iam:AttachRolePolicy'
                    ]
                ),
                PlaybookStep(
                    step_number="4.3",
                    title="Validate security posture",
                    description="Verify that all security measures are properly implemented",
                    actions=[
                        "Run AWS Config rules to check compliance",
                        "Perform security assessment of bucket configuration",
                        "Test access controls with different user roles",
                        "Verify monitoring and alerting is working"
                    ],
                    aws_apis=[
                        'config:GetComplianceDetailsByConfigRule',
                        's3:GetBucketPolicy',
                        's3:GetPublicAccessBlock'
                    ]
                )
            ]
            
            # Section 5: Post-Incident Activity
            post_incident_steps = [
                PlaybookStep(
                    step_number="5.1",
                    title="Document incident and lessons learned",
                    description="Capture comprehensive incident documentation and insights",
                    actions=[
                        "Document the complete incident timeline",
                        "Identify root cause of public access",
                        "Assess effectiveness of detection and response",
                        "Document data that may have been accessed",
                        "Prepare incident report for stakeholders"
                    ]
                ),
                PlaybookStep(
                    step_number="5.2",
                    title="Implement preventive measures",
                    description="Strengthen security posture to prevent similar incidents",
                    actions=[
                        "Implement organization-wide S3 public access blocks",
                        "Create AWS Config rules for S3 security compliance",
                        "Set up automated remediation for public buckets",
                        "Enhance security awareness training",
                        "Review and update data classification policies"
                    ]
                ),
                PlaybookStep(
                    step_number="5.3",
                    title="Compliance and notification activities",
                    description="Handle regulatory and business notification requirements",
                    actions=[
                        "Assess regulatory notification requirements",
                        "Notify affected customers if required",
                        "File necessary compliance reports",
                        "Update privacy policies if needed",
                        "Coordinate with legal and compliance teams"
                    ]
                )
            ]
            
            # Add all sections to the playbook
            playbook.sections = [
                PlaybookSection("Incident Classification & Handling", "Initial assessment and classification", classification_steps),
                PlaybookSection("Detection & Analysis", "Investigate and analyze the incident", detection_steps),
                PlaybookSection("Containment", "Contain the threat and prevent further exposure", containment_steps),
                PlaybookSection("Eradication & Recovery", "Remove threats and restore secure configuration", eradication_steps),
                PlaybookSection("Post-Incident Activity", "Learn, improve, and handle compliance requirements", post_incident_steps)
            ]
            
            return playbook
            
        except Exception as e:
            self.logger.error(f"Error loading S3 public access playbook: {str(e)}")
            return None

    def load_compromised_iam_playbook(self) -> IncidentPlaybook:
        """Load the Compromised IAM Credentials playbook"""
        try:
            # Create the playbook structure based on the GitHub content
            playbook = IncidentPlaybook(
                playbook_id="compromised_iam_credentials",
                title="Compromised IAM Credentials",
                description="Response playbook for suspected or confirmed compromise of AWS IAM credentials",
                incident_type="Credential Compromise",
                severity="High",
                sections=[],
                related_mitre_tactics=self.playbook_to_mitre.get('Compromised_IAM_Credentials', []),
                aws_services=['IAM', 'CloudTrail', 'GuardDuty', 'Config'],
                last_updated=datetime.now().isoformat()
            )
            
            # Section 1: Incident Classification & Handling
            classification_steps = [
                PlaybookStep(
                    step_number="1.1",
                    title="Determine if this is a compromised IAM credential incident",
                    description="Assess the nature and scope of the potential credential compromise",
                    actions=[
                        "Review the initial alert or detection",
                        "Identify the affected IAM user or role",
                        "Determine the potential impact scope"
                    ],
                    aws_apis=['iam:GetUser', 'iam:ListAttachedUserPolicies', 'sts:GetCallerIdentity'],
                    guardduty_findings=['UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration']
                ),
                PlaybookStep(
                    step_number="1.2", 
                    title="Determine the affected AWS account(s)",
                    description="Identify all AWS accounts that may be impacted",
                    actions=[
                        "Check if credentials are used across multiple accounts",
                        "Review cross-account role assumptions",
                        "Identify federated access patterns"
                    ],
                    aws_apis=['organizations:ListAccounts', 'sts:GetCallerIdentity'],
                    mitre_techniques=['T1087.004']  # Account Discovery: Cloud Account
                )
            ]
            
            # Section 2: Detection & Analysis
            detection_steps = [
                PlaybookStep(
                    step_number="2.1",
                    title="Review CloudTrail logs for suspicious activity",
                    description="Analyze CloudTrail events for indicators of compromise",
                    actions=[
                        "Search for unusual API calls from the compromised credentials",
                        "Look for access from unexpected IP addresses or locations",
                        "Identify privilege escalation attempts",
                        "Check for resource creation or modification"
                    ],
                    aws_apis=[
                        'cloudtrail:LookupEvents',
                        'logs:FilterLogEvents',
                        'logs:StartQuery'
                    ],
                    mitre_techniques=['T1078.004', 'T1098.001'],  # Valid Accounts, Account Manipulation
                    automation_possible=True
                ),
                PlaybookStep(
                    step_number="2.2",
                    title="Check GuardDuty findings",
                    description="Review GuardDuty alerts related to the compromised credentials",
                    actions=[
                        "Review all GuardDuty findings for the affected user/role",
                        "Analyze finding severity and confidence levels",
                        "Correlate findings with CloudTrail events"
                    ],
                    aws_apis=['guardduty:GetFindings', 'guardduty:ListFindings'],
                    guardduty_findings=[
                        'UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration',
                        'Stealth:IAMUser/CloudTrailLoggingDisabled',
                        'Policy:IAMUser/RootCredentialUsage'
                    ]
                ),
                PlaybookStep(
                    step_number="2.3",
                    title="Analyze IAM permissions and recent changes",
                    description="Review the permissions and recent modifications to the compromised identity",
                    actions=[
                        "List all policies attached to the user/role",
                        "Review recent policy changes",
                        "Check for new access keys or login profiles",
                        "Analyze permission boundaries and SCPs"
                    ],
                    aws_apis=[
                        'iam:ListAttachedUserPolicies',
                        'iam:ListUserPolicies', 
                        'iam:GetPolicy',
                        'iam:ListAccessKeys'
                    ],
                    mitre_techniques=['T1098.001', 'T1098.003']  # Account Manipulation
                )
            ]
            
            # Section 3: Containment
            containment_steps = [
                PlaybookStep(
                    step_number="3.1",
                    title="Disable compromised access keys",
                    description="Immediately disable all access keys for the compromised user",
                    actions=[
                        "List all access keys for the user",
                        "Deactivate (don't delete yet) all access keys",
                        "Document the access key IDs for investigation"
                    ],
                    aws_apis=[
                        'iam:ListAccessKeys',
                        'iam:UpdateAccessKey'
                    ],
                    automation_possible=True
                ),
                PlaybookStep(
                    step_number="3.2",
                    title="Reset console password and disable console access",
                    description="Prevent console access by the compromised user",
                    actions=[
                        "Delete the login profile to disable console access",
                        "Reset MFA devices if configured",
                        "Document the changes made"
                    ],
                    aws_apis=[
                        'iam:DeleteLoginProfile',
                        'iam:DeactivateMFADevice',
                        'iam:ListMFADevices'
                    ],
                    automation_possible=True
                ),
                PlaybookStep(
                    step_number="3.3",
                    title="Apply restrictive policy for investigation",
                    description="Attach a deny-all policy to prevent further damage while preserving evidence",
                    actions=[
                        "Create or attach an explicit deny policy",
                        "Ensure the policy doesn't interfere with logging",
                        "Document the policy attachment"
                    ],
                    aws_apis=[
                        'iam:AttachUserPolicy',
                        'iam:PutUserPolicy'
                    ],
                    automation_possible=True
                )
            ]
            
            # Section 4: Eradication & Recovery
            eradication_steps = [
                PlaybookStep(
                    step_number="4.1",
                    title="Remove malicious resources created by attacker",
                    description="Identify and remove any resources created by the compromised credentials",
                    actions=[
                        "Review CloudTrail for resource creation events",
                        "Identify and catalog malicious resources",
                        "Safely remove unauthorized resources",
                        "Check for backdoors or persistence mechanisms"
                    ],
                    aws_apis=[
                        'ec2:DescribeInstances',
                        'ec2:TerminateInstances',
                        'iam:ListUsers',
                        'iam:DeleteUser',
                        's3:ListBuckets'
                    ],
                    mitre_techniques=['T1098.001', 'T1136.003']  # Account Manipulation, Create Account
                ),
                PlaybookStep(
                    step_number="4.2",
                    title="Restore legitimate access",
                    description="Safely restore access for legitimate users",
                    actions=[
                        "Create new access keys if needed",
                        "Reset console password with strong authentication",
                        "Re-enable MFA with new devices",
                        "Apply principle of least privilege"
                    ],
                    aws_apis=[
                        'iam:CreateAccessKey',
                        'iam:CreateLoginProfile',
                        'iam:EnableMFADevice'
                    ]
                )
            ]
            
            # Section 5: Post-Incident Activity
            post_incident_steps = [
                PlaybookStep(
                    step_number="5.1",
                    title="Document lessons learned",
                    description="Capture insights and improvements for future incidents",
                    actions=[
                        "Document the attack timeline",
                        "Identify detection gaps",
                        "Review response effectiveness",
                        "Update security controls"
                    ]
                ),
                PlaybookStep(
                    step_number="5.2",
                    title="Implement preventive measures",
                    description="Strengthen security posture based on incident findings",
                    actions=[
                        "Review and update IAM policies",
                        "Enhance monitoring and alerting",
                        "Implement additional security controls",
                        "Conduct security awareness training"
                    ]
                )
            ]
            
            # Add all sections to the playbook
            playbook.sections = [
                PlaybookSection("Incident Classification & Handling", "Initial assessment and classification", classification_steps),
                PlaybookSection("Detection & Analysis", "Investigate and analyze the incident", detection_steps),
                PlaybookSection("Containment", "Contain the threat and prevent further damage", containment_steps),
                PlaybookSection("Eradication & Recovery", "Remove threats and restore normal operations", eradication_steps),
                PlaybookSection("Post-Incident Activity", "Learn and improve from the incident", post_incident_steps)
            ]
            
            return playbook
            
        except Exception as e:
            self.logger.error(f"Error loading compromised IAM playbook: {str(e)}")
            return None

    def load_unauthorized_network_changes_playbook(self) -> IncidentPlaybook:
        """Load the Unauthorized Network Changes playbook"""
        try:
            # Create the playbook structure based on the GitHub content
            playbook = IncidentPlaybook(
                playbook_id="unauthorized_network_changes",
                title="Unauthorized Network Changes",
                description="Response playbook for suspected or confirmed unauthorized changes to network configurations",
                incident_type="Network Security",
                severity="High",
                sections=[],
                related_mitre_tactics=self.playbook_to_mitre.get('Unauthorized_Network_Changes', []),
                aws_services=['VPC', 'EC2', 'CloudTrail', 'GuardDuty', 'Config', 'Security Groups', 'NACLs'],
                last_updated=datetime.now().isoformat()
            )
            
            # Section 1: Incident Classification & Handling
            classification_steps = [
                PlaybookStep(
                    step_number="1.1",
                    title="Determine if this is an unauthorized network change incident",
                    description="Assess the nature and scope of the network configuration changes",
                    actions=[
                        "Review the initial alert or detection",
                        "Identify the affected network resources (VPC, subnets, security groups, NACLs)",
                        "Determine the scope and impact of changes",
                        "Assess potential for data exfiltration or lateral movement"
                    ],
                    aws_apis=['ec2:DescribeVpcs', 'ec2:DescribeSecurityGroups', 'ec2:DescribeNetworkAcls'],
                    guardduty_findings=['Recon:EC2/PortProbeUnprotectedPort', 'UnauthorizedAccess:EC2/SSHBruteForce']
                ),
                PlaybookStep(
                    step_number="1.2",
                    title="Determine the affected AWS account(s) and regions",
                    description="Identify all AWS accounts and regions that may be impacted",
                    actions=[
                        "Check if changes span multiple regions",
                        "Review cross-account network connections",
                        "Identify VPC peering and transit gateway connections",
                        "Document all affected network resources"
                    ],
                    aws_apis=['ec2:DescribeRegions', 'ec2:DescribeVpcPeeringConnections', 'ec2:DescribeTransitGateways'],
                    mitre_techniques=['T1087.004']  # Account Discovery: Cloud Account
                )
            ]
            
            # Section 2: Detection & Analysis
            detection_steps = [
                PlaybookStep(
                    step_number="2.1",
                    title="Analyze network configuration changes",
                    description="Review recent changes to network security configurations",
                    actions=[
                        "Review security group rule changes",
                        "Check NACL modifications",
                        "Analyze route table changes",
                        "Examine VPC and subnet configurations",
                        "Review internet gateway and NAT gateway changes"
                    ],
                    aws_apis=[
                        'ec2:DescribeSecurityGroups',
                        'ec2:DescribeNetworkAcls',
                        'ec2:DescribeRouteTables',
                        'ec2:DescribeInternetGateways',
                        'ec2:DescribeNatGateways'
                    ],
                    mitre_techniques=['T1562.007'],  # Impair Defenses: Disable or Modify Cloud Firewall
                    automation_possible=True
                ),
                PlaybookStep(
                    step_number="2.2",
                    title="Review CloudTrail logs for network changes",
                    description="Analyze CloudTrail events for unauthorized network modifications",
                    actions=[
                        "Search for EC2 network-related API calls",
                        "Look for security group and NACL modifications",
                        "Identify unusual source IP addresses or user agents",
                        "Check for bulk network configuration changes",
                        "Review VPC and subnet creation/deletion events"
                    ],
                    aws_apis=[
                        'cloudtrail:LookupEvents',
                        'logs:FilterLogEvents',
                        'logs:StartQuery'
                    ],
                    mitre_techniques=['T1562.007', 'T1070.003'],  # Impair Defenses, Indicator Removal
                    automation_possible=True
                ),
                PlaybookStep(
                    step_number="2.3",
                    title="Check GuardDuty and VPC Flow Logs",
                    description="Review GuardDuty findings and VPC Flow Logs for suspicious network activity",
                    actions=[
                        "Review all GuardDuty findings related to network activity",
                        "Analyze VPC Flow Logs for unusual traffic patterns",
                        "Check for data exfiltration indicators",
                        "Identify potential lateral movement activities",
                        "Look for connections to known malicious IPs"
                    ],
                    aws_apis=['guardduty:GetFindings', 'ec2:DescribeFlowLogs', 'logs:FilterLogEvents'],
                    guardduty_findings=[
                        'Recon:EC2/PortProbeUnprotectedPort',
                        'UnauthorizedAccess:EC2/SSHBruteForce',
                        'Backdoor:EC2/C&CActivity.B!DNS'
                    ]
                ),
                PlaybookStep(
                    step_number="2.4",
                    title="Assess impact and exposure",
                    description="Evaluate the security impact of the network changes",
                    actions=[
                        "Identify newly exposed services and ports",
                        "Check for overly permissive security group rules",
                        "Assess potential for data exfiltration",
                        "Review affected instances and their data sensitivity",
                        "Document compliance and regulatory implications"
                    ],
                    aws_apis=['ec2:DescribeInstances', 'ec2:DescribeSecurityGroups', 'config:GetComplianceDetailsByConfigRule']
                )
            ]
            
            # Section 3: Containment
            containment_steps = [
                PlaybookStep(
                    step_number="3.1",
                    title="Block unauthorized network access",
                    description="Immediately restrict network access to prevent further compromise",
                    actions=[
                        "Remove overly permissive security group rules",
                        "Block suspicious IP addresses in NACLs",
                        "Disable internet gateways if necessary",
                        "Isolate affected instances using security groups"
                    ],
                    aws_apis=[
                        'ec2:RevokeSecurityGroupIngress',
                        'ec2:RevokeSecurityGroupEgress',
                        'ec2:CreateNetworkAclEntry',
                        'ec2:ModifyInstanceAttribute'
                    ],
                    automation_possible=True
                ),
                PlaybookStep(
                    step_number="3.2",
                    title="Implement network segmentation",
                    description="Create network barriers to prevent lateral movement",
                    actions=[
                        "Create restrictive security groups for affected resources",
                        "Implement NACL rules to block suspicious traffic",
                        "Isolate compromised subnets if necessary",
                        "Review and restrict VPC peering connections"
                    ],
                    aws_apis=[
                        'ec2:CreateSecurityGroup',
                        'ec2:AuthorizeSecurityGroupIngress',
                        'ec2:CreateNetworkAcl',
                        'ec2:AssociateNetworkAcl'
                    ],
                    automation_possible=True
                ),
                PlaybookStep(
                    step_number="3.3",
                    title="Enable enhanced monitoring",
                    description="Increase network monitoring and logging capabilities",
                    actions=[
                        "Enable VPC Flow Logs for affected VPCs",
                        "Configure CloudWatch alarms for network anomalies",
                        "Enable GuardDuty DNS logging",
                        "Set up AWS Config rules for network compliance"
                    ],
                    aws_apis=[
                        'ec2:CreateFlowLogs',
                        'cloudwatch:PutMetricAlarm',
                        'guardduty:UpdateDetector',
                        'config:PutConfigRule'
                    ]
                )
            ]
            
            # Section 4: Eradication & Recovery
            eradication_steps = [
                PlaybookStep(
                    step_number="4.1",
                    title="Remove unauthorized network configurations",
                    description="Clean up malicious network configurations and restore secure settings",
                    actions=[
                        "Remove unauthorized security group rules",
                        "Delete malicious NACL entries",
                        "Remove unauthorized route table entries",
                        "Clean up unauthorized VPC peering connections"
                    ],
                    aws_apis=[
                        'ec2:RevokeSecurityGroupIngress',
                        'ec2:RevokeSecurityGroupEgress',
                        'ec2:DeleteNetworkAclEntry',
                        'ec2:DeleteRoute',
                        'ec2:DeleteVpcPeeringConnection'
                    ],
                    mitre_techniques=['T1562.007']  # Impair Defenses: Disable or Modify Cloud Firewall
                ),
                PlaybookStep(
                    step_number="4.2",
                    title="Restore secure network configuration",
                    description="Implement proper network security configuration",
                    actions=[
                        "Apply principle of least privilege to security groups",
                        "Implement proper NACL configurations",
                        "Configure secure routing tables",
                        "Enable network access logging and monitoring"
                    ],
                    aws_apis=[
                        'ec2:AuthorizeSecurityGroupIngress',
                        'ec2:CreateNetworkAclEntry',
                        'ec2:CreateRoute',
                        'ec2:CreateFlowLogs'
                    ]
                ),
                PlaybookStep(
                    step_number="4.3",
                    title="Validate network security posture",
                    description="Verify that all network security measures are properly implemented",
                    actions=[
                        "Run AWS Config compliance checks",
                        "Perform network security assessment",
                        "Test network access controls",
                        "Verify monitoring and alerting is working"
                    ],
                    aws_apis=[
                        'config:GetComplianceDetailsByConfigRule',
                        'ec2:DescribeSecurityGroups',
                        'ec2:DescribeNetworkAcls'
                    ]
                )
            ]
            
            # Section 5: Post-Incident Activity
            post_incident_steps = [
                PlaybookStep(
                    step_number="5.1",
                    title="Document incident and lessons learned",
                    description="Capture comprehensive incident documentation and insights",
                    actions=[
                        "Document the complete incident timeline",
                        "Identify root cause of unauthorized changes",
                        "Assess effectiveness of detection and response",
                        "Document network changes that were made",
                        "Prepare incident report for stakeholders"
                    ]
                ),
                PlaybookStep(
                    step_number="5.2",
                    title="Implement preventive measures",
                    description="Strengthen network security posture to prevent similar incidents",
                    actions=[
                        "Implement AWS Config rules for network compliance",
                        "Set up automated remediation for network violations",
                        "Enhance network monitoring and alerting",
                        "Review and update network security policies",
                        "Implement infrastructure as code for network resources"
                    ]
                ),
                PlaybookStep(
                    step_number="5.3",
                    title="Update security controls and training",
                    description="Improve security controls and team capabilities",
                    actions=[
                        "Update network security baselines",
                        "Enhance security awareness training",
                        "Review and update incident response procedures",
                        "Implement additional network security tools",
                        "Conduct tabletop exercises for network incidents"
                    ]
                )
            ]
            
            # Add all sections to the playbook
            playbook.sections = [
                PlaybookSection("Incident Classification & Handling", "Initial assessment and classification", classification_steps),
                PlaybookSection("Detection & Analysis", "Investigate and analyze the incident", detection_steps),
                PlaybookSection("Containment", "Contain the threat and prevent further damage", containment_steps),
                PlaybookSection("Eradication & Recovery", "Remove threats and restore secure configuration", eradication_steps),
                PlaybookSection("Post-Incident Activity", "Learn, improve, and strengthen security posture", post_incident_steps)
            ]
            
            return playbook
            
        except Exception as e:
            self.logger.error(f"Error loading unauthorized network changes playbook: {str(e)}")
            return None
    
    def correlate_with_mitre_techniques(self, playbook: IncidentPlaybook, mitre_db: Dict) -> Dict:
        """Correlate playbook steps with MITRE ATT&CK techniques"""
        correlations = []
        
        for section in playbook.sections:
            for step in section.steps:
                if step.mitre_techniques:
                    for technique_id in step.mitre_techniques:
                        # Find matching techniques in the database
                        matching_techniques = []
                        for api_call, technique in mitre_db.items():
                            if technique.technique_id == technique_id:
                                matching_techniques.append({
                                    'api_call': api_call,
                                    'technique_name': technique.technique_name,
                                    'tactic': technique.tactic,
                                    'severity': technique.severity
                                })
                        
                        if matching_techniques:
                            correlations.append({
                                'playbook_step': f"{step.step_number}: {step.title}",
                                'section': section.section_name,
                                'mitre_technique_id': technique_id,
                                'matching_techniques': matching_techniques
                            })
        
        return {
            'playbook_id': playbook.playbook_id,
            'correlations': correlations,
            'total_correlations': len(correlations)
        }
    
    def correlate_with_guardduty_findings(self, playbook: IncidentPlaybook, guardduty_findings: List) -> Dict:
        """Correlate playbook steps with GuardDuty findings"""
        correlations = []
        
        for section in playbook.sections:
            for step in section.steps:
                if step.guardduty_findings:
                    for finding_type in step.guardduty_findings:
                        # Find matching GuardDuty findings
                        matching_findings = []
                        for finding in guardduty_findings:
                            if finding_type in finding.finding_type:
                                matching_findings.append({
                                    'finding_type': finding.finding_type,
                                    'category': finding.category,
                                    'severity': finding.severity,
                                    'description': finding.description
                                })
                        
                        if matching_findings:
                            correlations.append({
                                'playbook_step': f"{step.step_number}: {step.title}",
                                'section': section.section_name,
                                'guardduty_finding': finding_type,
                                'matching_findings': matching_findings
                            })
        
        return {
            'playbook_id': playbook.playbook_id,
            'correlations': correlations,
            'total_correlations': len(correlations)
        }
    
    def generate_automated_response_script(self, playbook: IncidentPlaybook) -> str:
        """Generate automated response script for automatable steps"""
        script_lines = [
            "#!/bin/bash",
            "# Automated Incident Response Script",
            f"# Generated for: {playbook.title}",
            f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "set -e",
            "",
            "# Configuration",
            "COMPROMISED_USER=\"$1\"",
            "AWS_REGION=\"${AWS_REGION:-us-east-1}\"",
            "",
            "if [ -z \"$COMPROMISED_USER\" ]; then",
            "    echo \"Usage: $0 <compromised-username>\"",
            "    exit 1",
            "fi",
            "",
            "echo \"Starting automated response for compromised user: $COMPROMISED_USER\"",
            ""
        ]
        
        for section in playbook.sections:
            if section.section_name == "Containment":
                script_lines.append(f"# {section.section_name}")
                script_lines.append("")
                
                for step in section.steps:
                    if step.automation_possible:
                        script_lines.append(f"# Step {step.step_number}: {step.title}")
                        
                        if "access keys" in step.title.lower():
                            script_lines.extend([
                                "echo \"Disabling access keys for user: $COMPROMISED_USER\"",
                                "aws iam list-access-keys --user-name \"$COMPROMISED_USER\" --query 'AccessKeyMetadata[].AccessKeyId' --output text | while read key_id; do",
                                "    if [ ! -z \"$key_id\" ]; then",
                                "        echo \"Deactivating access key: $key_id\"",
                                "        aws iam update-access-key --user-name \"$COMPROMISED_USER\" --access-key-id \"$key_id\" --status Inactive",
                                "    fi",
                                "done",
                                ""
                            ])
                        
                        elif "console password" in step.title.lower():
                            script_lines.extend([
                                "echo \"Disabling console access for user: $COMPROMISED_USER\"",
                                "aws iam delete-login-profile --user-name \"$COMPROMISED_USER\" 2>/dev/null || echo \"No login profile found\"",
                                ""
                            ])
                        
                        elif "restrictive policy" in step.title.lower():
                            script_lines.extend([
                                "echo \"Applying restrictive policy to user: $COMPROMISED_USER\"",
                                "cat > /tmp/deny-all-policy.json << 'EOF'",
                                "{",
                                "    \"Version\": \"2012-10-17\",",
                                "    \"Statement\": [",
                                "        {",
                                "            \"Effect\": \"Deny\",",
                                "            \"Action\": \"*\",",
                                "            \"Resource\": \"*\"",
                                "        }",
                                "    ]",
                                "}",
                                "EOF",
                                "aws iam put-user-policy --user-name \"$COMPROMISED_USER\" --policy-name \"IncidentResponseDenyAll\" --policy-document file:///tmp/deny-all-policy.json",
                                "rm /tmp/deny-all-policy.json",
                                ""
                            ])
        
        script_lines.extend([
            "echo \"Automated containment steps completed for user: $COMPROMISED_USER\"",
            "echo \"Please proceed with manual investigation and analysis steps\"",
            ""
        ])
        
        return "\n".join(script_lines)
    
    def export_playbook_to_json(self, playbook: IncidentPlaybook, filename: str = None) -> str:
        """Export playbook to JSON format"""
        if not filename:
            filename = f"{playbook.playbook_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(asdict(playbook), f, indent=2)
            
            self.logger.info(f"Playbook exported to {filename}")
            return filename
            
        except Exception as e:
            self.logger.error(f"Error exporting playbook: {str(e)}")
            return None

def main():
    """Example usage of the AWS Playbook Framework Integrator"""
    print("AWS Customer Playbook Framework Integration")
    print("=" * 45)
    
    # Initialize integrator
    integrator = AWSPlaybookFrameworkIntegrator()
    
    try:
        # Load the Compromised IAM Credentials playbook
        print("\nLoading Compromised IAM Credentials playbook...")
        playbook = integrator.load_compromised_iam_playbook()
        
        if playbook:
            print(f"✓ Loaded playbook: {playbook.title}")
            print(f"  - Sections: {len(playbook.sections)}")
            print(f"  - Total steps: {sum(len(section.steps) for section in playbook.sections)}")
            print(f"  - Related MITRE tactics: {', '.join(playbook.related_mitre_tactics)}")
            
            # Display section summary
            print(f"\nPlaybook sections:")
            for section in playbook.sections:
                automatable_steps = sum(1 for step in section.steps if step.automation_possible)
                print(f"  - {section.section_name}: {len(section.steps)} steps ({automatable_steps} automatable)")
            
            # Generate automation script
            print(f"\nGenerating automation script...")
            script = integrator.generate_automated_response_script(playbook)
            script_filename = f"incident_response_{playbook.playbook_id}.sh"
            
            with open(script_filename, 'w') as f:
                f.write(script)
            
            print(f"✓ Automation script saved to: {script_filename}")
            
            # Export playbook
            json_filename = integrator.export_playbook_to_json(playbook)
            if json_filename:
                print(f"✓ Playbook exported to: {json_filename}")
        
        else:
            print("✗ Failed to load playbook")
    
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()