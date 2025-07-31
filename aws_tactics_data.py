#!/usr/bin/env python3

"""
AWS MITRE ATT&CK Tactics Data
Official tactics descriptions from the AWS Threat Technique Catalog
"""

from typing import Dict, List
from dataclasses import dataclass

@dataclass
class TacticInfo:
    """Information about a MITRE ATT&CK tactic in AWS context"""
    name: str
    short_description: str
    description: str
    aws_context: str
    techniques_count: int = 0
    example_techniques: List[str] = None

# Official AWS MITRE ATT&CK Tactics Data
AWS_TACTICS_DATA = {
    "Initial Access": TacticInfo(
        name="Initial Access",
        short_description="The adversary is trying to get into your AWS environment",
        description="Initial Access consists of techniques that use various entry vectors to gain their initial foothold within an AWS environment. Techniques used to gain a foothold include exploiting weaknesses on public-facing web servers. Footholds gained through initial access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.",
        aws_context="Attackers may exploit misconfigured S3 buckets, compromise IAM credentials, exploit vulnerabilities in public-facing AWS services, or use phishing to obtain valid cloud account credentials.",
        example_techniques=["Valid Accounts: Cloud Accounts", "Exploit Public-Facing Application", "Phishing: Spearphishing Link"]
    ),
    
    "Execution": TacticInfo(
        name="Execution",
        short_description="The adversary is trying to run malicious code",
        description="Execution consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques used to gain execution include command and scripting interpreters. This tactic represents the various ways an adversary can execute code, including cloud APIs and container administration commands.",
        aws_context="Attackers may execute code through Lambda functions, EC2 instances, ECS containers, or by modifying existing AWS resources to run malicious payloads. Cloud APIs provide a powerful execution environment for adversaries.",
        example_techniques=["Command and Scripting Interpreter: Cloud API", "Container Administration Command", "Deploy Container"]
    ),
    
    "Persistence": TacticInfo(
        name="Persistence",
        short_description="The adversary is trying to maintain their foothold",
        description="Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems.",
        aws_context="Attackers may create additional IAM users, modify existing policies, establish backdoors in Lambda functions or EC2 instances, create new cloud accounts, or implant malicious images in container registries.",
        example_techniques=["Account Manipulation: Additional Cloud Credentials", "Create Account: Cloud Account", "Implant Internal Image"]
    ),
    
    "Privilege Escalation": TacticInfo(
        name="Privilege Escalation",
        short_description="The adversary is trying to gain higher-level permissions",
        description="Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives.",
        aws_context="Attackers may exploit overprivileged IAM roles, assume roles with higher permissions, exploit misconfigurations in AWS services, or abuse the IAM PassRole permission to escalate privileges within the cloud environment.",
        example_techniques=["Exploitation for Privilege Escalation", "Domain Policy Modification: Trust Modification"]
    ),
    
    "Defense Evasion": TacticInfo(
        name="Defense Evasion",
        short_description="The adversary is trying to avoid being detected",
        description="Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries also leverage and abuse trusted processes to hide and masquerade their malware.",
        aws_context="Attackers may disable CloudTrail logging, modify security groups, stop GuardDuty monitoring, delete log groups, create instances in unused regions, or use techniques to avoid detection by AWS security services.",
        example_techniques=["Impair Defenses: Disable Cloud Logs", "Modify Cloud Compute Infrastructure", "Use Alternate Authentication Material"]
    ),
    
    "Credential Access": TacticInfo(
        name="Credential Access",
        short_description="The adversary is trying to steal account names and passwords",
        description="Credential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credentials include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals.",
        aws_context="Attackers may extract credentials from EC2 metadata, compromise IAM access keys, exploit secrets stored in AWS services like Secrets Manager or Parameter Store, or access private keys from certificate services.",
        example_techniques=["Unsecured Credentials: Cloud Instance Metadata API", "Credentials from Password Stores: Cloud Secrets Management Stores", "Brute Force: Password Guessing"]
    ),
    
    "Discovery": TacticInfo(
        name="Discovery",
        short_description="The adversary is trying to figure out your environment",
        description="Discovery consists of techniques an adversary may use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act. They also allow adversaries to explore what they can control and what's around their entry point.",
        aws_context="Attackers may enumerate AWS resources, discover IAM policies, list S3 buckets, describe EC2 instances, gather information about the cloud infrastructure and services in use, or explore network configurations and security groups.",
        example_techniques=["Cloud Service Discovery", "Account Discovery: Cloud Account", "Cloud Infrastructure Discovery"]
    ),
    
    "Lateral Movement": TacticInfo(
        name="Lateral Movement",
        short_description="The adversary is trying to move through your environment",
        description="Lateral Movement consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it. Reaching their objective often involves pivoting through multiple systems and accounts.",
        aws_context="Attackers may move between AWS accounts, assume cross-account roles, pivot through different AWS services and regions, or use cloud services to facilitate internal spearphishing campaigns within the organization.",
        example_techniques=["Remote Services: Cloud Services", "Internal Spearphishing"]
    ),
    
    "Collection": TacticInfo(
        name="Collection",
        short_description="The adversary is trying to gather data of interest to their goal",
        description="Collection consists of techniques adversaries may use to gather information and the sources information is collected from that are relevant to following through on the adversary's objectives. Frequently, the next goal after collecting data is to steal (exfiltrate) the data.",
        aws_context="Attackers may collect data from S3 buckets, RDS databases, DynamoDB tables, EFS file systems, or other AWS storage services, often targeting sensitive business or personal information stored in cloud repositories.",
        example_techniques=["Data from Cloud Storage Object", "Data from Local System", "Data from Network Shared Drive"]
    ),
    
    "Command and Control": TacticInfo(
        name="Command and Control",
        short_description="The adversary is trying to communicate with compromised systems to control them",
        description="Command and Control consists of techniques that adversaries may use to communicate with systems under their control within a victim network. Adversaries commonly attempt to mimic normal, expected traffic to avoid detection. There are many ways an adversary can establish command and control with various levels of stealth.",
        aws_context="Attackers may use AWS services like Lambda, API Gateway, SQS, SNS, S3, or CloudFront to establish command and control channels that blend in with legitimate AWS traffic, making detection more difficult.",
        example_techniques=["Application Layer Protocol: Web Protocols", "Web Service: Bidirectional Communication", "Ingress Tool Transfer"]
    ),
    
    "Exfiltration": TacticInfo(
        name="Exfiltration",
        short_description="The adversary is trying to steal data",
        description="Exfiltration consists of techniques that adversaries may use to steal data from your network. Once they've collected data, adversaries often package it to avoid detection while removing it. This can include compression and encryption. Techniques for getting data out of a target network typically include transferring it over their command and control channel or an alternate channel.",
        aws_context="Attackers may exfiltrate data through S3 transfers, database exports, automated Lambda functions, or by using AWS's own data transfer services to move stolen information to external locations while avoiding detection.",
        example_techniques=["Automated Exfiltration", "Data Transfer Size Limits", "Exfiltration Over Web Service"]
    ),
    
    "Impact": TacticInfo(
        name="Impact",
        short_description="The adversary is trying to manipulate, interrupt, or destroy your systems and data",
        description="Impact consists of techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes. Techniques used for impact can include destroying or tampering with data. In some cases, business processes can look fine, but may have been altered to benefit the adversaries' goals.",
        aws_context="Attackers may delete S3 buckets, terminate EC2 instances, modify databases, encrypt data for ransom, disrupt AWS services to cause business impact, or cover their tracks by destroying evidence of their activities.",
        example_techniques=["Data Destruction", "Resource Hijacking", "Service Stop"]
    )
}

def get_tactic_info(tactic_name: str) -> TacticInfo:
    """Get information about a specific tactic"""
    return AWS_TACTICS_DATA.get(tactic_name, TacticInfo(
        name=tactic_name,
        short_description="Unknown tactic",
        description="No description available for this tactic.",
        aws_context="No AWS-specific context available."
    ))

def get_all_tactics() -> Dict[str, TacticInfo]:
    """Get all tactics information"""
    return AWS_TACTICS_DATA

def update_tactic_counts(tactic_counts: Dict[str, int]) -> None:
    """Update the technique counts for each tactic"""
    for tactic_name, count in tactic_counts.items():
        if tactic_name in AWS_TACTICS_DATA:
            AWS_TACTICS_DATA[tactic_name].techniques_count = count

def update_tactic_techniques(threat_db: Dict) -> None:
    """Update the example techniques for each tactic with actual techniques from the database"""
    tactic_techniques = {}
    
    # Group techniques by tactic
    for api_call, technique in threat_db.items():
        tactic = technique.tactic
        if tactic not in tactic_techniques:
            tactic_techniques[tactic] = []
        
        # Add technique if not already in the list (avoid duplicates)
        technique_name = technique.technique_name
        if technique_name not in tactic_techniques[tactic]:
            tactic_techniques[tactic].append(technique_name)
    
    # Update the tactics data with actual techniques (limit to top 5 for display)
    for tactic_name, techniques in tactic_techniques.items():
        if tactic_name in AWS_TACTICS_DATA:
            # Sort techniques and take top 5 for display
            sorted_techniques = sorted(techniques)[:5]
            AWS_TACTICS_DATA[tactic_name].example_techniques = sorted_techniques