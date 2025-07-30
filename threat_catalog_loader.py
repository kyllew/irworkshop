#!/usr/bin/env python3

import json
import requests
import yaml
import os
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import re
from urllib.parse import urljoin
import time

@dataclass
class ThreatTechnique:
    """Enhanced data class for threat technique information"""
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    aws_services: List[str]
    api_calls: List[str]
    detection_methods: List[str]
    mitigation: str
    severity: str = "MEDIUM"
    references: List[str] = None
    playbook_url: str = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []

class ThreatCatalogLoader:
    """
    Loads threat intelligence from AWS threat catalog and playbook framework
    """
    
    def __init__(self):
        self.base_catalog_url = "https://raw.githubusercontent.com/aws-samples/threat-technique-catalog-for-aws/main"
        self.playbook_base_url = "https://raw.githubusercontent.com/aws-samples/aws-customer-playbook-framework/main"
        self.threat_db = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AWS-Threat-Intel-Loader/1.0'
        })
    
    def load_full_catalog(self) -> Dict[str, ThreatTechnique]:
        """
        Load the complete threat catalog from both sources
        
        Returns:
            Dict: Complete threat database
        """
        print("Loading AWS Threat Technique Catalog...")
        
        # Load main catalog
        catalog_data = self._load_threat_catalog()
        
        # Load playbook data
        playbook_data = self._load_playbook_framework()
        
        # Merge and process data
        self.threat_db = self._merge_threat_data(catalog_data, playbook_data)
        
        print(f"Loaded {len(self.threat_db)} threat techniques")
        return self.threat_db
    
    def _load_threat_catalog(self) -> Dict:
        """Load data from the threat technique catalog repository"""
        catalog_data = {}
        
        try:
            # Get the main catalog structure
            catalog_url = f"{self.base_catalog_url}/docs/catalog.json"
            response = self._safe_request(catalog_url)
            
            if response and response.status_code == 200:
                catalog_data = response.json()
                print("✓ Main catalog loaded")
            else:
                # Fallback: try to load individual technique files
                catalog_data = self._load_individual_techniques()
                
        except Exception as e:
            print(f"Error loading main catalog: {e}")
            catalog_data = self._load_individual_techniques()
        
        return catalog_data
    
    def _load_individual_techniques(self) -> Dict:
        """Load individual technique files from the catalog"""
        techniques = {}
        
        # Common MITRE ATT&CK technique IDs for AWS
        technique_ids = [
            "T1098.001",  # Account Manipulation: Additional Cloud Credentials
            "T1136.003",  # Create Account: Cloud Account
            "T1562.008",  # Impair Defenses: Disable Cloud Logs
            "T1033",      # System Owner/User Discovery
            "T1087.004",  # Account Discovery: Cloud Account
            "T1526",      # Cloud Service Discovery
            "T1580",      # Cloud Infrastructure Discovery
            "T1552.005",  # Unsecured Credentials: Cloud Instance Metadata API
            "T1078.004",  # Valid Accounts: Cloud Accounts
            "T1110.001",  # Brute Force: Password Guessing
        ]
        
        for tech_id in technique_ids:
            try:
                # Try different possible file structures
                possible_paths = [
                    f"techniques/{tech_id}.json",
                    f"docs/techniques/{tech_id}.json",
                    f"catalog/{tech_id}.json"
                ]
                
                for path in possible_paths:
                    url = f"{self.base_catalog_url}/{path}"
                    response = self._safe_request(url)
                    
                    if response and response.status_code == 200:
                        technique_data = response.json()
                        techniques[tech_id] = technique_data
                        print(f"✓ Loaded technique {tech_id}")
                        break
                        
            except Exception as e:
                print(f"Could not load technique {tech_id}: {e}")
                continue
        
        return {"techniques": techniques}
    
    def _load_playbook_framework(self) -> Dict:
        """Load data from the AWS customer playbook framework"""
        playbook_data = {}
        
        try:
            # Load incident response playbooks
            playbooks_url = f"{self.playbook_base_url}/playbooks"
            
            # Common playbook files
            playbook_files = [
                "EC2_Forensics.md",
                "IAM_Credential_Compromise.md", 
                "S3_Public_Access.md",
                "CloudTrail_Disabled.md",
                "Unusual_API_Activity.md"
            ]
            
            for playbook_file in playbook_files:
                try:
                    url = f"{playbooks_url}/{playbook_file}"
                    response = self._safe_request(url)
                    
                    if response and response.status_code == 200:
                        playbook_content = response.text
                        playbook_data[playbook_file] = self._parse_playbook_content(playbook_content)
                        print(f"✓ Loaded playbook {playbook_file}")
                        
                except Exception as e:
                    print(f"Could not load playbook {playbook_file}: {e}")
                    continue
                    
        except Exception as e:
            print(f"Error loading playbook framework: {e}")
        
        return playbook_data
    
    def _parse_playbook_content(self, content: str) -> Dict:
        """Parse markdown playbook content to extract threat information"""
        playbook_info = {
            "api_calls": [],
            "detection_methods": [],
            "mitigation_steps": [],
            "aws_services": []
        }
        
        # Extract API calls (look for AWS API patterns)
        api_pattern = r'([a-zA-Z0-9]+:[A-Z][a-zA-Z0-9]*)'
        api_calls = re.findall(api_pattern, content)
        playbook_info["api_calls"] = list(set(api_calls))
        
        # Extract AWS services
        service_pattern = r'\b(IAM|EC2|S3|CloudTrail|CloudWatch|Lambda|RDS|VPC|ECS|EKS|SQS|SNS)\b'
        services = re.findall(service_pattern, content, re.IGNORECASE)
        playbook_info["aws_services"] = list(set([s.upper() for s in services]))
        
        # Extract detection methods (look for detection/monitoring sections)
        detection_section = re.search(r'## Detection.*?(?=##|\Z)', content, re.DOTALL | re.IGNORECASE)
        if detection_section:
            detection_text = detection_section.group(0)
            # Extract bullet points or numbered items
            detection_items = re.findall(r'[-*]\s+(.+)', detection_text)
            playbook_info["detection_methods"] = detection_items
        
        # Extract mitigation steps
        mitigation_section = re.search(r'## (Mitigation|Response|Remediation).*?(?=##|\Z)', content, re.DOTALL | re.IGNORECASE)
        if mitigation_section:
            mitigation_text = mitigation_section.group(0)
            mitigation_items = re.findall(r'[-*]\s+(.+)', mitigation_text)
            playbook_info["mitigation_steps"] = mitigation_items
        
        return playbook_info
    
    def _merge_threat_data(self, catalog_data: Dict, playbook_data: Dict) -> Dict[str, ThreatTechnique]:
        """Merge data from both sources into unified threat database"""
        merged_db = {}
        
        # Process catalog data
        if "techniques" in catalog_data:
            for tech_id, tech_data in catalog_data["techniques"].items():
                threat_technique = self._process_catalog_technique(tech_id, tech_data)
                if threat_technique:
                    # Use API calls as keys for quick lookup
                    for api_call in threat_technique.api_calls:
                        merged_db[api_call.lower()] = threat_technique
        
        # Enhance with playbook data
        for playbook_name, playbook_info in playbook_data.items():
            self._enhance_with_playbook_data(merged_db, playbook_name, playbook_info)
        
        # Add hardcoded techniques for common scenarios
        self._add_common_techniques(merged_db)
        
        return merged_db
    
    def _process_catalog_technique(self, tech_id: str, tech_data: Dict) -> Optional[ThreatTechnique]:
        """Process individual technique from catalog"""
        try:
            # Extract basic information
            name = tech_data.get("name", f"Technique {tech_id}")
            description = tech_data.get("description", "")
            tactic = tech_data.get("tactic", ["Unknown"])[0] if isinstance(tech_data.get("tactic"), list) else tech_data.get("tactic", "Unknown")
            
            # Extract AWS-specific information
            aws_services = tech_data.get("aws_services", [])
            api_calls = tech_data.get("api_calls", [])
            
            # Extract detection and mitigation
            detection_methods = tech_data.get("detection", [])
            mitigation = tech_data.get("mitigation", "")
            
            return ThreatTechnique(
                technique_id=tech_id,
                technique_name=name,
                tactic=tactic,
                description=description,
                aws_services=aws_services,
                api_calls=api_calls,
                detection_methods=detection_methods,
                mitigation=mitigation,
                references=[f"https://attack.mitre.org/techniques/{tech_id}/"]
            )
            
        except Exception as e:
            print(f"Error processing technique {tech_id}: {e}")
            return None
    
    def _enhance_with_playbook_data(self, merged_db: Dict, playbook_name: str, playbook_info: Dict):
        """Enhance existing techniques with playbook information"""
        playbook_url = f"{self.playbook_base_url}/playbooks/{playbook_name}"
        
        # Match playbook API calls with existing techniques
        for api_call in playbook_info.get("api_calls", []):
            api_key = api_call.lower()
            if api_key in merged_db:
                # Enhance existing technique
                technique = merged_db[api_key]
                technique.detection_methods.extend(playbook_info.get("detection_methods", []))
                technique.playbook_url = playbook_url
                
                # Remove duplicates
                technique.detection_methods = list(set(technique.detection_methods))
    
    def _add_common_techniques(self, merged_db: Dict):
        """Add common AWS threat techniques not found in external sources"""
        common_techniques = [
            {
                "api_call": "iam:attachuserpolicy",
                "technique": ThreatTechnique(
                    technique_id="T1098.001",
                    technique_name="Account Manipulation: Additional Cloud Credentials",
                    tactic="Privilege Escalation",
                    description="Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access.",
                    aws_services=["IAM"],
                    api_calls=["iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AttachRolePolicy"],
                    detection_methods=[
                        "Monitor CloudTrail for unusual policy attachments",
                        "Alert on policy changes outside business hours",
                        "Track privilege escalation patterns",
                        "Monitor for attachment of high-privilege policies"
                    ],
                    mitigation="Implement least privilege access, use SCPs, enable CloudTrail logging",
                    severity="HIGH"
                )
            },
            {
                "api_call": "iam:createuser",
                "technique": ThreatTechnique(
                    technique_id="T1136.003",
                    technique_name="Create Account: Cloud Account",
                    tactic="Persistence",
                    description="Adversaries may create a cloud account to maintain access to victim systems.",
                    aws_services=["IAM"],
                    api_calls=["iam:CreateUser", "iam:CreateRole"],
                    detection_methods=[
                        "Monitor for new user creation events",
                        "Alert on user creation from unusual locations",
                        "Track user creation patterns",
                        "Monitor for users created outside normal processes"
                    ],
                    mitigation="Restrict user creation permissions, implement approval workflows",
                    severity="MEDIUM"
                )
            },
            {
                "api_call": "iam:createaccesskey",
                "technique": ThreatTechnique(
                    technique_id="T1098.001",
                    technique_name="Account Manipulation: Additional Cloud Credentials",
                    tactic="Privilege Escalation",
                    description="Creating additional access keys for persistence and privilege escalation.",
                    aws_services=["IAM"],
                    api_calls=["iam:CreateAccessKey", "iam:UpdateAccessKey"],
                    detection_methods=[
                        "Monitor access key creation events",
                        "Alert on multiple access keys per user",
                        "Track access key usage patterns",
                        "Monitor for programmatic access key creation"
                    ],
                    mitigation="Limit access key creation, rotate keys regularly, use temporary credentials",
                    severity="HIGH"
                )
            },
            {
                "api_call": "cloudtrail:stoplogging",
                "technique": ThreatTechnique(
                    technique_id="T1562.008",
                    technique_name="Impair Defenses: Disable Cloud Logs",
                    tactic="Defense Evasion",
                    description="Adversaries may disable cloud logging capabilities to avoid detection.",
                    aws_services=["CloudTrail"],
                    api_calls=["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:PutEventSelectors"],
                    detection_methods=[
                        "Monitor CloudTrail configuration changes",
                        "Alert on logging disruptions",
                        "Implement backup logging mechanisms",
                        "Monitor for trail deletion or modification"
                    ],
                    mitigation="Use SCPs to prevent CloudTrail modification, enable multi-region trails",
                    severity="CRITICAL"
                )
            },
            {
                "api_call": "sts:getcalleridentity",
                "technique": ThreatTechnique(
                    technique_id="T1033",
                    technique_name="System Owner/User Discovery",
                    tactic="Discovery",
                    description="Adversaries may attempt to identify the primary user, currently logged in user, or set of users that commonly uses a system.",
                    aws_services=["STS"],
                    api_calls=["sts:GetCallerIdentity", "iam:GetUser", "iam:ListUsers"],
                    detection_methods=[
                        "Monitor for unusual identity discovery patterns",
                        "Track repeated GetCallerIdentity calls",
                        "Correlate with other discovery activities",
                        "Alert on discovery from unusual sources"
                    ],
                    mitigation="Monitor and log identity discovery activities",
                    severity="LOW"
                )
            }
        ]
        
        for item in common_techniques:
            merged_db[item["api_call"]] = item["technique"]
    
    def _safe_request(self, url: str, timeout: int = 10) -> Optional[requests.Response]:
        """Make a safe HTTP request with error handling"""
        try:
            response = self.session.get(url, timeout=timeout)
            time.sleep(0.1)  # Rate limiting
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request failed for {url}: {e}")
            return None
    
    def save_catalog_to_file(self, filename: str = "threat_catalog.json"):
        """Save the loaded catalog to a local file"""
        try:
            # Convert ThreatTechnique objects to dictionaries
            serializable_db = {}
            for api_call, technique in self.threat_db.items():
                serializable_db[api_call] = asdict(technique)
            
            with open(filename, 'w') as f:
                json.dump(serializable_db, f, indent=2, default=str)
            
            print(f"✓ Threat catalog saved to {filename}")
            
        except Exception as e:
            print(f"Error saving catalog: {e}")
    
    def load_catalog_from_file(self, filename: str = "threat_catalog.json") -> bool:
        """Load catalog from a local file"""
        try:
            if not os.path.exists(filename):
                return False
            
            with open(filename, 'r') as f:
                data = json.load(f)
            
            # Convert dictionaries back to ThreatTechnique objects
            self.threat_db = {}
            for api_call, technique_dict in data.items():
                self.threat_db[api_call] = ThreatTechnique(**technique_dict)
            
            print(f"✓ Threat catalog loaded from {filename}")
            return True
            
        except Exception as e:
            print(f"Error loading catalog from file: {e}")
            return False

def main():
    """Example usage of the threat catalog loader"""
    loader = ThreatCatalogLoader()
    
    print("AWS Threat Catalog Loader")
    print("="*40)
    
    # Try to load from file first (faster)
    if not loader.load_catalog_from_file():
        print("Local catalog not found, loading from remote sources...")
        # Load from remote sources
        catalog = loader.load_full_catalog()
        # Save for future use
        loader.save_catalog_to_file()
    
    # Display some statistics
    print(f"\nCatalog Statistics:")
    print(f"Total API calls mapped: {len(loader.threat_db)}")
    
    # Show some examples
    print(f"\nSample mappings:")
    for i, (api_call, technique) in enumerate(list(loader.threat_db.items())[:5]):
        print(f"{i+1}. {api_call} -> {technique.technique_name} ({technique.tactic})")
    
    # Test lookup
    print(f"\nTesting lookup for 'iam:attachuserpolicy':")
    test_api = "iam:attachuserpolicy"
    if test_api in loader.threat_db:
        technique = loader.threat_db[test_api]
        print(f"Found: {technique.technique_name}")
        print(f"Tactic: {technique.tactic}")
        print(f"Severity: {technique.severity}")
        print(f"Detection methods: {len(technique.detection_methods)}")

if __name__ == "__main__":
    main()