#!/usr/bin/env python3

"""
AWS GuardDuty Finding Types Scraper
Scrapes and analyzes GuardDuty finding types from AWS documentation
"""

import requests
from bs4 import BeautifulSoup
import json
import re
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

@dataclass
class GuardDutyFinding:
    """GuardDuty finding type information"""
    finding_type: str
    category: str
    severity: str
    description: str
    remediation: str
    sample_finding: Optional[str] = None
    mitre_tactics: List[str] = None
    aws_services: List[str] = None
    threat_purpose: Optional[str] = None
    resource_role: Optional[str] = None

class GuardDutyFindingsScraper:
    """
    Scrapes GuardDuty finding types from AWS documentation
    and provides analysis capabilities
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.base_url = "https://docs.aws.amazon.com/guardduty/latest/ug/"
        self.findings_cache = {}
        
        # Mapping of GuardDuty categories to MITRE ATT&CK tactics
        self.category_to_mitre = {
            'Backdoor': ['Persistence', 'Command and Control'],
            'Behavior': ['Defense Evasion', 'Discovery'],
            'CryptoCurrency': ['Impact', 'Resource Hijacking'],
            'DefenseEvasion': ['Defense Evasion'],
            'Discovery': ['Discovery'],
            'Impact': ['Impact'],
            'InitialAccess': ['Initial Access'],
            'Malware': ['Execution', 'Persistence'],
            'Persistence': ['Persistence'],
            'Policy': ['Defense Evasion', 'Privilege Escalation'],
            'PrivilegeEscalation': ['Privilege Escalation'],
            'Recon': ['Reconnaissance', 'Discovery'],
            'ResourceConsumption': ['Impact'],
            'Stealth': ['Defense Evasion'],
            'Trojan': ['Execution', 'Command and Control'],
            'UnauthorizedAccess': ['Initial Access', 'Credential Access']
        }
    
    def scrape_finding_types(self) -> List[GuardDutyFinding]:
        """
        Scrape GuardDuty finding types from AWS documentation
        
        Returns:
            List[GuardDutyFinding]: List of GuardDuty findings
        """
        findings = []
        
        # URLs for different finding type categories
        finding_urls = [
            "guardduty_finding-types-active.html",
            "guardduty_finding-types-ec2.html", 
            "guardduty_finding-types-iam.html",
            "guardduty_finding-types-kubernetes.html",
            "guardduty_finding-types-malware-protection.html",
            "guardduty_finding-types-s3.html"
        ]
        
        for url_path in finding_urls:
            try:
                self.logger.info(f"Scraping findings from {url_path}")
                page_findings = self._scrape_page(self.base_url + url_path)
                findings.extend(page_findings)
            except Exception as e:
                self.logger.error(f"Error scraping {url_path}: {str(e)}")
        
        self.logger.info(f"Scraped {len(findings)} GuardDuty finding types")
        return findings
    
    def _scrape_page(self, url: str) -> List[GuardDutyFinding]:
        """Scrape findings from a specific documentation page"""
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            findings = []
            
            # Look for finding type sections
            # GuardDuty documentation typically has finding types in specific patterns
            finding_sections = soup.find_all(['div', 'section'], class_=re.compile(r'section|finding'))
            
            if not finding_sections:
                # Fallback: look for headings that contain finding types
                finding_sections = soup.find_all(['h2', 'h3', 'h4'])
            
            for section in finding_sections:
                finding = self._extract_finding_from_section(section)
                if finding:
                    findings.append(finding)
            
            # Alternative approach: look for specific patterns in text
            if not findings:
                findings = self._extract_findings_from_text(soup.get_text())
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Error scraping page {url}: {str(e)}")
            return []
    
    def _extract_finding_from_section(self, section) -> Optional[GuardDutyFinding]:
        """Extract finding information from a documentation section"""
        try:
            # Look for finding type pattern (e.g., "Backdoor:EC2/C&CActivity.B!DNS")
            text = section.get_text()
            
            # Pattern for GuardDuty finding types
            finding_pattern = r'([A-Za-z]+):([A-Za-z0-9]+)/([A-Za-z0-9&!.\-_]+)'
            match = re.search(finding_pattern, text)
            
            if not match:
                return None
            
            finding_type = match.group(0)
            category = match.group(1)
            service = match.group(2)
            
            # Extract description (usually follows the finding type)
            description = self._extract_description(section, text)
            
            # Extract severity if mentioned
            severity = self._extract_severity(text)
            
            # Extract remediation information
            remediation = self._extract_remediation(section, text)
            
            # Map to MITRE tactics
            mitre_tactics = self.category_to_mitre.get(category, [])
            
            # Determine AWS services involved
            aws_services = self._determine_aws_services(service, text)
            
            return GuardDutyFinding(
                finding_type=finding_type,
                category=category,
                severity=severity,
                description=description,
                remediation=remediation,
                mitre_tactics=mitre_tactics,
                aws_services=aws_services,
                threat_purpose=self._extract_threat_purpose(text),
                resource_role=service
            )
            
        except Exception as e:
            self.logger.error(f"Error extracting finding from section: {str(e)}")
            return None
    
    def _extract_findings_from_text(self, text: str) -> List[GuardDutyFinding]:
        """Extract findings using text pattern matching as fallback"""
        findings = []
        
        # Common GuardDuty finding patterns
        patterns = [
            r'(Backdoor:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(Behavior:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(CryptoCurrency:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(DefenseEvasion:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(Discovery:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(Impact:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(InitialAccess:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(Malware:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(Persistence:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(Policy:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(PrivilegeEscalation:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(Recon:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(ResourceConsumption:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(Stealth:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(Trojan:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)',
            r'(UnauthorizedAccess:[A-Za-z0-9]+/[A-Za-z0-9&!.\-_]+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                finding_type = match
                category = finding_type.split(':')[0]
                
                # Create basic finding
                finding = GuardDutyFinding(
                    finding_type=finding_type,
                    category=category,
                    severity="Medium",  # Default
                    description=f"GuardDuty finding: {finding_type}",
                    remediation="Investigate the finding and take appropriate action",
                    mitre_tactics=self.category_to_mitre.get(category, []),
                    aws_services=[finding_type.split(':')[1].split('/')[0]]
                )
                findings.append(finding)
        
        return findings
    
    def _extract_description(self, section, text: str) -> str:
        """Extract description from section"""
        # Look for description patterns
        desc_patterns = [
            r'Description[:\s]+([^.]+\.)',
            r'This finding[:\s]+([^.]+\.)',
            r'Indicates[:\s]+([^.]+\.)'
        ]
        
        for pattern in desc_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        # Fallback: take first sentence after finding type
        sentences = text.split('.')
        if len(sentences) > 1:
            return sentences[1].strip()[:200] + "..."
        
        return "GuardDuty security finding requiring investigation"
    
    def _extract_severity(self, text: str) -> str:
        """Extract severity level from text"""
        severity_patterns = [
            r'Severity[:\s]+(High|Medium|Low)',
            r'(High|Medium|Low)\s+severity',
            r'severity\s+of\s+(High|Medium|Low)'
        ]
        
        for pattern in severity_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).title()
        
        return "Medium"  # Default
    
    def _extract_remediation(self, section, text: str) -> str:
        """Extract remediation information"""
        remediation_patterns = [
            r'Remediation[:\s]+([^.]+\.)',
            r'To remediate[:\s]+([^.]+\.)',
            r'Recommended action[:\s]+([^.]+\.)'
        ]
        
        for pattern in remediation_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return "Review the finding details and investigate the reported activity"
    
    def _extract_threat_purpose(self, text: str) -> Optional[str]:
        """Extract threat purpose from text"""
        purpose_keywords = {
            'cryptocurrency': 'Cryptocurrency Mining',
            'backdoor': 'Backdoor Access',
            'malware': 'Malware Execution',
            'reconnaissance': 'Information Gathering',
            'data exfiltration': 'Data Theft',
            'privilege escalation': 'Privilege Escalation',
            'lateral movement': 'Network Traversal'
        }
        
        text_lower = text.lower()
        for keyword, purpose in purpose_keywords.items():
            if keyword in text_lower:
                return purpose
        
        return None
    
    def _determine_aws_services(self, service_code: str, text: str) -> List[str]:
        """Determine AWS services involved"""
        service_mapping = {
            'EC2': ['EC2', 'VPC'],
            'S3': ['S3'],
            'IAM': ['IAM'],
            'EKS': ['EKS', 'Kubernetes'],
            'Lambda': ['Lambda'],
            'RDS': ['RDS'],
            'ECS': ['ECS']
        }
        
        services = service_mapping.get(service_code, [service_code])
        
        # Look for additional services mentioned in text
        service_keywords = ['CloudTrail', 'Route53', 'ELB', 'ALB', 'NLB', 'API Gateway']
        text_lower = text.lower()
        
        for keyword in service_keywords:
            if keyword.lower() in text_lower:
                services.append(keyword)
        
        return list(set(services))
    
    def save_findings_to_file(self, findings: List[GuardDutyFinding], filename: str = "guardduty_findings.json"):
        """Save findings to JSON file"""
        try:
            findings_data = {
                'scraped_timestamp': datetime.now().isoformat(),
                'total_findings': len(findings),
                'findings': [asdict(finding) for finding in findings]
            }
            
            with open(filename, 'w') as f:
                json.dump(findings_data, f, indent=2)
            
            self.logger.info(f"Saved {len(findings)} findings to {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving findings to {filename}: {str(e)}")
            return False
    
    def load_findings_from_file(self, filename: str = "guardduty_findings.json") -> List[GuardDutyFinding]:
        """Load findings from JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
            
            findings = []
            for finding_data in data.get('findings', []):
                finding = GuardDutyFinding(**finding_data)
                findings.append(finding)
            
            self.logger.info(f"Loaded {len(findings)} findings from {filename}")
            return findings
            
        except Exception as e:
            self.logger.error(f"Error loading findings from {filename}: {str(e)}")
            return []
    
    def analyze_findings(self, findings: List[GuardDutyFinding]) -> Dict:
        """Analyze GuardDuty findings for insights"""
        analysis = {
            'total_findings': len(findings),
            'categories': {},
            'severities': {},
            'mitre_tactics': {},
            'aws_services': {},
            'threat_purposes': {},
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        for finding in findings:
            # Count categories
            category = finding.category
            analysis['categories'][category] = analysis['categories'].get(category, 0) + 1
            
            # Count severities
            severity = finding.severity
            analysis['severities'][severity] = analysis['severities'].get(severity, 0) + 1
            
            # Count MITRE tactics
            if finding.mitre_tactics:
                for tactic in finding.mitre_tactics:
                    analysis['mitre_tactics'][tactic] = analysis['mitre_tactics'].get(tactic, 0) + 1
            
            # Count AWS services
            if finding.aws_services:
                for service in finding.aws_services:
                    analysis['aws_services'][service] = analysis['aws_services'].get(service, 0) + 1
            
            # Count threat purposes
            if finding.threat_purpose:
                purpose = finding.threat_purpose
                analysis['threat_purposes'][purpose] = analysis['threat_purposes'].get(purpose, 0) + 1
        
        return analysis
    
    def find_mitre_correlations(self, findings: List[GuardDutyFinding], mitre_techniques: Dict) -> List[Dict]:
        """Find correlations between GuardDuty findings and MITRE techniques"""
        correlations = []
        
        for finding in findings:
            if not finding.mitre_tactics:
                continue
            
            for tactic in finding.mitre_tactics:
                # Find MITRE techniques that match this tactic
                matching_techniques = []
                for api_call, technique in mitre_techniques.items():
                    if technique.tactic == tactic:
                        matching_techniques.append({
                            'technique_id': technique.technique_id,
                            'technique_name': technique.technique_name,
                            'api_call': api_call,
                            'severity': technique.severity
                        })
                
                if matching_techniques:
                    correlation = {
                        'guardduty_finding': finding.finding_type,
                        'guardduty_category': finding.category,
                        'mitre_tactic': tactic,
                        'matching_techniques': matching_techniques[:5],  # Limit to top 5
                        'correlation_strength': len(matching_techniques)
                    }
                    correlations.append(correlation)
        
        # Sort by correlation strength
        correlations.sort(key=lambda x: x['correlation_strength'], reverse=True)
        return correlations

def main():
    """Example usage of GuardDuty Findings Scraper"""
    print("AWS GuardDuty Findings Scraper")
    print("=" * 35)
    
    # Initialize scraper
    scraper = GuardDutyFindingsScraper()
    
    try:
        # Scrape findings
        print("\nScraping GuardDuty finding types from AWS documentation...")
        findings = scraper.scrape_finding_types()
        
        if not findings:
            print("No findings scraped. This might be due to changes in AWS documentation structure.")
            return
        
        print(f"Scraped {len(findings)} GuardDuty finding types")
        
        # Display sample findings
        print(f"\nSample findings:")
        for finding in findings[:5]:
            print(f"- {finding.finding_type} ({finding.category}) - {finding.severity}")
        
        # Analyze findings
        analysis = scraper.analyze_findings(findings)
        print(f"\nAnalysis:")
        print(f"Categories: {dict(list(analysis['categories'].items())[:5])}")
        print(f"Severities: {analysis['severities']}")
        print(f"MITRE Tactics: {dict(list(analysis['mitre_tactics'].items())[:5])}")
        
        # Save findings
        scraper.save_findings_to_file(findings)
        print(f"\nFindings saved to guardduty_findings.json")
        
    except Exception as e:
        print(f"Error during scraping: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()