#!/usr/bin/env python3

import json
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from threat_catalog_loader import ThreatCatalogLoader, ThreatTechnique
from aws_threat_catalog_loader import AWSCompleteThreatCatalogLoader

class AWSAPIThreatAnalyzer:
    """
    Analyzes AWS API calls against threat intelligence database
    Maps API calls to MITRE ATT&CK tactics and techniques
    """
    
    def __init__(self, use_remote_catalog: bool = True):
        self.threat_db = {}
        self.catalog_loader = AWSCompleteThreatCatalogLoader()
        self.load_threat_database(use_remote_catalog)
    
    def load_threat_database(self, use_remote_catalog: bool = True):
        """Load threat intelligence database from AWS samples or local cache"""
        print("Loading threat intelligence database...")
        
        if use_remote_catalog:
            # Try to load from local cache first (faster)
            if not self.catalog_loader.load_catalog_from_file():
                print("Local catalog not found, loading from remote sources...")
                # Load from remote sources
                self.catalog_loader.load_full_catalog()
                # Save for future use
                self.catalog_loader.save_catalog_to_file()
        else:
            # Force load from remote
            self.catalog_loader.load_full_catalog()
            self.catalog_loader.save_catalog_to_file()
        
        # Use the loaded catalog
        self.threat_db = self.catalog_loader.threat_db
        print(f"✓ Loaded {len(self.threat_db)} threat techniques")
    
    def analyze_api_call(self, api_call: str) -> Optional[ThreatTechnique]:
        """
        Analyze a single API call and return threat intelligence
        
        Args:
            api_call (str): AWS API call (e.g., 'iam:AttachUserPolicy')
            
        Returns:
            ThreatTechnique: Threat intelligence information or None if not found
        """
        # Normalize API call format
        normalized_call = api_call.lower().strip()
        
        # Direct lookup
        if normalized_call in self.threat_db:
            return self.threat_db[normalized_call]
        
        # Fuzzy matching for similar API calls
        for known_call, threat_technique in self.threat_db.items():
            if normalized_call in known_call or any(normalized_call in api.lower() for api in threat_technique.api_calls):
                return threat_technique
        
        return None
    
    def analyze_api_sequence(self, api_calls: List[str]) -> Dict:
        """
        Analyze a sequence of API calls for attack patterns
        
        Args:
            api_calls (List[str]): List of AWS API calls
            
        Returns:
            Dict: Analysis results with potential attack chains
        """
        results = {
            'individual_calls': [],
            'attack_chains': [],
            'tactics_identified': set(),
            'risk_score': 0
        }
        
        # Analyze individual calls
        for api_call in api_calls:
            threat_technique = self.analyze_api_call(api_call)
            if threat_technique:
                results['individual_calls'].append({
                    'api_call': api_call,
                    'threat_info': threat_technique
                })
                results['tactics_identified'].add(threat_technique.tactic)
        
        # Detect attack chains
        results['attack_chains'] = self._detect_attack_chains(api_calls)
        
        # Calculate risk score
        results['risk_score'] = self._calculate_risk_score(results)
        
        # Convert set to list for JSON serialization
        results['tactics_identified'] = list(results['tactics_identified'])
        
        return results
    
    def _detect_attack_chains(self, api_calls: List[str]) -> List[Dict]:
        """Detect potential attack chains from API call sequences"""
        chains = []
        
        # Example: Privilege escalation chain
        priv_esc_calls = ['iam:CreateUser', 'iam:AttachUserPolicy', 'iam:CreateAccessKey']
        if all(any(call.lower() in api.lower() for api in api_calls) for call in priv_esc_calls):
            chains.append({
                'chain_name': 'Privilege Escalation Chain',
                'description': 'User creation followed by policy attachment and access key generation',
                'severity': 'HIGH',
                'calls_involved': priv_esc_calls
            })
        
        # Example: Defense evasion chain
        evasion_calls = ['cloudtrail:StopLogging', 'iam:DeleteRole']
        if all(any(call.lower() in api.lower() for api in api_calls) for call in evasion_calls):
            chains.append({
                'chain_name': 'Defense Evasion Chain',
                'description': 'Disabling logging followed by cleanup activities',
                'severity': 'CRITICAL',
                'calls_involved': evasion_calls
            })
        
        return chains
    
    def _calculate_risk_score(self, results: Dict) -> int:
        """Calculate risk score based on analysis results"""
        score = 0
        
        # Base score for each identified threat
        score += len(results['individual_calls']) * 10
        
        # Higher score for multiple tactics
        score += len(results['tactics_identified']) * 15
        
        # Significant increase for attack chains
        for chain in results['attack_chains']:
            if chain['severity'] == 'CRITICAL':
                score += 50
            elif chain['severity'] == 'HIGH':
                score += 30
            else:
                score += 20
        
        return min(score, 100)  # Cap at 100
    
    def generate_report(self, analysis_results: Dict, output_format: str = 'json') -> str:
        """
        Generate a formatted report from analysis results
        
        Args:
            analysis_results (Dict): Results from analyze_api_sequence
            output_format (str): Output format ('json', 'text', 'markdown')
            
        Returns:
            str: Formatted report
        """
        if output_format == 'json':
            return json.dumps(analysis_results, indent=2, default=str)
        
        elif output_format == 'markdown':
            return self._generate_markdown_report(analysis_results)
        
        else:  # text format
            return self._generate_text_report(analysis_results)
    
    def _generate_markdown_report(self, results: Dict) -> str:
        """Generate markdown formatted report"""
        report = f"""# AWS API Threat Analysis Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- **Risk Score**: {results['risk_score']}/100
- **Tactics Identified**: {', '.join(results['tactics_identified'])}
- **API Calls Analyzed**: {len(results['individual_calls'])}
- **Attack Chains Detected**: {len(results['attack_chains'])}

## Individual API Call Analysis
"""
        
        for call_info in results['individual_calls']:
            threat = call_info['threat_info']
            report += f"""
### {call_info['api_call']}
- **Technique**: {threat.technique_name} ({threat.technique_id})
- **Tactic**: {threat.tactic}
- **Severity**: {threat.severity}
- **Description**: {threat.description}
- **AWS Services**: {', '.join(threat.aws_services)}
- **Detection Methods**:
"""
            for method in threat.detection_methods:
                report += f"  - {method}\n"
            
            report += f"- **Mitigation**: {threat.mitigation}\n"
            if threat.playbook_url:
                report += f"- **Playbook**: {threat.playbook_url}\n"
        
        if results['attack_chains']:
            report += "\n## Attack Chains Detected\n"
            for chain in results['attack_chains']:
                report += f"""
### {chain['chain_name']} (Severity: {chain['severity']})
- **Description**: {chain['description']}
- **Calls Involved**: {', '.join(chain['calls_involved'])}
"""
        
        return report
    
    def _generate_text_report(self, results: Dict) -> str:
        """Generate plain text report"""
        report = f"""AWS API THREAT ANALYSIS REPORT
{'='*50}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY:
Risk Score: {results['risk_score']}/100
Tactics Identified: {', '.join(results['tactics_identified'])}
API Calls Analyzed: {len(results['individual_calls'])}
Attack Chains Detected: {len(results['attack_chains'])}

INDIVIDUAL API CALL ANALYSIS:
{'-'*30}
"""
        
        for call_info in results['individual_calls']:
            threat = call_info['threat_info']
            report += f"""
API Call: {call_info['api_call']}
Technique: {threat.technique_name} ({threat.technique_id})
Tactic: {threat.tactic}
Severity: {threat.severity}
Description: {threat.description}
AWS Services: {', '.join(threat.aws_services)}
Mitigation: {threat.mitigation}
"""
        
        if results['attack_chains']:
            report += f"\nATTACK CHAINS DETECTED:\n{'-'*25}\n"
            for chain in results['attack_chains']:
                report += f"""
Chain: {chain['chain_name']} (Severity: {chain['severity']})
Description: {chain['description']}
Calls Involved: {', '.join(chain['calls_involved'])}
"""
        
        return report

def main():
    """Example usage of the AWS API Threat Analyzer"""
    print("AWS API Threat Intelligence Analyzer")
    print("="*40)
    
    # Initialize analyzer (will load from cache if available)
    analyzer = AWSAPIThreatAnalyzer(use_remote_catalog=True)
    
    # Example 1: Single API call analysis
    print("\n1. Single API Call Analysis:")
    api_call = "iam:AttachUserPolicy"
    result = analyzer.analyze_api_call(api_call)
    if result:
        print(f"API Call: {api_call}")
        print(f"Technique: {result.technique_name}")
        print(f"Tactic: {result.tactic}")
        print(f"Severity: {result.severity}")
        print(f"Description: {result.description[:100]}...")
    else:
        print(f"No threat intelligence found for {api_call}")
    
    # Example 2: API sequence analysis
    print("\n2. API Sequence Analysis:")
    api_sequence = [
        "iam:CreateUser",
        "iam:AttachUserPolicy", 
        "iam:CreateAccessKey",
        "sts:GetCallerIdentity"
    ]
    
    analysis_results = analyzer.analyze_api_sequence(api_sequence)
    
    print(f"Risk Score: {analysis_results['risk_score']}/100")
    print(f"Tactics Identified: {', '.join(analysis_results['tactics_identified'])}")
    print(f"Attack Chains: {len(analysis_results['attack_chains'])}")
    
    # Show individual call results
    print(f"\nIndividual Call Analysis:")
    for call_result in analysis_results['individual_calls']:
        threat = call_result['threat_info']
        print(f"  - {call_result['api_call']}: {threat.technique_name} ({threat.severity})")
    
    # Generate report
    print("\n3. Generated Report (Text format - first 800 chars):")
    print("-" * 60)
    report = analyzer.generate_report(analysis_results, 'text')
    print(report[:800] + "..." if len(report) > 800 else report)

if __name__ == "__main__":
    main()