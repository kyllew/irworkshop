# Examples

This document provides practical examples of using the AWS Threat Intelligence Analyzer for various security scenarios.

## Incident Response Examples

### Example 1: Privilege Escalation Investigation

**Scenario**: CloudTrail logs show suspicious IAM activity from a compromised user account.

**API Call Sequence**:
```
sts:GetCallerIdentity
iam:ListUsers
iam:ListRoles
iam:CreateUser
iam:AttachUserPolicy
iam:CreateAccessKey
```

**Analysis Steps**:

1. **Single Call Analysis**:
   ```bash
   curl -X POST "http://localhost:8000/api/analyze/single" \
        -H "Content-Type: application/json" \
        -d '{"api_call": "iam:CreateUser"}'
   ```

2. **Sequence Analysis**:
   ```bash
   curl -X POST "http://localhost:8000/api/analyze/sequence" \
        -H "Content-Type: application/json" \
        -d '{
          "api_calls": [
            "sts:GetCallerIdentity",
            "iam:ListUsers", 
            "iam:CreateUser",
            "iam:AttachUserPolicy",
            "iam:CreateAccessKey"
          ],
          "context": "Incident #2025-001: Suspicious IAM activity"
        }'
   ```

**Expected Results**:
- **Risk Score**: 85-95/100
- **Tactics**: Discovery, Persistence, Privilege Escalation
- **Attack Chain**: Privilege Escalation Chain detected
- **Techniques**: T1033, T1087.004, T1136.003, T1098.001

### Example 2: Data Exfiltration Investigation

**Scenario**: Large amounts of data accessed from S3 buckets.

**API Call Sequence**:
```
s3:ListBuckets
s3:GetBucketLocation
s3:ListBucket
s3:GetObject
s3:CreateBucket
s3:PutObject
```

**Python Analysis**:
```python
import requests

api_calls = [
    "s3:ListBuckets",
    "s3:GetBucketLocation", 
    "s3:ListBucket",
    "s3:GetObject",
    "s3:CreateBucket",
    "s3:PutObject"
]

response = requests.post(
    "http://localhost:8000/api/analyze/sequence",
    json={
        "api_calls": api_calls,
        "context": "Data exfiltration investigation"
    }
)

analysis = response.json()
print(f"Risk Score: {analysis['risk_score']}")
print(f"Tactics: {', '.join(analysis['tactics_identified'])}")

for chain in analysis['attack_chains']:
    print(f"Attack Chain: {chain['chain_name']} ({chain['severity']})")
```

**Expected Results**:
- **Risk Score**: 70-80/100
- **Tactics**: Discovery, Collection, Exfiltration
- **Techniques**: T1526, T1530, T1537

### Example 3: Defense Evasion Analysis

**Scenario**: CloudTrail logging was disabled during an incident.

**API Call Sequence**:
```
cloudtrail:DescribeTrails
cloudtrail:StopLogging
cloudtrail:DeleteTrail
logs:DeleteLogGroup
```

**Web Interface Steps**:
1. Navigate to Analyze → API Sequence
2. Enter the API calls
3. Add context: "Defense evasion - logging disabled"
4. Click "Analyze Sequence"

**Expected Results**:
- **Risk Score**: 95-100/100
- **Tactics**: Defense Evasion
- **Severity**: CRITICAL
- **Technique**: T1562.008 (Impair Defenses: Disable Cloud Logs)

## Threat Hunting Examples

### Example 4: Resource Hijacking Detection

**Scenario**: Looking for cryptocurrency mining or resource abuse.

**Search Query**: "T1496" or "resource hijacking"

**Related API Calls**:
```
ec2:RunInstances
ec2:DescribeInstances
lambda:CreateFunction
batch:SubmitJob
sagemaker:CreateTrainingJob
```

**Detection Strategy**:
```python
# Monitor for unusual compute resource creation
suspicious_apis = [
    "ec2:RunInstances",
    "lambda:CreateFunction", 
    "batch:SubmitJob",
    "sagemaker:CreateTrainingJob"
]

for api in suspicious_apis:
    response = requests.post(
        "http://localhost:8000/api/analyze/single",
        json={"api_call": api}
    )
    
    result = response.json()
    if result['technique_found']:
        technique = result['technique_info']
        print(f"API: {api}")
        print(f"Technique: {technique['technique_name']}")
        print(f"Severity: {technique['severity']}")
        print("---")
```

### Example 5: Account Manipulation Hunt

**Scenario**: Hunting for unauthorized account modifications.

**Database Search**: Search for "account manipulation"

**Key API Calls to Monitor**:
```
iam:CreateUser
iam:CreateRole
iam:AttachUserPolicy
iam:PutUserPolicy
iam:CreateAccessKey
iam:CreateLoginProfile
```

**Hunting Query**:
```bash
# Search for account manipulation techniques
curl "http://localhost:8000/api/database/search?q=account%20manipulation"
```

## Security Awareness Examples

### Example 6: Training Scenario - Insider Threat

**Learning Objective**: Understand how insiders might abuse legitimate access.

**Scenario**: Privileged user gradually escalates access and exfiltrates data.

**Phase 1 - Reconnaissance**:
```
sts:GetCallerIdentity
iam:GetUser
iam:ListAttachedUserPolicies
```

**Phase 2 - Privilege Escalation**:
```
iam:CreateRole
iam:AttachRolePolicy
sts:AssumeRole
```

**Phase 3 - Data Access**:
```
s3:ListBuckets
s3:GetObject
dynamodb:Scan
```

**Phase 4 - Exfiltration**:
```
s3:CreateBucket
s3:PutObject
```

**Training Exercise**:
1. Analyze each phase separately
2. Combine all phases for full attack analysis
3. Discuss detection and prevention strategies

### Example 7: Red Team Exercise

**Scenario**: Simulating an advanced persistent threat (APT).

**Multi-Stage Attack**:

**Stage 1 - Initial Access**:
```
sts:GetCallerIdentity
ec2:DescribeInstances
```

**Stage 2 - Discovery**:
```
iam:ListUsers
iam:ListRoles
s3:ListBuckets
ec2:DescribeSecurityGroups
```

**Stage 3 - Persistence**:
```
iam:CreateUser
iam:AttachUserPolicy
iam:CreateAccessKey
```

**Stage 4 - Defense Evasion**:
```
cloudtrail:StopLogging
logs:DeleteLogGroup
```

**Stage 5 - Impact**:
```
s3:DeleteBucket
rds:DeleteDBInstance
```

## Integration Examples

### Example 8: SIEM Integration

**Scenario**: Integrate with Splunk for automated analysis.

**Splunk Search**:
```splunk
index=cloudtrail 
| eval api_call=eventSource+":"+eventName
| stats count by api_call
| where count > threshold
```

**Python Integration Script**:
```python
import requests
import splunklib.client as client

# Connect to Splunk
service = client.connect(
    host="splunk-server",
    port=8089,
    username="admin",
    password="password"
)

# Search for suspicious API calls
search_query = '''
search index=cloudtrail earliest=-1h
| eval api_call=eventSource+":"+eventName
| stats count by api_call, sourceIPAddress
| where count > 10
'''

job = service.jobs.create(search_query)
results = job.results()

# Analyze each API call
for result in results:
    api_call = result['api_call']
    
    response = requests.post(
        "http://localhost:8000/api/analyze/single",
        json={"api_call": api_call}
    )
    
    analysis = response.json()
    if analysis['technique_found']:
        technique = analysis['technique_info']
        if technique['severity'] in ['HIGH', 'CRITICAL']:
            # Create alert
            print(f"ALERT: {api_call} - {technique['technique_name']}")
```

### Example 9: Lambda Function Integration

**Scenario**: Automated CloudTrail log analysis.

**Lambda Function**:
```python
import json
import boto3
import requests

def lambda_handler(event, context):
    # Parse CloudTrail event
    records = event['Records']
    
    for record in records:
        # Extract S3 object info
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        
        # Download CloudTrail log
        s3 = boto3.client('s3')
        obj = s3.get_object(Bucket=bucket, Key=key)
        log_data = json.loads(obj['Body'].read())
        
        # Extract API calls
        api_calls = []
        for log_record in log_data['Records']:
            api_call = f"{log_record['eventSource']}:{log_record['eventName']}"
            api_calls.append(api_call)
        
        # Analyze sequence
        if api_calls:
            response = requests.post(
                "http://threat-analyzer:8000/api/analyze/sequence",
                json={
                    "api_calls": api_calls,
                    "context": f"CloudTrail log: {key}"
                }
            )
            
            analysis = response.json()
            
            # Alert on high risk
            if analysis['risk_score'] > 70:
                # Send to SNS, Slack, etc.
                send_alert(analysis)
    
    return {'statusCode': 200}

def send_alert(analysis):
    # Implementation for alerting
    pass
```

## Advanced Analysis Examples

### Example 10: Time-based Analysis

**Scenario**: Analyzing attack progression over time.

**Time-series Data**:
```python
import datetime
import requests

# Simulate time-based API calls
time_series_calls = [
    ("2025-01-01 09:00:00", "sts:GetCallerIdentity"),
    ("2025-01-01 09:05:00", "iam:ListUsers"),
    ("2025-01-01 09:10:00", "iam:CreateUser"),
    ("2025-01-01 09:15:00", "iam:AttachUserPolicy"),
    ("2025-01-01 09:20:00", "iam:CreateAccessKey"),
    ("2025-01-01 09:25:00", "s3:ListBuckets"),
    ("2025-01-01 09:30:00", "s3:GetObject")
]

# Analyze progression
for timestamp, api_call in time_series_calls:
    response = requests.post(
        "http://localhost:8000/api/analyze/single",
        json={"api_call": api_call}
    )
    
    result = response.json()
    if result['technique_found']:
        technique = result['technique_info']
        print(f"{timestamp}: {api_call} -> {technique['tactic']} ({technique['severity']})")
```

### Example 11: Correlation Analysis

**Scenario**: Correlating with external threat intelligence.

**Multi-source Analysis**:
```python
import requests

def correlate_with_mitre(technique_id):
    """Correlate with MITRE ATT&CK database"""
    mitre_url = f"https://attack.mitre.org/techniques/{technique_id}/"
    # Additional correlation logic
    return mitre_url

def analyze_with_context(api_calls, external_context):
    """Analyze with additional context"""
    response = requests.post(
        "http://localhost:8000/api/analyze/sequence",
        json={
            "api_calls": api_calls,
            "context": external_context
        }
    )
    
    analysis = response.json()
    
    # Enhance with external correlation
    for call_info in analysis['individual_calls']:
        technique_id = call_info['technique_id']
        mitre_link = correlate_with_mitre(technique_id)
        call_info['mitre_link'] = mitre_link
    
    return analysis

# Example usage
api_calls = ["iam:CreateUser", "iam:AttachUserPolicy"]
context = "IOC match: Known APT29 technique pattern"
enhanced_analysis = analyze_with_context(api_calls, context)
```

## Reporting Examples

### Example 12: Executive Summary Report

**Scenario**: Creating executive-level incident reports.

**Report Generation**:
```python
import requests
from datetime import datetime

def generate_executive_report(api_calls, incident_id):
    # Analyze the sequence
    response = requests.post(
        "http://localhost:8000/api/analyze/sequence",
        json={
            "api_calls": api_calls,
            "context": f"Incident {incident_id}"
        }
    )
    
    analysis = response.json()
    
    # Generate executive summary
    report = f"""
# Security Incident Report - {incident_id}

**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Risk Score**: {analysis['risk_score']}/100
**Severity**: {'CRITICAL' if analysis['risk_score'] > 80 else 'HIGH' if analysis['risk_score'] > 60 else 'MEDIUM'}

## Executive Summary

This incident involved {len(analysis['individual_calls'])} suspicious API calls across {len(analysis['tactics_identified'])} MITRE ATT&CK tactics.

**Tactics Involved**: {', '.join(analysis['tactics_identified'])}

## Attack Chains Detected

"""
    
    for chain in analysis['attack_chains']:
        report += f"- **{chain['chain_name']}** ({chain['severity']}): {chain['description']}\n"
    
    report += f"""

## Recommendations

1. Immediate containment of affected accounts
2. Review and revoke suspicious access keys
3. Implement additional monitoring for related API calls
4. Conduct forensic analysis of affected resources

## Technical Details

Total API calls analyzed: {len(api_calls)}
Analysis timestamp: {analysis['analysis_timestamp']}
"""
    
    return report

# Usage
incident_api_calls = [
    "sts:GetCallerIdentity",
    "iam:CreateUser", 
    "iam:AttachUserPolicy",
    "s3:ListBuckets",
    "s3:GetObject"
]

executive_report = generate_executive_report(incident_api_calls, "INC-2025-001")
print(executive_report)
```

These examples demonstrate the versatility and power of the AWS Threat Intelligence Analyzer across various security use cases. Each example can be adapted to your specific environment and requirements.