# User Guide

This guide will help you get the most out of the AWS Threat Intelligence Analyzer.

## Getting Started

### Accessing the Application

Once installed and running, open your web browser and navigate to:
```
http://localhost:8000
```

## Dashboard Overview

The dashboard provides a high-level view of your threat intelligence database:

- **Statistics Cards**: Total techniques, tactics, high-risk techniques, and daily analyses
- **Charts**: Visual representation of techniques by tactic and severity distribution
- **Quick Analysis**: Instantly analyze a single API call
- **System Status**: Health monitoring and database information
- **Quick Links**: Navigate to other features

### Key Metrics

- **Total Techniques**: 68 MITRE ATT&CK techniques
- **MITRE Tactics**: 12 different attack tactics
- **High Risk Techniques**: Critical and high severity techniques
- **AWS Services**: 43 different AWS services covered

## Analysis Features

### Single API Call Analysis

1. Navigate to the **Analyze** tab
2. Select **Single API Call**
3. Enter an AWS API call (e.g., `iam:CreateUser`)
4. Click **Analyze**

**Results include:**
- MITRE ATT&CK technique information
- Tactic classification
- Severity level
- Detection methods
- Mitigation strategies
- Related API calls

### API Sequence Analysis

Analyze multiple API calls to detect attack patterns:

1. Select **API Sequence** tab
2. Enter API calls (one per line):
   ```
   iam:CreateUser
   iam:AttachUserPolicy
   iam:CreateAccessKey
   ```
3. Add context (optional)
4. Click **Analyze Sequence**

**Results include:**
- Risk score (0-100)
- Tactics identified
- Attack chains detected
- Individual call analysis
- Comprehensive report generation

### Understanding Risk Scores

- **0-25**: Low risk - Discovery or reconnaissance activities
- **26-50**: Medium risk - Potential preparation activities
- **51-75**: High risk - Active attack techniques
- **76-100**: Critical risk - Multiple attack chains or high-impact techniques

## Database Browser

Explore the complete threat intelligence database:

### Features

- **Search**: Find techniques by API calls, descriptions, or technique names
- **Filter**: Filter by MITRE ATT&CK tactics
- **Statistics**: Real-time counts of visible techniques
- **Detailed View**: Click "View Details" for comprehensive information

### Search Tips

- Search for specific API calls: `iam:CreateUser`
- Search by service: `s3`
- Search by tactic: `privilege escalation`
- Search by technique ID: `T1098`

### Filtering

Use the tactic filter to focus on specific attack categories:
- **Initial Access**: Entry point techniques
- **Execution**: Code execution methods
- **Persistence**: Maintaining access
- **Privilege Escalation**: Gaining higher privileges
- **Defense Evasion**: Avoiding detection
- **Credential Access**: Stealing credentials
- **Discovery**: Information gathering
- **Lateral Movement**: Moving through networks
- **Collection**: Data gathering
- **Command and Control**: Communication channels
- **Exfiltration**: Data theft
- **Impact**: Destructive activities

## Common Use Cases

### Incident Response

**Scenario**: Investigating suspicious CloudTrail logs

1. Extract API calls from CloudTrail events
2. Use **API Sequence Analysis** to analyze the sequence
3. Review risk score and attack chains
4. Generate a report for documentation

**Example API sequence from a privilege escalation attack:**
```
sts:GetCallerIdentity
iam:ListUsers
iam:CreateUser
iam:AttachUserPolicy
iam:CreateAccessKey
```

### Threat Hunting

**Scenario**: Proactive threat hunting

1. Use **Database Browser** to explore techniques by tactic
2. Focus on high-severity techniques
3. Create detection rules based on API calls
4. Monitor for related attack patterns

### Security Awareness Training

**Scenario**: Training security teams

1. Demonstrate common attack techniques
2. Show detection methods for each technique
3. Explain mitigation strategies
4. Practice with real API call examples

### Detection Rule Development

**Scenario**: Creating SIEM rules

1. Identify high-risk API calls from the database
2. Review detection methods for each technique
3. Implement monitoring for related API calls
4. Test with sequence analysis

## Advanced Features

### Report Generation

Generate comprehensive reports for documentation:

1. Complete your analysis
2. Click **Generate Full Report**
3. Choose format (Markdown, JSON, Text)
4. Save or share the report

### API Integration

Integrate with existing tools using the REST API:

```python
import requests

# Analyze CloudTrail events programmatically
api_calls = extract_api_calls_from_cloudtrail(event)
response = requests.post(
    "http://localhost:8000/api/analyze/sequence",
    json={"api_calls": api_calls}
)
analysis = response.json()
```

### Batch Analysis

For analyzing large datasets:

1. Extract API calls from logs
2. Use the API endpoints for batch processing
3. Aggregate results for reporting
4. Identify patterns across multiple incidents

## Best Practices

### Analysis Workflow

1. **Start with Context**: Always provide context for your analysis
2. **Sequence Matters**: Order of API calls can indicate attack progression
3. **Consider Timing**: Time gaps between calls can be significant
4. **Cross-Reference**: Use multiple analysis methods for validation

### Interpretation Guidelines

- **High Risk Scores**: Don't panic - investigate context
- **Attack Chains**: Focus on the complete chain, not individual calls
- **False Positives**: Legitimate admin activities may trigger alerts
- **Baseline**: Understand normal API usage patterns

### Documentation

- **Save Reports**: Keep analysis reports for future reference
- **Context Notes**: Always include investigation context
- **Follow-up**: Document actions taken based on analysis
- **Share Findings**: Collaborate with team members

## Troubleshooting

### Common Issues

**No results for API call:**
- Check API call format (service:action)
- Verify the API call exists in AWS
- Try related API calls

**Low risk score for suspicious activity:**
- Consider the complete sequence
- Check for attack chains
- Review individual technique severities

**Performance issues:**
- Restart the application
- Check system resources
- Reduce analysis scope

### Getting Help

1. Check the [API Documentation](api.md)
2. Review [Examples](examples.md)
3. Create an issue on GitHub
4. Check existing issues for solutions

## Tips and Tricks

### Keyboard Shortcuts

- **Quick Analysis**: Use the dashboard quick analysis for fast lookups
- **Search**: Use Ctrl+F in database browser for quick searches
- **Navigation**: Use browser back/forward for analysis history

### Efficiency Tips

- **Bookmark**: Bookmark frequently used analysis pages
- **Templates**: Save common API sequences for reuse
- **Batch Processing**: Use API endpoints for large-scale analysis
- **Regular Updates**: Keep the threat database updated

### Advanced Analysis

- **Correlation**: Correlate with other security tools
- **Timeline**: Consider temporal aspects of API calls
- **Attribution**: Look for technique patterns by threat actors
- **Validation**: Cross-check with multiple intelligence sources