# API Documentation

The AWS Threat Intelligence Analyzer provides a comprehensive REST API for programmatic access to threat intelligence data.

## Base URL

```
http://localhost:8000
```

## Authentication

Currently, no authentication is required for local deployment. For production deployments, consider implementing authentication.

## Endpoints

### Health Check

**GET** `/health`

Check the health status of the application.

**Response:**
```json
{
  "status": "healthy",
  "analyzer_loaded": true,
  "database_size": 144,
  "timestamp": "2025-07-29T14:25:58.453500"
}
```

### Database Statistics

**GET** `/api/database/stats`

Get comprehensive statistics about the threat intelligence database.

**Response:**
```json
{
  "total_techniques": 144,
  "tactic_counts": {
    "Impact": 30,
    "Discovery": 27,
    "Defense Evasion": 24
  },
  "severity_counts": {
    "HIGH": 49,
    "MEDIUM": 47,
    "LOW": 31,
    "CRITICAL": 17
  },
  "service_counts": {
    "EC2": 37,
    "IAM": 27,
    "S3": 19
  },
  "last_updated": "2025-07-29T14:25:58.453500"
}
```

### Single API Call Analysis

**POST** `/api/analyze/single`

Analyze a single AWS API call for threat intelligence.

**Request Body:**
```json
{
  "api_call": "iam:CreateUser"
}
```

**Response:**
```json
{
  "api_call": "iam:CreateUser",
  "technique_found": true,
  "technique_info": {
    "technique_id": "T1136.003",
    "technique_name": "Create Account: Cloud Account",
    "tactic": "Persistence",
    "severity": "MEDIUM",
    "description": "Adversaries may create a cloud account to maintain access to victim systems.",
    "aws_services": ["IAM"],
    "api_calls": ["iam:CreateUser", "iam:CreateRole"],
    "detection_methods": [
      "Monitor for new user creation events",
      "Alert on user creation from unusual locations"
    ],
    "mitigation": "Restrict user creation permissions, implement approval workflows",
    "references": ["https://attack.mitre.org/techniques/T1136.003/"],
    "playbook_url": null
  }
}
```

### API Sequence Analysis

**POST** `/api/analyze/sequence`

Analyze a sequence of AWS API calls to detect attack patterns.

**Request Body:**
```json
{
  "api_calls": [
    "iam:CreateUser",
    "iam:AttachUserPolicy",
    "iam:CreateAccessKey"
  ],
  "context": "Security investigation #12345"
}
```

**Response:**
```json
{
  "risk_score": 85,
  "tactics_identified": ["Persistence", "Privilege Escalation"],
  "individual_calls": [
    {
      "api_call": "iam:CreateUser",
      "technique_id": "T1136.003",
      "technique_name": "Create Account: Cloud Account",
      "tactic": "Persistence",
      "severity": "MEDIUM"
    }
  ],
  "attack_chains": [
    {
      "chain_name": "Privilege Escalation Chain",
      "description": "User creation followed by policy attachment and access key generation",
      "severity": "HIGH",
      "calls_involved": ["iam:CreateUser", "iam:AttachUserPolicy", "iam:CreateAccessKey"]
    }
  ],
  "analysis_timestamp": "2025-07-29T14:25:58.453500"
}
```

### Database Search

**GET** `/api/database/search`

Search the threat intelligence database.

**Parameters:**
- `q` (string): Search query

**Example:**
```
GET /api/database/search?q=iam
```

**Response:**
```json
{
  "results": [
    {
      "api_call": "iam:createuser",
      "technique_id": "T1136.003",
      "technique_name": "Create Account: Cloud Account",
      "tactic": "Persistence",
      "severity": "MEDIUM",
      "description": "Adversaries may create a cloud account to maintain access..."
    }
  ]
}
```

### Report Generation

**GET** `/api/reports/generate`

Generate analysis reports in various formats.

**Parameters:**
- `api_calls` (string): Comma-separated list of API calls
- `format` (string): Report format (`json`, `markdown`, `text`)

**Example:**
```
GET /api/reports/generate?api_calls=iam:CreateUser,iam:AttachUserPolicy&format=markdown
```

**Response:**
```json
{
  "report": "# AWS API Threat Analysis Report\n\n## Summary\n...",
  "format": "markdown"
}
```

## Error Responses

### 400 Bad Request
```json
{
  "detail": "Invalid API call format"
}
```

### 404 Not Found
```json
{
  "detail": "Technique not found"
}
```

### 500 Internal Server Error
```json
{
  "detail": "Internal server error occurred"
}
```

## Rate Limiting

Currently, no rate limiting is implemented. For production use, consider implementing rate limiting based on your requirements.

## Examples

### Python Example

```python
import requests

# Analyze single API call
response = requests.post(
    "http://localhost:8000/api/analyze/single",
    json={"api_call": "iam:CreateUser"}
)
result = response.json()
print(f"Technique: {result['technique_info']['technique_name']}")

# Analyze sequence
response = requests.post(
    "http://localhost:8000/api/analyze/sequence",
    json={
        "api_calls": ["iam:CreateUser", "iam:AttachUserPolicy"],
        "context": "Investigation"
    }
)
analysis = response.json()
print(f"Risk Score: {analysis['risk_score']}")
```

### cURL Examples

```bash
# Single API analysis
curl -X POST "http://localhost:8000/api/analyze/single" \
     -H "Content-Type: application/json" \
     -d '{"api_call": "iam:CreateUser"}'

# Sequence analysis
curl -X POST "http://localhost:8000/api/analyze/sequence" \
     -H "Content-Type: application/json" \
     -d '{
       "api_calls": ["iam:CreateUser", "iam:AttachUserPolicy"],
       "context": "Security investigation"
     }'

# Database search
curl "http://localhost:8000/api/database/search?q=s3"

# Get statistics
curl "http://localhost:8000/api/database/stats"
```

### JavaScript Example

```javascript
// Analyze API call
async function analyzeAPI(apiCall) {
  const response = await fetch('http://localhost:8000/api/analyze/single', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ api_call: apiCall })
  });
  
  const result = await response.json();
  return result;
}

// Usage
analyzeAPI('iam:CreateUser').then(result => {
  console.log('Technique:', result.technique_info.technique_name);
});
```

## OpenAPI Documentation

Interactive API documentation is available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc