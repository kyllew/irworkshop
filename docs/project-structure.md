# Project Structure

This document explains the organization and purpose of files in the AWS Threat Intelligence Analyzer project.

## Root Directory

```
irworkshop/
├── docs/                           # Documentation
├── static/                         # Static web assets (auto-created)
├── templates/                      # HTML templates
├── .gitignore                      # Git ignore rules
├── LICENSE                         # MIT License
├── README.md                       # Main project documentation
├── requirements.txt                # Python dependencies
└── [Python files...]              # Core application files
```

## Core Application Files

### Main Application
- **`web_app.py`** - FastAPI web application and REST API
- **`threat_intel_app.py`** - Core threat analysis engine
- **`start_web_app.py`** - Application startup script

### Data Loading
- **`threat_catalog_loader.py`** - Base threat catalog loader class
- **`aws_threat_catalog_loader.py`** - Complete AWS threat catalog loader (68 techniques)
- **`threat_catalog.json`** - Main threat intelligence database (144 API calls)

### Testing
- **`test_threat_analyzer.py`** - Core functionality tests
- **`test_web_app.py`** - Web application tests

### Utilities
- **`update_threat_database.py`** - Database update utility
- **`create_iam_user.py`** - AWS IAM user creation utility
- **`get_caller_identity.py`** - AWS identity verification utility

## Templates Directory

HTML templates for the web interface:

```
templates/
├── base.html                       # Base template with common layout
├── dashboard.html                  # Main dashboard page
├── analyze.html                    # Analysis tools page
└── database.html                   # Database browser page
```

### Template Features
- **Bootstrap 5** for responsive design
- **Chart.js** for data visualization
- **Font Awesome** for icons
- **Jinja2** templating engine

## Documentation Directory

```
docs/
├── installation.md                 # Installation guide
├── user-guide.md                   # User manual
├── api.md                          # API documentation
├── examples.md                     # Usage examples
└── project-structure.md            # This file
```

## Infrastructure

### AWS Architecture (Simplified)

```
┌─────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Internet  │───▶│ Application     │───▶│   ECS Fargate   │
│             │    │ Load Balancer   │    │     Tasks       │
└─────────────┘    └─────────────────┘    └─────────────────┘
                            │                       │
                   ┌─────────────────┐    ┌─────────────────┐
                   │   Route 53      │    │   CloudWatch    │
                   │   (Optional)    │    │     Logs        │
                   └─────────────────┘    └─────────────────┘
```

### Infrastructure Files
- **`infrastructure/cloudformation-infrastructure.yaml`** - Main infrastructure template
- **`infrastructure/cloudformation-cicd.yaml`** - CI/CD pipeline template
- **`scripts/deploy-infrastructure.sh`** - Infrastructure deployment script
- **`scripts/deploy-cicd.sh`** - CI/CD deployment script
- **`scripts/validate-deployment.sh`** - Deployment validation script
- **`Dockerfile`** - Container image definition
- **`docker-compose.yml`** - Local development environment

## Key Components

### Threat Analysis Engine (`threat_intel_app.py`)

**Classes:**
- `AWSAPIThreatAnalyzer` - Main analysis engine

**Key Methods:**
- `analyze_api_call()` - Single API call analysis
- `analyze_api_sequence()` - Multi-call sequence analysis
- `generate_report()` - Report generation

### Web Application (`web_app.py`)

**API Endpoints:**
- `/` - Dashboard
- `/analyze` - Analysis tools
- `/database` - Database browser
- `/api/analyze/single` - Single API analysis
- `/api/analyze/sequence` - Sequence analysis
- `/api/database/stats` - Database statistics
- `/api/database/search` - Search functionality

### Threat Catalog Loader (`aws_threat_catalog_loader.py`)

**Classes:**
- `AWSCompleteThreatCatalogLoader` - Loads all 68 MITRE ATT&CK techniques
- `ThreatTechnique` - Data structure for threat information

**Features:**
- 68 MITRE ATT&CK techniques
- 144 AWS API calls mapped
- 12 attack tactics covered
- 43 AWS services included

## Data Structure

### Threat Database Schema

```json
{
  "api_call_name": {
    "technique_id": "T1234.567",
    "technique_name": "Technique Name",
    "tactic": "Attack Tactic",
    "description": "Detailed description",
    "aws_services": ["Service1", "Service2"],
    "api_calls": ["api:Call1", "api:Call2"],
    "detection_methods": ["Method 1", "Method 2"],
    "mitigation": "Mitigation strategy",
    "severity": "HIGH|MEDIUM|LOW|CRITICAL",
    "references": ["URL1", "URL2"],
    "playbook_url": "URL or null"
  }
}
```

### Analysis Response Schema

```json
{
  "risk_score": 85,
  "tactics_identified": ["Tactic1", "Tactic2"],
  "individual_calls": [...],
  "attack_chains": [...],
  "analysis_timestamp": "ISO timestamp"
}
```

## Dependencies

### Core Dependencies
- **FastAPI** - Web framework
- **Uvicorn** - ASGI server
- **Jinja2** - Template engine
- **Requests** - HTTP client
- **PyYAML** - YAML parsing
- **BeautifulSoup4** - HTML parsing

### Development Dependencies
- **Boto3** - AWS SDK (for examples)
- **HTTPx** - Testing HTTP client

## Configuration

### Environment Variables
- `HOST` - Web server host (default: 0.0.0.0)
- `PORT` - Web server port (default: 8000)
- `RELOAD` - Enable auto-reload (default: False)

### File Locations
- **Database**: `threat_catalog.json`
- **Templates**: `templates/`
- **Static files**: `static/` (auto-created)
- **Logs**: Console output

## Development Workflow

### Adding New Techniques
1. Update `aws_threat_catalog_loader.py`
2. Add technique to the mapping dictionary
3. Run `python3 update_threat_database.py`
4. Test with `python3 test_threat_analyzer.py`

### Modifying Web Interface
1. Update templates in `templates/`
2. Modify API endpoints in `web_app.py`
3. Test with `python3 test_web_app.py`
4. Restart application

### Database Updates
1. Modify loader in `aws_threat_catalog_loader.py`
2. Run update script: `python3 update_threat_database.py`
3. Restart web application
4. Verify with `/api/database/stats`

## Deployment Considerations

### Production Deployment
- Use proper ASGI server (Gunicorn + Uvicorn)
- Implement authentication/authorization
- Add rate limiting
- Use reverse proxy (Nginx)
- Enable HTTPS
- Monitor performance and logs

### Security Considerations
- No authentication in current version
- Designed for internal/trusted networks
- Consider adding API keys for production
- Implement input validation
- Add request logging

### Scalability
- Single-threaded application
- In-memory database
- Consider Redis for caching
- Database can be externalized
- Horizontal scaling possible

## Maintenance

### Regular Tasks
- Update threat intelligence database
- Review and update API mappings
- Monitor for new MITRE ATT&CK techniques
- Update dependencies
- Review and update documentation

### Monitoring
- Application health: `/health`
- Database statistics: `/api/database/stats`
- Error logs in console output
- Performance metrics via FastAPI

### Backup
- Backup `threat_catalog.json`
- Version control for code changes
- Document configuration changes
- Export analysis reports regularly