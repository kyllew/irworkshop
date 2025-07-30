# AWS Threat Intelligence Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)

A comprehensive web application for analyzing AWS API calls against the MITRE ATT&CK framework and AWS threat intelligence catalog. Built for security analysts and incident responders.

## 🏗️ Architecture

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

**Simplified Production Architecture:**
- **Application Load Balancer** - HTTPS termination and load balancing
- **ECS Fargate** - Containerized application hosting
- **VPC** - Isolated network with public/private subnets
- **Route 53** - DNS management (optional)
- **CI/CD Pipeline** - Automated deployment via CodePipeline

## 🚀 Features

### 🔍 **Threat Analysis**
- **Single API Call Analysis**: Analyze individual AWS API calls for threat intelligence
- **API Sequence Analysis**: Detect attack patterns across multiple API calls
- **Risk Scoring**: Calculate threat levels (0-100) based on tactics and severity
- **Attack Chain Detection**: Identify common attack patterns like privilege escalation

### 🌐 **Web Interface**
- **Interactive Dashboard**: Real-time statistics and quick analysis
- **Analysis Tools**: Multiple analysis modes with rich visualizations
- **Database Browser**: Explore the complete threat intelligence database
- **Search & Filtering**: Find techniques by API calls, tactics, or descriptions

### 📊 **Intelligence Database**
- **MITRE ATT&CK Integration**: Maps to official MITRE ATT&CK techniques
- **AWS Threat Catalog**: Based on AWS samples threat technique catalog
- **Playbook Integration**: Links to AWS customer playbook framework
- **Real-time Updates**: Automatically loads latest threat intelligence

### 🚀 **API Endpoints**
- RESTful API for programmatic access
- JSON responses for easy integration
- Comprehensive error handling
- OpenAPI/Swagger documentation

## Quick Start

### Prerequisites
- Python 3.9+
- pip package manager

### Installation

1. **Clone or download the project files**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the web application**:
   ```bash
   python3 start_web_app.py
   ```
   
   Or directly:
   ```bash
   python3 web_app.py
   ```

The application will be available at: http://localhost:8000

## 🚀 AWS Deployment

Deploy to AWS with the simplified architecture:

```bash
# 1. Simple deployment (HTTP only)
./scripts/deploy-infrastructure.sh deploy

# 2. Upload source code to S3
./scripts/upload-source.sh upload

# 3. Deploy CI/CD pipeline
./scripts/deploy-cicd.sh deploy

# Optional: With custom domain and HTTPS
DOMAIN_NAME=your-domain.com CERTIFICATE_ARN=your-cert-arn \
./scripts/deploy-infrastructure.sh deploy
```

See the [Deployment Guide](docs/deployment.md) for detailed instructions.

4. **Access the application**:
   - Dashboard: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - Health Check: http://localhost:8000/health

## Usage Guide

### Web Interface

#### Dashboard
- View threat intelligence statistics
- Quick API call analysis
- System status monitoring
- Navigation to other features

#### Analysis Page
- **Single API Call**: Enter an AWS API call (e.g., `iam:CreateUser`) for analysis
- **API Sequence**: Analyze multiple API calls for attack patterns
- **CloudTrail Logs**: (Coming soon) Direct CloudTrail log analysis

#### Database Browser
- Browse all threat techniques
- Search by API calls, techniques, or descriptions
- Filter by MITRE ATT&CK tactics
- View detailed technique information

### API Endpoints

#### Analyze Single API Call
```bash
curl -X POST "http://localhost:8000/api/analyze/single" \
     -H "Content-Type: application/json" \
     -d '{"api_call": "iam:CreateUser"}'
```

#### Analyze API Sequence
```bash
curl -X POST "http://localhost:8000/api/analyze/sequence" \
     -H "Content-Type: application/json" \
     -d '{
       "api_calls": ["iam:CreateUser", "iam:AttachUserPolicy", "iam:CreateAccessKey"],
       "context": "Incident #12345"
     }'
```

#### Search Database
```bash
curl "http://localhost:8000/api/database/search?q=iam"
```

#### Get Database Statistics
```bash
curl "http://localhost:8000/api/database/stats"
```

## Example Analysis

### Single API Call
Input: `iam:AttachUserPolicy`

Output:
- **Technique**: Account Manipulation: Additional Cloud Credentials (T1098.001)
- **Tactic**: Privilege Escalation
- **Severity**: HIGH
- **Detection Methods**: Monitor CloudTrail for unusual policy attachments
- **Mitigation**: Implement least privilege access, use SCPs

### API Sequence
Input:
```
iam:CreateUser
iam:AttachUserPolicy
iam:CreateAccessKey
```

Output:
- **Risk Score**: 100/100
- **Tactics**: Persistence, Privilege Escalation
- **Attack Chain Detected**: Privilege Escalation Chain
- **Individual Analysis**: 3 techniques identified

## Architecture

### Components
- **`threat_catalog_loader.py`**: Loads threat intelligence from AWS sources
- **`threat_intel_app.py`**: Core analysis engine
- **`web_app.py`**: FastAPI web application
- **`templates/`**: HTML templates for web interface
- **`test_*.py`**: Test suites for validation

### Data Sources
- [AWS Threat Technique Catalog](https://aws-samples.github.io/threat-technique-catalog-for-aws/)
- [AWS Customer Playbook Framework](https://github.com/aws-samples/aws-customer-playbook-framework)
- MITRE ATT&CK Framework

### Database Structure
The threat database maps AWS API calls to:
- MITRE ATT&CK Technique ID and Name
- Tactic (e.g., Privilege Escalation, Persistence)
- Severity Level (CRITICAL, HIGH, MEDIUM, LOW)
- AWS Services involved
- Detection methods
- Mitigation strategies
- Related API calls
- Reference links

## Testing

### Run All Tests
```bash
python3 test_threat_analyzer.py
python3 test_web_app.py
```

### Interactive Testing
```bash
python3 test_threat_analyzer.py --interactive
```

## Configuration

### Environment Variables
- `HOST`: Web server host (default: 0.0.0.0)
- `PORT`: Web server port (default: 8000)
- `RELOAD`: Enable auto-reload in development (default: True)

### Database Updates
The threat database is automatically cached locally (`threat_catalog.json`) and updated from remote sources when needed.

## Use Cases

### Security Analysts
- Investigate suspicious AWS API activity
- Understand attack techniques and tactics
- Generate incident response reports
- Research threat intelligence

### Incident Responders
- Quickly analyze CloudTrail logs
- Identify attack patterns
- Assess threat severity
- Plan response strategies

### Security Engineers
- Validate detection rules
- Understand AWS security threats
- Design monitoring strategies
- Security awareness training

## Contributing

### Adding New Techniques
1. Update `threat_catalog_loader.py` with new data sources
2. Add techniques to the `_add_common_techniques()` method
3. Test with `python3 test_threat_analyzer.py`

### Enhancing the Web Interface
1. Modify templates in `templates/` directory
2. Update API endpoints in `web_app.py`
3. Test with `python3 test_web_app.py`

## Troubleshooting

### Common Issues

**Database not loading**:
- Check internet connectivity for remote sources
- Verify `threat_catalog.json` exists and is readable

**Web server not starting**:
- Ensure all dependencies are installed
- Check if port 8000 is available
- Review error messages in console

**Analysis returning no results**:
- Verify API call format (service:action)
- Check if technique exists in database
- Try related API calls

### Debug Mode
Run with debug logging:
```bash
python3 web_app.py --log-level debug
```

## License

This project is provided as-is for educational and security research purposes.

## 📈 Database Statistics

- **68 MITRE ATT&CK Techniques** mapped to AWS services
- **144 AWS API calls** with threat intelligence
- **12 MITRE ATT&CK Tactics** covered
- **43 AWS Services** analyzed

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [AWS Security Team](https://aws-samples.github.io/threat-technique-catalog-for-aws/) for threat intelligence catalogs
- [MITRE Corporation](https://attack.mitre.org/) for the ATT&CK framework
- [FastAPI](https://fastapi.tiangolo.com/) and Python communities for excellent frameworks

## 📞 Support

If you have questions or need help:

1. Check the [Issues](https://github.com/kyllew/irworkshop/issues) page
2. Create a new issue with detailed information
3. Join the discussion in existing issues

## 🔗 Related Projects

- [AWS Threat Technique Catalog](https://aws-samples.github.io/threat-technique-catalog-for-aws/)
- [AWS Customer Playbook Framework](https://github.com/aws-samples/aws-customer-playbook-framework)
- [MITRE ATT&CK](https://attack.mitre.org/)