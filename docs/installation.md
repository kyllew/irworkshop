# Installation Guide

## Prerequisites

- Python 3.9 or higher
- pip package manager
- Git (for cloning the repository)

## Quick Installation

### 1. Clone the Repository

```bash
git clone https://github.com/kyllew/irworkshop.git
cd irworkshop
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Start the Application

```bash
python3 web_app.py
```

The application will be available at: http://localhost:8000

## Detailed Installation

### Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Dependencies Explained

- **FastAPI**: Web framework for the API and web interface
- **Uvicorn**: ASGI server for running the FastAPI application
- **Jinja2**: Template engine for HTML rendering
- **Requests**: HTTP library for fetching threat intelligence
- **PyYAML**: YAML parsing for configuration files
- **BeautifulSoup4**: HTML parsing for web scraping
- **Boto3**: AWS SDK for Python (for AWS API examples)

## Verification

### Test the Installation

```bash
# Run the test suite
python3 test_threat_analyzer.py
python3 test_web_app.py

# Check database statistics
python3 -c "
from complete_catalog_loader import CompleteCatalogLoader
loader = CompleteCatalogLoader()
loader.load_catalog_from_file('threat_catalog.json')
print(f'Loaded {len(loader.threat_db)} techniques')
"
```

### Expected Output

- **68 MITRE ATT&CK techniques** loaded
- **144 AWS API calls** mapped
- Web server running on port 8000

## Troubleshooting

### Common Issues

**Port 8000 already in use:**
```bash
# Find and kill the process
lsof -ti:8000 | xargs kill -9

# Or use a different port
python3 -c "
import uvicorn
from web_app import app
uvicorn.run(app, host='0.0.0.0', port=8080)
"
```

**Missing dependencies:**
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**Database not loading:**
```bash
# Regenerate the threat database
python3 complete_catalog_loader.py
```

## Docker Installation (Optional)

Create a `Dockerfile`:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python3", "web_app.py"]
```

Build and run:

```bash
docker build -t aws-threat-analyzer .
docker run -p 8000:8000 aws-threat-analyzer
```

## Development Setup

For development with auto-reload:

```bash
uvicorn web_app:app --host 0.0.0.0 --port 8000 --reload
```

## Next Steps

After installation:

1. Visit http://localhost:8000 for the dashboard
2. Check out the [API Documentation](api.md)
3. Read the [User Guide](user-guide.md)
4. Explore [Examples](examples.md)