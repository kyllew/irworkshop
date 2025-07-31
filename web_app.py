#!/usr/bin/env python3

from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import json
import uvicorn
from datetime import datetime
import os

from threat_intel_app import AWSAPIThreatAnalyzer
from threat_catalog_loader import ThreatTechnique
from aws_threat_catalog_loader import AWSCompleteThreatCatalogLoader

# Pydantic models for API requests/responses
class APICallRequest(BaseModel):
    api_call: str

class APISequenceRequest(BaseModel):
    api_calls: List[str]
    context: Optional[str] = None

class AnalysisResponse(BaseModel):
    api_call: str
    technique_found: bool
    technique_info: Optional[Dict[str, Any]] = None

class SequenceAnalysisResponse(BaseModel):
    risk_score: int
    tactics_identified: List[str]
    individual_calls: List[Dict[str, Any]]
    attack_chains: List[Dict[str, Any]]
    analysis_timestamp: str

# Initialize FastAPI app
app = FastAPI(
    title="AWS Threat Catalog",
    description="Educational tool to analyze AWS API calls against MITRE ATT&CK framework - Not official AWS source",
    version="1.0.0"
)

# Global analyzer instance
analyzer = None

# Force reload flag
_force_reload = True

def get_analyzer():
    """Get or initialize the threat analyzer"""
    global analyzer, _force_reload
    if analyzer is None or _force_reload:
        try:
            print("Initializing analyzer with complete catalog...")
            
            # Check if threat_catalog.json exists
            import os
            catalog_path = "threat_catalog.json"
            if not os.path.exists(catalog_path):
                print(f"ERROR: {catalog_path} not found!")
                print(f"Current directory: {os.getcwd()}")
                print(f"Files in current directory: {os.listdir('.')}")
                raise FileNotFoundError(f"Threat catalog file not found: {catalog_path}")
            
            print(f"Found threat catalog file: {catalog_path}")
            
            # Initialize with AWS complete catalog loader
            aws_loader = AWSCompleteThreatCatalogLoader()
            aws_loader.load_catalog_from_file(catalog_path)
            
            # Create analyzer and set the database directly
            analyzer = AWSAPIThreatAnalyzer(use_remote_catalog=False)
            analyzer.threat_db = aws_loader.threat_db
            analyzer.catalog_loader = aws_loader
            
            print(f"✓ Loaded {len(analyzer.threat_db)} AWS threat techniques")
            _force_reload = False
            
        except Exception as e:
            print(f"ERROR initializing analyzer: {str(e)}")
            import traceback
            traceback.print_exc()
            raise
    return analyzer

# Create directories for static files and templates
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Templates
templates = Jinja2Templates(directory="templates")

@app.on_event("startup")
async def startup_event():
    """Initialize the analyzer on startup"""
    try:
        print("Initializing AWS Threat Catalog...")
        get_analyzer()
        print("✓ Analyzer ready")
    except Exception as e:
        print(f"ERROR during startup: {str(e)}")
        import traceback
        traceback.print_exc()
        # Don't raise here, let the application start and handle errors gracefully

# Web Interface Routes
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    analyzer = get_analyzer()
    
    # Get database statistics
    total_techniques = len(analyzer.threat_db)
    tactic_counts = {}
    severity_counts = {}
    
    for technique in analyzer.threat_db.values():
        tactic_counts[technique.tactic] = tactic_counts.get(technique.tactic, 0) + 1
        severity_counts[technique.severity] = severity_counts.get(technique.severity, 0) + 1
    
    stats = {
        'total_techniques': total_techniques,
        'tactic_counts': tactic_counts,
        'severity_counts': severity_counts
    }
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": stats
    })

@app.get("/analyze", response_class=HTMLResponse)
async def analyze_page(request: Request):
    """Analysis page"""
    return templates.TemplateResponse("analyze.html", {"request": request})

@app.get("/database", response_class=HTMLResponse)
async def database_page(request: Request):
    """Database browser page"""
    analyzer = get_analyzer()
    
    # Prepare database entries for display
    db_entries = []
    for api_call, technique in analyzer.threat_db.items():
        db_entries.append({
            'api_call': api_call,
            'technique': technique
        })
    
    # Sort by tactic and severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    db_entries.sort(key=lambda x: (x['technique'].tactic, severity_order.get(x['technique'].severity, 4)))
    
    return templates.TemplateResponse("database.html", {
        "request": request,
        "db_entries": db_entries
    })

# API Routes
@app.post("/api/analyze/single", response_model=AnalysisResponse)
async def analyze_single_api(request: APICallRequest):
    """Analyze a single API call"""
    analyzer = get_analyzer()
    
    try:
        technique = analyzer.analyze_api_call(request.api_call)
        
        if technique:
            return AnalysisResponse(
                api_call=request.api_call,
                technique_found=True,
                technique_info={
                    "technique_id": technique.technique_id,
                    "technique_name": technique.technique_name,
                    "tactic": technique.tactic,
                    "severity": technique.severity,
                    "description": technique.description,
                    "aws_services": technique.aws_services,
                    "api_calls": technique.api_calls,
                    "detection_methods": technique.detection_methods,
                    "mitigation": technique.mitigation,
                    "references": technique.references,
                    "playbook_url": technique.playbook_url
                }
            )
        else:
            return AnalysisResponse(
                api_call=request.api_call,
                technique_found=False
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze/sequence", response_model=SequenceAnalysisResponse)
async def analyze_api_sequence(request: APISequenceRequest):
    """Analyze a sequence of API calls"""
    analyzer = get_analyzer()
    
    try:
        analysis = analyzer.analyze_api_sequence(request.api_calls)
        
        # Convert ThreatTechnique objects to dictionaries
        individual_calls = []
        for call_info in analysis['individual_calls']:
            technique = call_info['threat_info']
            individual_calls.append({
                'api_call': call_info['api_call'],
                'technique_id': technique.technique_id,
                'technique_name': technique.technique_name,
                'tactic': technique.tactic,
                'severity': technique.severity,
                'description': technique.description,
                'detection_methods': technique.detection_methods,
                'mitigation': technique.mitigation
            })
        
        return SequenceAnalysisResponse(
            risk_score=analysis['risk_score'],
            tactics_identified=analysis['tactics_identified'],
            individual_calls=individual_calls,
            attack_chains=analysis['attack_chains'],
            analysis_timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/analyze/cloudtrail")
async def analyze_cloudtrail_logs(request: Request):
    """Analyze CloudTrail logs (placeholder for future implementation)"""
    # This would parse CloudTrail JSON logs and extract API calls
    return {"message": "CloudTrail analysis not yet implemented"}

@app.get("/api/database/stats")
async def get_database_stats():
    """Get database statistics"""
    analyzer = get_analyzer()
    
    total_techniques = len(analyzer.threat_db)
    tactic_counts = {}
    severity_counts = {}
    service_counts = {}
    
    for technique in analyzer.threat_db.values():
        tactic_counts[technique.tactic] = tactic_counts.get(technique.tactic, 0) + 1
        severity_counts[technique.severity] = severity_counts.get(technique.severity, 0) + 1
        
        for service in technique.aws_services:
            service_counts[service] = service_counts.get(service, 0) + 1
    
    return {
        "total_techniques": total_techniques,
        "tactic_counts": tactic_counts,
        "severity_counts": severity_counts,
        "service_counts": service_counts,
        "last_updated": datetime.now().isoformat()
    }

@app.get("/api/database/search")
async def search_database(q: str = ""):
    """Search the threat database"""
    analyzer = get_analyzer()
    
    if not q:
        return {"results": []}
    
    results = []
    query = q.lower()
    
    for api_call, technique in analyzer.threat_db.items():
        # Search in API call, technique name, description
        if (query in api_call.lower() or 
            query in technique.technique_name.lower() or 
            query in technique.description.lower() or
            query in technique.tactic.lower()):
            
            results.append({
                "api_call": api_call,
                "technique_id": technique.technique_id,
                "technique_name": technique.technique_name,
                "tactic": technique.tactic,
                "severity": technique.severity,
                "description": technique.description[:200] + "..." if len(technique.description) > 200 else technique.description
            })
    
    return {"results": results[:20]}  # Limit to 20 results

@app.get("/api/database/autocomplete")
async def get_autocomplete_suggestions(q: str = ""):
    """Get autocomplete suggestions for API calls"""
    analyzer = get_analyzer()
    
    if not q or len(q) < 2:
        return {"suggestions": []}
    
    query = q.lower()
    suggestions = []
    
    # Get all unique API calls from the database
    all_api_calls = set()
    for api_call, technique in analyzer.threat_db.items():
        all_api_calls.add(api_call)
        # Also add individual API calls from the technique's api_calls list
        for call in technique.api_calls:
            all_api_calls.add(call)
    
    # Filter API calls that match the query
    for api_call in sorted(all_api_calls):
        if query in api_call.lower():
            suggestions.append({
                "api_call": api_call,
                "service": api_call.split(':')[0] if ':' in api_call else "unknown"
            })
    
    # Limit to 10 suggestions for performance
    return {"suggestions": suggestions[:10]}

@app.get("/api/database/severity/{severity_level}")
async def get_techniques_by_severity(severity_level: str):
    """Get all techniques for a specific severity level"""
    analyzer = get_analyzer()
    
    techniques = []
    for api_call, technique in analyzer.threat_db.items():
        if technique.severity.lower() == severity_level.lower():
            techniques.append({
                "technique_id": technique.technique_id,
                "technique_name": technique.technique_name,
                "tactic": technique.tactic,
                "severity": technique.severity,
                "api_call": api_call,
                "description": technique.description[:100] + "..." if len(technique.description) > 100 else technique.description,
                "aws_services": technique.aws_services
            })
    
    return {"techniques": techniques, "severity": severity_level, "count": len(techniques)}

@app.get("/api/reports/generate")
async def generate_report(api_calls: str, format: str = "json"):
    """Generate analysis report"""
    analyzer = get_analyzer()
    
    try:
        # Parse API calls (comma-separated)
        api_call_list = [call.strip() for call in api_calls.split(',') if call.strip()]
        
        if not api_call_list:
            raise HTTPException(status_code=400, detail="No API calls provided")
        
        # Analyze sequence
        analysis = analyzer.analyze_api_sequence(api_call_list)
        
        # Generate report
        report = analyzer.generate_report(analysis, format)
        
        if format == "json":
            return JSONResponse(content=json.loads(report))
        else:
            return {"report": report, "format": format}
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    analyzer = get_analyzer()
    return {
        "status": "healthy",
        "analyzer_loaded": analyzer is not None,
        "database_size": len(analyzer.threat_db) if analyzer else 0,
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    print("Starting AWS Threat Intelligence Web Application...")
    print("Dashboard will be available at: http://localhost:8000")
    uvicorn.run("web_app:app", host="0.0.0.0", port=8000, reload=False)