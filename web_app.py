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
from aws_tactics_data import get_all_tactics, get_tactic_info, update_tactic_counts, update_tactic_techniques
from guardduty_findings_scraper import GuardDutyFindingsScraper
from aws_playbook_framework import AWSPlaybookFrameworkIntegrator


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
    
    # Get database statistics - count unique techniques, not API calls
    unique_techniques = {}
    for api_call, technique in analyzer.threat_db.items():
        unique_techniques[technique.technique_id] = technique
    
    total_techniques = len(unique_techniques)
    tactic_counts = {}
    severity_counts = {}
    
    for technique in unique_techniques.values():
        tactic_counts[technique.tactic] = tactic_counts.get(technique.tactic, 0) + 1
        severity_counts[technique.severity] = severity_counts.get(technique.severity, 0) + 1
    
    # Update tactic counts and techniques in tactics data
    update_tactic_counts(tactic_counts)
    update_tactic_techniques(analyzer.threat_db)
    
    stats = {
        'total_techniques': total_techniques,
        'tactic_counts': tactic_counts,
        'severity_counts': severity_counts
    }
    
    # Get tactics information for the dashboard
    tactics_info = get_all_tactics()
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": stats,
        "tactics_info": tactics_info
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

@app.get("/guardduty", response_class=HTMLResponse)
async def guardduty_page(request: Request):
    """GuardDuty findings analysis page"""
    return templates.TemplateResponse("guardduty.html", {"request": request})

@app.get("/playbooks", response_class=HTMLResponse)
async def playbooks_page(request: Request):
    """Incident response playbooks page"""
    return templates.TemplateResponse("playbooks.html", {"request": request})



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
    
    # Count unique techniques, not API calls
    unique_techniques = {}
    for api_call, technique in analyzer.threat_db.items():
        unique_techniques[technique.technique_id] = technique
    
    total_techniques = len(unique_techniques)
    tactic_counts = {}
    severity_counts = {}
    service_counts = {}
    
    for technique in unique_techniques.values():
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

@app.get("/api/database/technique/{technique_id}")
async def get_technique_by_id(technique_id: str):
    """Get detailed information about a specific technique by ID"""
    try:
        analyzer = get_analyzer()
        
        # Debug: Log the search
        print(f"Searching for technique ID: {technique_id}")
        print(f"Database size: {len(analyzer.threat_db)}")
        
        # Find the technique in the database
        matching_techniques = []
        technique_ids_found = set()
        
        for api_call, technique in analyzer.threat_db.items():
            technique_ids_found.add(technique.technique_id)
            if technique.technique_id == technique_id:
                matching_techniques.append({
                    "technique_id": technique.technique_id,
                    "technique_name": technique.technique_name,
                    "tactic": technique.tactic,
                    "severity": technique.severity,
                    "description": technique.description,
                    "aws_services": technique.aws_services,
                    "api_call": api_call,
                    "detection_methods": technique.detection_methods,
                    "mitigation": technique.mitigation,
                    "references": technique.references
                })
        
        # Debug: Log what we found
        print(f"Found {len(matching_techniques)} matches for {technique_id}")
        print(f"All technique IDs in database: {sorted(list(technique_ids_found))}")
        
        if not matching_techniques:
            # Check if the technique ID exists at all
            if technique_id in technique_ids_found:
                print(f"Technique {technique_id} exists but no matches found - this shouldn't happen")
            else:
                print(f"Technique {technique_id} not found in database")
            raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
        
        # Get unique technique info and all associated API calls
        technique_info = matching_techniques[0]
        technique_info["api_calls"] = [t["api_call"] for t in matching_techniques]
        
        return {
            "technique": technique_info,
            "total_api_calls": len(matching_techniques)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting technique details: {str(e)}")

@app.get("/api/database/debug/{technique_id}")
async def debug_technique_lookup(technique_id: str):
    """Debug endpoint to check technique lookup"""
    try:
        analyzer = get_analyzer()
        
        # Get all unique technique IDs
        all_technique_ids = set()
        technique_details = {}
        
        for api_call, technique in analyzer.threat_db.items():
            all_technique_ids.add(technique.technique_id)
            if technique.technique_id not in technique_details:
                technique_details[technique.technique_id] = {
                    "name": technique.technique_name,
                    "tactic": technique.tactic,
                    "api_calls": []
                }
            technique_details[technique.technique_id]["api_calls"].append(api_call)
        
        return {
            "searched_for": technique_id,
            "found": technique_id in all_technique_ids,
            "all_technique_ids": sorted(list(all_technique_ids)),
            "technique_details": technique_details.get(technique_id, "Not found"),
            "total_techniques": len(all_technique_ids),
            "total_api_calls": len(analyzer.threat_db)
        }
    except Exception as e:
        return {"error": str(e)}

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

@app.get("/api/database/all")
async def get_all_techniques():
    """Get all techniques for the matrix view"""
    analyzer = get_analyzer()
    
    # Use a dictionary to deduplicate techniques by technique_id
    unique_techniques = {}
    
    for api_call, technique in analyzer.threat_db.items():
        technique_id = technique.technique_id
        
        # If we haven't seen this technique before, add it
        if technique_id not in unique_techniques:
            unique_techniques[technique_id] = {
                "technique_id": technique.technique_id,
                "technique_name": technique.technique_name,
                "tactic": technique.tactic,
                "severity": technique.severity,
                "api_calls": [api_call],  # Store as list
                "description": technique.description[:100] + "..." if len(technique.description) > 100 else technique.description,
                "aws_services": technique.aws_services
            }
        else:
            # If we've seen this technique, add the API call to the list
            unique_techniques[technique_id]["api_calls"].append(api_call)
            
            # Update severity to highest if current is higher
            current_severity = unique_techniques[technique_id]["severity"]
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            if severity_order.get(technique.severity, 0) > severity_order.get(current_severity, 0):
                unique_techniques[technique_id]["severity"] = technique.severity
    
    # Convert to list and add api_call field for backward compatibility
    techniques = []
    for technique_data in unique_techniques.values():
        # Add the first API call as 'api_call' for backward compatibility
        technique_data["api_call"] = technique_data["api_calls"][0]
        techniques.append(technique_data)
    
    return {"results": techniques, "count": len(techniques)}

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

@app.get("/api/tactics/{tactic_name}")
async def get_tactic_details(tactic_name: str):
    """Get detailed information about a specific tactic"""
    try:
        # Replace URL encoding
        tactic_name = tactic_name.replace("%20", " ").replace("+", " ")
        
        # Get analyzer and update tactics data
        analyzer = get_analyzer()
        update_tactic_techniques(analyzer.threat_db)
        
        tactic_info = get_tactic_info(tactic_name)
        
        # Get actual techniques from the database for this tactic
        actual_techniques = []
        for api_call, technique in analyzer.threat_db.items():
            if technique.tactic == tactic_name:
                technique_info = {
                    "technique_id": technique.technique_id,
                    "technique_name": technique.technique_name,
                    "severity": technique.severity,
                    "api_call": api_call
                }
                # Avoid duplicates
                if not any(t["technique_name"] == technique_info["technique_name"] for t in actual_techniques):
                    actual_techniques.append(technique_info)
        
        # Sort by technique ID - show all techniques
        actual_techniques.sort(key=lambda x: x["technique_id"])
        
        return {
            "name": tactic_info.name,
            "short_description": tactic_info.short_description,
            "description": tactic_info.description,
            "aws_context": tactic_info.aws_context,
            "techniques_count": tactic_info.techniques_count,
            "example_techniques": tactic_info.example_techniques or [],
            "actual_techniques": actual_techniques  # Show all techniques
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/tactics")
async def get_all_tactics_info():
    """Get information about all tactics"""
    try:
        tactics_info = get_all_tactics()
        return {
            tactic_name: {
                "name": info.name,
                "short_description": info.short_description,
                "description": info.description,
                "aws_context": info.aws_context,
                "techniques_count": info.techniques_count,
                "example_techniques": info.example_techniques or []
            }
            for tactic_name, info in tactics_info.items()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# GuardDuty API Routes
@app.get("/api/guardduty/scrape-findings")
async def scrape_guardduty_findings():
    """Scrape GuardDuty finding types from AWS documentation"""
    try:
        scraper = GuardDutyFindingsScraper()
        findings = scraper.scrape_finding_types()
        
        if findings:
            # Save findings to file for caching
            scraper.save_findings_to_file(findings, "guardduty_findings.json")
            
            return {
                "status": "success",
                "total_findings": len(findings),
                "findings": [
                    {
                        "finding_type": finding.finding_type,
                        "category": finding.category,
                        "severity": finding.severity,
                        "description": finding.description,
                        "mitre_tactics": finding.mitre_tactics or [],
                        "aws_services": finding.aws_services or []
                    }
                    for finding in findings
                ],
                "scraped_timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "status": "no_findings",
                "message": "No findings could be scraped from AWS documentation",
                "total_findings": 0,
                "findings": []
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error scraping GuardDuty findings: {str(e)}")

@app.get("/api/guardduty/findings")
async def get_guardduty_findings():
    """Get cached GuardDuty findings"""
    try:
        scraper = GuardDutyFindingsScraper()
        
        # Try to load from cache first
        findings = scraper.load_findings_from_file("guardduty_findings.json")
        
        if not findings:
            # If no cache, try to scrape
            findings = scraper.scrape_finding_types()
            if findings:
                scraper.save_findings_to_file(findings, "guardduty_findings.json")
        
        return {
            "total_findings": len(findings),
            "findings": [
                {
                    "finding_type": finding.finding_type,
                    "category": finding.category,
                    "severity": finding.severity,
                    "description": finding.description,
                    "remediation": finding.remediation,
                    "mitre_tactics": finding.mitre_tactics or [],
                    "aws_services": finding.aws_services or [],
                    "threat_purpose": finding.threat_purpose
                }
                for finding in findings
            ],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting GuardDuty findings: {str(e)}")

@app.get("/api/guardduty/analysis")
async def get_guardduty_analysis():
    """Get GuardDuty findings analysis"""
    try:
        scraper = GuardDutyFindingsScraper()
        findings = scraper.load_findings_from_file("guardduty_findings.json")
        
        if not findings:
            findings = scraper.scrape_finding_types()
            if findings:
                scraper.save_findings_to_file(findings, "guardduty_findings.json")
        
        if not findings:
            return {
                "error": "No GuardDuty findings available",
                "analysis": {}
            }
        
        analysis = scraper.analyze_findings(findings)
        return analysis
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing GuardDuty findings: {str(e)}")

@app.get("/api/guardduty/correlations")
async def get_mitre_guardduty_correlations():
    """Get correlations between MITRE techniques and GuardDuty findings"""
    try:
        # Get MITRE techniques
        analyzer = get_analyzer()
        
        # Get GuardDuty findings
        scraper = GuardDutyFindingsScraper()
        findings = scraper.load_findings_from_file("guardduty_findings.json")
        
        if not findings:
            findings = scraper.scrape_finding_types()
            if findings:
                scraper.save_findings_to_file(findings, "guardduty_findings.json")
        
        if not findings:
            return {
                "error": "No GuardDuty findings available for correlation",
                "correlations": []
            }
        
        # Find correlations
        correlations = scraper.find_mitre_correlations(findings, analyzer.threat_db)
        
        return {
            "total_correlations": len(correlations),
            "correlations": correlations,
            "analysis_timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error finding correlations: {str(e)}")

@app.get("/api/guardduty/search")
async def search_guardduty_findings(q: str = ""):
    """Search GuardDuty findings"""
    try:
        if not q:
            return {"results": []}
        
        scraper = GuardDutyFindingsScraper()
        findings = scraper.load_findings_from_file("guardduty_findings.json")
        
        if not findings:
            return {"results": []}
        
        query = q.lower()
        results = []
        
        for finding in findings:
            # Search in finding type, category, description
            if (query in finding.finding_type.lower() or 
                query in finding.category.lower() or 
                query in finding.description.lower() or
                (finding.mitre_tactics and any(query in tactic.lower() for tactic in finding.mitre_tactics)) or
                (finding.aws_services and any(query in service.lower() for service in finding.aws_services))):
                
                results.append({
                    "finding_type": finding.finding_type,
                    "category": finding.category,
                    "severity": finding.severity,
                    "description": finding.description[:200] + "..." if len(finding.description) > 200 else finding.description,
                    "mitre_tactics": finding.mitre_tactics or [],
                    "aws_services": finding.aws_services or []
                })
        
        return {"results": results[:20]}  # Limit to 20 results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error searching GuardDuty findings: {str(e)}")

# Playbook API Routes
@app.get("/api/playbooks/compromised-iam")
async def get_compromised_iam_playbook():
    """Get the Compromised IAM Credentials playbook"""
    try:
        integrator = AWSPlaybookFrameworkIntegrator()
        playbook = integrator.load_compromised_iam_playbook()
        
        if not playbook:
            raise HTTPException(status_code=500, detail="Failed to load playbook")
        
        return {
            "playbook_id": playbook.playbook_id,
            "title": playbook.title,
            "description": playbook.description,
            "incident_type": playbook.incident_type,
            "severity": playbook.severity,
            "sections": [
                {
                    "section_name": section.section_name,
                    "description": section.description,
                    "steps": [
                        {
                            "step_number": step.step_number,
                            "title": step.title,
                            "description": step.description,
                            "actions": step.actions,
                            "aws_apis": step.aws_apis or [],
                            "mitre_techniques": step.mitre_techniques or [],
                            "guardduty_findings": step.guardduty_findings or [],
                            "automation_possible": step.automation_possible
                        }
                        for step in section.steps
                    ]
                }
                for section in playbook.sections
            ],
            "related_mitre_tactics": playbook.related_mitre_tactics or [],
            "aws_services": playbook.aws_services or [],
            "last_updated": playbook.last_updated
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading playbook: {str(e)}")

@app.get("/api/playbooks/s3-public-access")
async def get_s3_public_access_playbook():
    """Get the S3 Public Access playbook"""
    try:
        integrator = AWSPlaybookFrameworkIntegrator()
        playbook = integrator.load_s3_public_access_playbook()
        
        if not playbook:
            raise HTTPException(status_code=500, detail="Failed to load playbook")
        
        return {
            "playbook_id": playbook.playbook_id,
            "title": playbook.title,
            "description": playbook.description,
            "incident_type": playbook.incident_type,
            "severity": playbook.severity,
            "sections": [
                {
                    "section_name": section.section_name,
                    "description": section.description,
                    "steps": [
                        {
                            "step_number": step.step_number,
                            "title": step.title,
                            "description": step.description,
                            "actions": step.actions,
                            "aws_apis": step.aws_apis or [],
                            "mitre_techniques": step.mitre_techniques or [],
                            "guardduty_findings": step.guardduty_findings or [],
                            "automation_possible": step.automation_possible
                        }
                        for step in section.steps
                    ]
                }
                for section in playbook.sections
            ],
            "related_mitre_tactics": playbook.related_mitre_tactics or [],
            "aws_services": playbook.aws_services or [],
            "last_updated": playbook.last_updated
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading playbook: {str(e)}")

@app.get("/api/playbooks/unauthorized-network-changes")
async def get_unauthorized_network_changes_playbook():
    """Get the Unauthorized Network Changes playbook"""
    try:
        integrator = AWSPlaybookFrameworkIntegrator()
        playbook = integrator.load_unauthorized_network_changes_playbook()
        
        if not playbook:
            raise HTTPException(status_code=500, detail="Failed to load playbook")
        
        return {
            "playbook_id": playbook.playbook_id,
            "title": playbook.title,
            "description": playbook.description,
            "incident_type": playbook.incident_type,
            "severity": playbook.severity,
            "sections": [
                {
                    "section_name": section.section_name,
                    "description": section.description,
                    "steps": [
                        {
                            "step_number": step.step_number,
                            "title": step.title,
                            "description": step.description,
                            "actions": step.actions,
                            "aws_apis": step.aws_apis or [],
                            "mitre_techniques": step.mitre_techniques or [],
                            "guardduty_findings": step.guardduty_findings or [],
                            "automation_possible": step.automation_possible
                        }
                        for step in section.steps
                    ]
                }
                for section in playbook.sections
            ],
            "related_mitre_tactics": playbook.related_mitre_tactics or [],
            "aws_services": playbook.aws_services or [],
            "last_updated": playbook.last_updated
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading playbook: {str(e)}")

@app.get("/api/playbooks/correlations/mitre")
async def get_playbook_mitre_correlations(playbook_id: str = "compromised-iam"):
    """Get correlations between playbook steps and MITRE techniques"""
    try:
        # Get MITRE techniques
        analyzer = get_analyzer()
        
        # Get playbook based on ID
        integrator = AWSPlaybookFrameworkIntegrator()
        if playbook_id == "compromised_iam_credentials" or playbook_id == "compromised-iam":
            playbook = integrator.load_compromised_iam_playbook()
        elif playbook_id == "s3_public_access" or playbook_id == "s3-public-access":
            playbook = integrator.load_s3_public_access_playbook()
        elif playbook_id == "unauthorized_network_changes" or playbook_id == "unauthorized-network-changes":
            playbook = integrator.load_unauthorized_network_changes_playbook()
        else:
            raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")
        
        if not playbook:
            return {"error": "Failed to load playbook", "correlations": []}
        
        # Find correlations
        correlations = integrator.correlate_with_mitre_techniques(playbook, analyzer.threat_db)
        
        return correlations
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error finding MITRE correlations: {str(e)}")

@app.get("/api/playbooks/correlations/guardduty")
async def get_playbook_guardduty_correlations(playbook_id: str = "compromised-iam"):
    """Get correlations between playbook steps and GuardDuty findings"""
    try:
        # Get GuardDuty findings
        scraper = GuardDutyFindingsScraper()
        findings = scraper.load_findings_from_file("guardduty_findings.json")
        
        if not findings:
            findings = scraper.scrape_finding_types()
        
        # Get playbook based on ID
        integrator = AWSPlaybookFrameworkIntegrator()
        if playbook_id == "compromised_iam_credentials" or playbook_id == "compromised-iam":
            playbook = integrator.load_compromised_iam_playbook()
        elif playbook_id == "s3_public_access" or playbook_id == "s3-public-access":
            playbook = integrator.load_s3_public_access_playbook()
        elif playbook_id == "unauthorized_network_changes" or playbook_id == "unauthorized-network-changes":
            playbook = integrator.load_unauthorized_network_changes_playbook()
        else:
            raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")
        
        if not playbook:
            return {"error": "Failed to load playbook", "correlations": []}
        
        # Find correlations
        correlations = integrator.correlate_with_guardduty_findings(playbook, findings)
        
        return correlations
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error finding GuardDuty correlations: {str(e)}")

@app.get("/api/playbooks/automation-script")
async def get_automation_script(playbook_id: str = "compromised-iam"):
    """Generate automation script for the playbook"""
    try:
        integrator = AWSPlaybookFrameworkIntegrator()
        
        # Get playbook based on ID
        if playbook_id == "compromised_iam_credentials" or playbook_id == "compromised-iam":
            playbook = integrator.load_compromised_iam_playbook()
        elif playbook_id == "s3_public_access" or playbook_id == "s3-public-access":
            playbook = integrator.load_s3_public_access_playbook()
        elif playbook_id == "unauthorized_network_changes" or playbook_id == "unauthorized-network-changes":
            playbook = integrator.load_unauthorized_network_changes_playbook()
        else:
            raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")
        
        if not playbook:
            raise HTTPException(status_code=500, detail="Failed to load playbook")
        
        script = integrator.generate_automated_response_script(playbook)
        
        return {
            "playbook_id": playbook.playbook_id,
            "script": script,
            "filename": f"incident_response_{playbook.playbook_id}.sh",
            "generated_timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating automation script: {str(e)}")

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