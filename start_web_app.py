#!/usr/bin/env python3

import sys
import os
import subprocess
import time

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import fastapi
        import uvicorn
        import jinja2
        print("✓ All web dependencies are installed")
        return True
    except ImportError as e:
        print(f"✗ Missing dependency: {e}")
        print("Please install dependencies with: pip install -r requirements.txt")
        return False

def check_threat_database():
    """Check if threat database is available"""
    if os.path.exists("threat_catalog.json"):
        print("✓ Threat catalog found")
        return True
    else:
        print("⚠ Threat catalog not found, will be downloaded on first run")
        return True

def start_web_application():
    """Start the web application"""
    print("Starting AWS Threat Intelligence Web Application...")
    print("="*60)
    
    if not check_dependencies():
        return False
    
    check_threat_database()
    
    print("\nStarting web server...")
    print("Dashboard will be available at: http://localhost:8000")
    print("API documentation at: http://localhost:8000/docs")
    print("\nPress Ctrl+C to stop the server")
    print("="*60)
    
    try:
        # Import and run the web app
        from web_app import app
        import uvicorn
        
        uvicorn.run(
            "web_app:app", 
            host="0.0.0.0", 
            port=8000, 
            reload=True,
            log_level="info"
        )
        
    except KeyboardInterrupt:
        print("\n\nShutting down web application...")
        return True
    except Exception as e:
        print(f"\n✗ Error starting web application: {e}")
        return False

if __name__ == "__main__":
    success = start_web_application()
    sys.exit(0 if success else 1)