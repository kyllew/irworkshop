#!/bin/bash

# Debug startup script for container
echo "=== Container Startup Debug ==="
echo "Current directory: $(pwd)"
echo "Files in current directory:"
ls -la

echo ""
echo "Checking for threat_catalog.json:"
if [ -f "threat_catalog.json" ]; then
    echo "✓ threat_catalog.json found"
    echo "File size: $(ls -lh threat_catalog.json | awk '{print $5}')"
else
    echo "✗ threat_catalog.json NOT found!"
fi

echo ""
echo "Python version:"
python3 --version

echo ""
echo "Installed packages:"
pip list

echo ""
echo "Starting application..."
python3 web_app.py 