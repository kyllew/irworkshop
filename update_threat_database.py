#!/usr/bin/env python3

import sys
import os
import shutil
from aws_threat_catalog_loader import AWSCompleteThreatCatalogLoader

def update_threat_database():
    """Update the threat database with enhanced techniques"""
    print("Updating AWS Threat Intelligence Database")
    print("="*50)
    
    try:
        # Backup existing database
        if os.path.exists("threat_catalog.json"):
            shutil.copy("threat_catalog.json", "threat_catalog_backup.json")
            print("✓ Backed up existing database")
        
        # Load complete catalog
        loader = AWSCompleteThreatCatalogLoader()
        catalog = loader.load_full_catalog()
        
        # Save the enhanced catalog
        loader.save_catalog_to_file("threat_catalog.json")
        
        # Also save as enhanced version
        loader.save_catalog_to_file("enhanced_threat_catalog.json")
        
        print(f"\n✓ Database updated successfully!")
        print(f"✓ Total techniques: {len(catalog)}")
        
        # Show statistics
        tactic_counts = {}
        severity_counts = {}
        service_counts = {}
        
        for technique in catalog.values():
            tactic_counts[technique.tactic] = tactic_counts.get(technique.tactic, 0) + 1
            severity_counts[technique.severity] = severity_counts.get(technique.severity, 0) + 1
            
            for service in technique.aws_services:
                service_counts[service] = service_counts.get(service, 0) + 1
        
        print(f"\nDatabase Statistics:")
        print(f"Tactics covered: {len(tactic_counts)}")
        print(f"AWS services covered: {len(service_counts)}")
        print(f"Severity levels: {list(severity_counts.keys())}")
        
        print(f"\nTactic distribution:")
        for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {tactic}: {count} techniques")
        
        print(f"\nSeverity distribution:")
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity}: {count} techniques")
        
        print(f"\nTop AWS services:")
        top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for service, count in top_services:
            print(f"  {service}: {count} techniques")
        
        print(f"\n🎉 Database update complete!")
        print(f"Restart your web application to see the new techniques.")
        
        return True
        
    except Exception as e:
        print(f"✗ Error updating database: {e}")
        import traceback
        traceback.print_exc()
        
        # Restore backup if it exists
        if os.path.exists("threat_catalog_backup.json"):
            shutil.copy("threat_catalog_backup.json", "threat_catalog.json")
            print("✓ Restored backup database")
        
        return False

def main():
    """Main function"""
    success = update_threat_database()
    
    if success:
        print(f"\nNext steps:")
        print(f"1. Restart your web application:")
        print(f"   python3 web_app.py")
        print(f"2. Visit http://localhost:8000/database to see all techniques")
        print(f"3. Try analyzing API sequences for better attack detection")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()