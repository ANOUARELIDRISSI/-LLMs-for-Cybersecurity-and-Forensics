#!/usr/bin/env python3
"""
Test script to verify dashboard functionality
"""

import requests
import json

def test_dashboard_endpoints():
    """Test all dashboard API endpoints"""
    base_url = "http://localhost:5000"
    
    endpoints = [
        "/api/system-status",
        "/api/threat-analytics", 
        "/api/forensics-analytics",
        "/api/soc-analytics",
        "/api/security-analytics",
        "/api/training-metrics"
    ]
    
    print("Testing Dashboard API Endpoints")
    print("=" * 50)
    
    for endpoint in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}")
            data = response.json()
            
            print(f"\n✓ {endpoint}")
            print(f"  Status: {response.status_code}")
            
            if endpoint == "/api/system-status":
                datasets = data.get("datasets", {})
                modules = data.get("modules", {})
                
                print(f"  Datasets: {len(datasets)} total")
                available = sum(1 for d in datasets.values() if d.get("exists", False))
                print(f"  Available: {available}/{len(datasets)}")
                
                print(f"  Modules: {len(modules)} total")
                active = sum(1 for m in modules.values() if m.get("status") == "active")
                print(f"  Active: {active}/{len(modules)}")
                
                print("  Dataset Details:")
                for name, info in datasets.items():
                    status = "✓" if info.get("exists") else "✗"
                    print(f"    {status} {name}: {info.get('description', 'No description')}")
            
            elif "error" in data:
                print(f"  Error: {data['error']}")
            else:
                print(f"  Data keys: {list(data.keys())}")
                
        except Exception as e:
            print(f"\n✗ {endpoint}")
            print(f"  Error: {e}")
    
    print("\n" + "=" * 50)
    print("Dashboard Test Complete")

if __name__ == "__main__":
    test_dashboard_endpoints()