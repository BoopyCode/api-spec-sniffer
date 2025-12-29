#!/usr/bin/env python3
"""
API Spec Sniffer - Because reading docs is for people with too much time.
"""

import sys
import json
import argparse
from urllib import request, parse
from http.client import HTTPResponse
from typing import Dict, Any, Optional


def sniff_endpoint(url: str, method: str = "GET", data: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Sniffs an API endpoint like a dog sniffs... well, you know.
    Returns whatever the API coughs up, plus some detective work.
    """
    result = {
        "url": url,
        "method": method,
        "success": False,
        "findings": {}
    }
    
    try:
        # Prepare the request with the subtlety of a bull in a china shop
        headers = {
            "User-Agent": "API-Sniffer/1.0 (Because docs lie)",
            "Accept": "application/json, */*"
        }
        
        req_data = None
        if data and method in ["POST", "PUT", "PATCH"]:
            req_data = parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        req = request.Request(url, data=req_data, headers=headers, method=method)
        
        # Make the request and hope for the best
        with request.urlopen(req, timeout=10) as response:
            result["status"] = response.status
            result["headers"] = dict(response.headers)
            
            # Try to read the response like a fortune cookie
            body = response.read().decode('utf-8', errors='ignore')
            
            # Guess the format (because who reads Content-Type anyway?)
            if body.strip().startswith('{') or body.strip().startswith('['):
                try:
                    result["body"] = json.loads(body)
                    result["findings"]["format"] = "JSON"
                except:
                    result["body"] = body
            else:
                result["body"] = body
            
            # Sherlock Holmes-level deduction
            if "application/json" in response.headers.get("Content-Type", ""):
                result["findings"]["format"] = "JSON"
            if "Bearer" in response.headers.get("Authorization", ""):
                result["findings"]["auth"] = "Bearer token"
            if "api_key" in url.lower() or "token" in url.lower():
                result["findings"]["auth_hint"] = "URL probably has auth params"
            
            result["success"] = True
            
    except Exception as e:
        result["error"] = str(e)
        result["findings"]["ouch"] = f"Endpoint says: {e}"
    
    return result


def main() -> None:
    """Main function - because every script needs one of these."""
    parser = argparse.ArgumentParser(description="Sniff API endpoints like a pro (or a very curious dog)")
    parser.add_argument("url", help="URL to sniff (make it a good one)")
    parser.add_argument("--method", "-m", default="GET", help="HTTP method (GET, POST, etc.)")
    parser.add_argument("--data", "-d", help="Data as key=value pairs, comma-separated")
    
    args = parser.parse_args()
    
    # Parse data if provided (because typing is hard)
    data = None
    if args.data:
        data = {k: v for k, v in [pair.split('=') for pair in args.data.split(',')]}
    
    print(f"\n🔍 Sniffing {args.method} {args.url}...\n")
    
    result = sniff_endpoint(args.url, args.method.upper(), data)
    
    # Print results with the flair of a magician revealing a trick
    print(json.dumps(result, indent=2, default=str))
    
    if result["success"]:
        print(f"\n✅ Sniff complete! Found {len(result['findings'])} clues.")
    else:
        print(f"\n❌ Sniff failed. Maybe try knocking first?")


if __name__ == "__main__":
    main()
