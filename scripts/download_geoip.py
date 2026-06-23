#!/usr/bin/env python3
import os
import sys
import urllib.request
import zipfile
import shutil
from pathlib import Path

GEO_DIR = Path(__file__).resolve().parent.parent / "data"
CITY_URL = "https://git.io/GeoLite2-City.mmdb"
ASN_URL = "https://git.io/GeoLite2-ASN.mmdb"

def download(url: str, dest: Path):
    print(f"Downloading {dest.name}...")
    try:
        urllib.request.urlretrieve(url, dest)
        print(f"  Saved to {dest} ({dest.stat().st_size / 1024 / 1024:.1f} MB)")
        return True
    except Exception as e:
        print(f"  Failed: {e}")
        return False

def main():
    GEO_DIR.mkdir(parents=True, exist_ok=True)
    city_path = GEO_DIR / "GeoLite2-City.mmdb"
    asn_path = GEO_DIR / "GeoLite2-ASN.mmdb"

    if "--check" in sys.argv:
        if city_path.exists() and asn_path.exists():
            print(f"Both DBs exist ({city_path}, {asn_path})")
            return
        print("One or both DBs missing. Run without --check to download.")

    if not city_path.exists():
        download(CITY_URL, city_path)
    else:
        print(f"{city_path.name} already exists")

    if not asn_path.exists():
        download(ASN_URL, asn_path)
    else:
        print(f"{asn_path.name} already exists")

if __name__ == "__main__":
    main()
