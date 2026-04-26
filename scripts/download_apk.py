#!/usr/bin/env python3
"""
APKPure downloader using BeautifulSoup + cloudscraper.
Downloads APK versions for any package from APKPure.
"""

import cloudscraper
from bs4 import BeautifulSoup
import re
import os
import sys
import json
import time
from urllib.parse import urljoin, quote

BASE_URL = "https://apkpure.com"

# Use cloudscraper to bypass Cloudflare
session = cloudscraper.create_scraper(
    browser={'browser': 'chrome', 'platform': 'linux', 'desktop': True}
)


def get_soup(url):
    """Fetch URL and return BeautifulSoup object."""
    print(f"[*] Fetching: {url}", file=sys.stderr)
    resp = session.get(url, timeout=30)
    resp.raise_for_status()
    return BeautifulSoup(resp.text, "html.parser")


def search_package(package_name):
    """Search for a package on APKPure and return its URL slug."""
    # Try common app slug patterns first (for well-known apps)
    common_slugs = {
        "com.whatsapp": "whatsapp-messenger",
        "com.facebook.katana": "facebook",
        "com.instagram.android": "instagram",
        "com.twitter.android": "twitter",
        "org.telegram.messenger": "telegram",
        "com.snapchat.android": "snapchat",
        "com.spotify.music": "spotify-music",
        "com.google.android.youtube": "youtube",
    }

    if package_name in common_slugs:
        return common_slugs[package_name]

    # Try searching APKPure
    search_url = f"{BASE_URL}/search?q={quote(package_name)}"
    soup = get_soup(search_url)

    # Look for exact package match in any link
    for a in soup.select('a[href]'):
        href = a.get("href", "")
        if package_name in href:
            # Extract app slug from URL like /app-name/com.package/...
            match = re.search(r'/([^/]+)/' + re.escape(package_name), href)
            if match:
                return match.group(1)

    # Try to find any result that might match
    for a in soup.select('.search-title a, .p-box a, a.dd'):
        href = a.get("href", "")
        if href and "/" in href:
            # Check if this is an app page
            match = re.search(r'^/([^/]+)/([^/]+)', href)
            if match and match.group(2).startswith("com."):
                return match.group(1)

    return None


def get_versions(package_name, app_slug=None, limit=30):
    """Get list of available versions from APKPure."""
    if not app_slug:
        app_slug = search_package(package_name)
        if not app_slug:
            print(f"[-] Could not find package: {package_name}", file=sys.stderr)
            return []

    versions_url = f"{BASE_URL}/{app_slug}/{package_name}/versions"
    soup = get_soup(versions_url)
    versions = []
    seen = set()

    # Find version links from the page
    for a in soup.select(f'a[href*="{package_name}/download"]'):
        href = a.get("href", "")
        text = a.get_text(strip=True)

        # Extract version from URL or text
        version_match = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', href) or re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', text)
        if version_match:
            version = version_match.group(1)
            if version in seen:
                continue
            seen.add(version)

            full_url = urljoin(BASE_URL, href)
            versions.append({
                "version": version,
                "url": full_url,
                "package": package_name,
                "app_slug": app_slug
            })

            if len(versions) >= limit:
                break

    return versions


def get_download_url(version_url, package_name):
    """Get the direct download URL from a version page."""
    soup = get_soup(version_url)

    # Look for direct download links (d.apkpure.com)
    for a in soup.select('a[href*="d.apkpure.com"]'):
        href = a.get("href", "")
        text = a.get_text(strip=True).lower()
        # Prefer arm64-v8a XAPK
        if "arm64" in href or "arm64" in text:
            return href, "xapk"

    # Fallback: any d.apkpure.com link
    for a in soup.select('a[href*="d.apkpure.com"]'):
        href = a.get("href", "")
        if "/XAPK/" in href:
            return href, "xapk"
        elif "/APK/" in href:
            return href, "apk"

    # Try data attributes on body
    body = soup.select_one("body[data-dt-apkid]")
    if body:
        version_code = body.get("data-version-code")
        if version_code:
            url = f"https://d.apkpure.com/b/XAPK/{package_name}?versionCode={version_code}&nc=arm64-v8a&sv=21"
            return url, "xapk"

    return None, None


def download_file(url, output_path):
    """Download file from URL with progress."""
    print(f"[*] Downloading: {url[:80]}...", file=sys.stderr)

    resp = session.get(url, stream=True, timeout=300, allow_redirects=True)
    resp.raise_for_status()

    # Check content type
    content_type = resp.headers.get("content-type", "")
    if "text/html" in content_type:
        print("[-] Got HTML instead of binary file", file=sys.stderr)
        return None

    total_size = int(resp.headers.get('content-length', 0))
    downloaded = 0

    with open(output_path, 'wb') as f:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)
                if total_size:
                    pct = (downloaded / total_size) * 100
                    mb = downloaded // 1024 // 1024
                    total_mb = total_size // 1024 // 1024
                    print(f"\r[*] {pct:.1f}% ({mb}MB / {total_mb}MB)", end="", flush=True, file=sys.stderr)

    print(f"\n[+] Saved: {output_path} ({downloaded // 1024 // 1024}MB)", file=sys.stderr)
    return output_path


def download_version(version_info, output_dir):
    """Download a specific version."""
    package = version_info['package']
    version = version_info['version']

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"[*] {package} {version}", file=sys.stderr)

    # Get download URL from version page
    download_url, ext = get_download_url(version_info["url"], package)
    if not download_url:
        print("[-] Could not find download URL", file=sys.stderr)
        return None

    ext = ext or "xapk"
    os.makedirs(output_dir, exist_ok=True)

    # Use package name as subdirectory
    package_dir = os.path.join(output_dir, package)
    os.makedirs(package_dir, exist_ok=True)

    filename = f"{package.split('.')[-1]}-{version}.{ext}"
    output_path = os.path.join(package_dir, filename)

    # Skip if exists
    if os.path.exists(output_path) and os.path.getsize(output_path) > 1024*1024:
        print(f"[*] Already exists: {output_path}", file=sys.stderr)
        return output_path

    time.sleep(1)
    return download_file(download_url, output_path)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Download APKs from APKPure")
    parser.add_argument("-p", "--package", type=str, default="com.whatsapp",
                       help="Package name (e.g., com.whatsapp)")
    parser.add_argument("-n", "--num-versions", type=int, default=1,
                       help="Number of versions to download")
    parser.add_argument("-o", "--output", default="./apks",
                       help="Output directory")
    parser.add_argument("-l", "--list-only", action="store_true",
                       help="List versions only (JSON output)")
    parser.add_argument("-v", "--version", type=str,
                       help="Specific version (or 'latest')")
    parser.add_argument("--json", action="store_true",
                       help="Output as JSON")
    args = parser.parse_args()

    # Get versions
    print(f"[*] Fetching versions for {args.package}...", file=sys.stderr)
    versions = get_versions(args.package, limit=max(args.num_versions + 10, 30))

    if not versions:
        if args.json:
            print(json.dumps({"error": f"No versions found for {args.package}", "versions": []}))
        else:
            print(f"[-] No versions found for {args.package}!")
        return 1

    # List only mode
    if args.list_only:
        if args.json:
            print(json.dumps({
                "package": args.package,
                "versions": [{"version": v["version"], "url": v["url"]} for v in versions]
            }))
        else:
            print(f"\n[+] Found {len(versions)} versions for {args.package}:")
            for i, v in enumerate(versions[:20]):
                print(f"  {i+1:2}. {v['version']}")
        return 0

    # Filter by version if specified
    if args.version:
        if args.version.lower() == "latest":
            versions = versions[:1]
        else:
            versions = [v for v in versions if args.version in v["version"]]
            if not versions:
                if args.json:
                    print(json.dumps({"error": f"Version {args.version} not found"}))
                else:
                    print(f"[-] Version {args.version} not found")
                return 1

    # Download
    print(f"\n[*] Downloading {min(args.num_versions, len(versions))} version(s)...", file=sys.stderr)

    downloaded = []
    for v in versions[:args.num_versions]:
        try:
            result = download_version(v, args.output)
            if result:
                downloaded.append({
                    "path": result,
                    "version": v["version"],
                    "package": v["package"]
                })
            time.sleep(2)
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)

    # Output result
    if args.json:
        print(json.dumps({
            "package": args.package,
            "downloaded": downloaded,
            "count": len(downloaded)
        }))
    else:
        print(f"\n{'='*60}")
        print(f"[+] Downloaded {len(downloaded)}/{args.num_versions}:")
        for d in downloaded:
            print(f"  - {d['path']}")

    return 0 if downloaded else 1


if __name__ == "__main__":
    exit(main())
