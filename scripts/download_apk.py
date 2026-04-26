#!/usr/bin/env python3
"""
APK downloader using BeautifulSoup + cloudscraper.
Downloads APK versions from APKPure or Uptodown.
"""

import cloudscraper
from bs4 import BeautifulSoup
import re
import os
import sys
import json
import time
from urllib.parse import urljoin, quote

# Use cloudscraper to bypass Cloudflare
session = cloudscraper.create_scraper(
    browser={'browser': 'chrome', 'platform': 'linux', 'desktop': True}
)

# App slug mappings for both sources
APP_SLUGS = {
    "com.whatsapp": {
        "apkpure": "whatsapp-messenger",
        "uptodown": "whatsapp-messenger",
    },
    "org.telegram.messenger": {
        "apkpure": "telegram",
        "uptodown": "telegram",
    },
    "org.telegram.messenger.beta": {
        "apkpure": "telegram-beta",
        "uptodown": "telegram-beta",
    },
    "com.instagram.android": {
        "apkpure": "instagram",
        "uptodown": "instagram",
    },
    "com.facebook.katana": {
        "apkpure": "facebook",
        "uptodown": "facebook-android",
    },
}


def get_soup(url):
    """Fetch URL and return BeautifulSoup object."""
    print(f"[*] Fetching: {url}", file=sys.stderr)
    resp = session.get(url, timeout=30)
    resp.raise_for_status()
    return BeautifulSoup(resp.text, "html.parser")


# =============================================================================
# APKPure Functions
# =============================================================================

def apkpure_get_versions(package_name, limit=30):
    """Get list of available versions from APKPure."""
    slugs = APP_SLUGS.get(package_name, {})
    app_slug = slugs.get("apkpure")

    if not app_slug:
        # Try to search for it
        search_url = f"https://apkpure.com/search?q={quote(package_name)}"
        soup = get_soup(search_url)
        for a in soup.select('a[href]'):
            href = a.get("href", "")
            if package_name in href:
                match = re.search(r'/([^/]+)/' + re.escape(package_name), href)
                if match:
                    app_slug = match.group(1)
                    break

    if not app_slug:
        print(f"[-] Could not find APKPure slug for: {package_name}", file=sys.stderr)
        return []

    versions_url = f"https://apkpure.com/{app_slug}/{package_name}/versions"
    soup = get_soup(versions_url)
    versions = []
    seen = set()

    for a in soup.select(f'a[href*="{package_name}/download"]'):
        href = a.get("href", "")
        text = a.get_text(strip=True)
        version_match = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', href) or re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', text)
        if version_match:
            version = version_match.group(1)
            if version in seen:
                continue
            seen.add(version)
            versions.append({
                "version": version,
                "url": urljoin("https://apkpure.com", href),
                "package": package_name,
                "source": "apkpure"
            })
            if len(versions) >= limit:
                break

    return versions


def apkpure_get_download_url(version_url, package_name):
    """Get the direct download URL from APKPure version page."""
    soup = get_soup(version_url)

    # Look for direct download links (d.apkpure.com)
    for a in soup.select('a[href*="d.apkpure.com"]'):
        href = a.get("href", "")
        text = a.get_text(strip=True).lower()
        if "arm64" in href or "arm64" in text:
            return href, "xapk"

    for a in soup.select('a[href*="d.apkpure.com"]'):
        href = a.get("href", "")
        if "/XAPK/" in href:
            return href, "xapk"
        elif "/APK/" in href:
            return href, "apk"

    body = soup.select_one("body[data-dt-apkid]")
    if body:
        version_code = body.get("data-version-code")
        if version_code:
            url = f"https://d.apkpure.com/b/XAPK/{package_name}?versionCode={version_code}&nc=arm64-v8a&sv=21"
            return url, "xapk"

    return None, None


# =============================================================================
# Uptodown Functions
# =============================================================================

def uptodown_get_versions(package_name, limit=30):
    """Get list of available versions from Uptodown."""
    slugs = APP_SLUGS.get(package_name, {})
    app_slug = slugs.get("uptodown")

    if not app_slug:
        # Try deriving from package name
        app_slug = package_name.split('.')[-1]

    base_url = f"https://{app_slug}.en.uptodown.com/android"
    versions_url = f"{base_url}/versions"

    try:
        soup = get_soup(versions_url)
    except Exception as e:
        print(f"[-] Could not fetch Uptodown versions: {e}", file=sys.stderr)
        return []

    versions = []
    seen = set()

    # Find version divs with version-id
    for div in soup.select('div[data-version-id]'):
        version_id = div.get('data-version-id', '')
        version_span = div.select_one('.version')
        if version_span and version_id:
            version = version_span.get_text(strip=True)
            if version and version not in seen:
                seen.add(version)
                # Construct version-specific download URL
                download_url = f"{base_url}/download/{version_id}"
                versions.append({
                    "version": version,
                    "url": download_url,
                    "package": package_name,
                    "source": "uptodown",
                    "version_id": version_id
                })
                if len(versions) >= limit:
                    break

    # Fallback: divs with data-url
    if not versions:
        for div in soup.select('div[data-url]'):
            url = div.get('data-url', '')
            version_span = div.select_one('.version')
            if version_span:
                version = version_span.get_text(strip=True)
                if version and version not in seen:
                    seen.add(version)
                    versions.append({
                        "version": version,
                        "url": url if url.startswith('http') else f"https:{url}",
                        "package": package_name,
                        "source": "uptodown"
                    })
                    if len(versions) >= limit:
                        break

    return versions


def uptodown_get_download_url(version_url, package_name):
    """Get the direct download URL from Uptodown version page."""
    # Uptodown has a two-step process:
    # 1. Go to /android/download or /android/download/{version_id} page
    # 2. Find button#detail-download-button with data-url
    # 3. Construct URL: https://dw.uptodown.net/dwn/{data_url}

    # Check if URL already contains /download
    if '/download' in version_url:
        download_url = version_url
    else:
        download_url = version_url.rstrip('/') + '/download'

    try:
        soup = get_soup(download_url)
    except Exception as e:
        print(f"[-] Could not fetch Uptodown page: {e}", file=sys.stderr)
        return None, None

    # Look for download button with data-url
    download_btn = soup.select_one('button#detail-download-button')
    if download_btn:
        data_url = download_btn.get('data-url')
        if data_url and not data_url.startswith('http'):
            # Construct the download URL
            final_url = f"https://dw.uptodown.net/dwn/{data_url}"
            print(f"[*] Found Uptodown download URL", file=sys.stderr)
            return final_url, "apk"

    # Fallback: Try finding direct APK link
    for a in soup.select('a[href$=".apk"], a[href*="dw.uptodown"]'):
        href = a.get('href', '')
        if href:
            return href, "apk"

    return None, None


# =============================================================================
# Common Functions
# =============================================================================

def download_file(url, output_path):
    """Download file from URL with progress."""
    print(f"[*] Downloading: {url[:80]}...", file=sys.stderr)

    resp = session.get(url, stream=True, timeout=300, allow_redirects=True)
    resp.raise_for_status()

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
    source = version_info.get('source', 'apkpure')

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"[*] {package} {version} (from {source})", file=sys.stderr)

    # Get download URL based on source
    if source == 'uptodown':
        download_url, ext = uptodown_get_download_url(version_info["url"], package)
    else:
        download_url, ext = apkpure_get_download_url(version_info["url"], package)

    if not download_url:
        print("[-] Could not find download URL", file=sys.stderr)
        return None

    ext = ext or "apk"
    os.makedirs(output_dir, exist_ok=True)

    package_dir = os.path.join(output_dir, package)
    os.makedirs(package_dir, exist_ok=True)

    filename = f"{package.split('.')[-1]}-{version}.{ext}"
    output_path = os.path.join(package_dir, filename)

    if os.path.exists(output_path) and os.path.getsize(output_path) > 1024*1024:
        print(f"[*] Already exists: {output_path}", file=sys.stderr)
        return output_path

    time.sleep(1)
    return download_file(download_url, output_path)


def get_versions(package_name, source='all', limit=30):
    """Get versions from specified source(s)."""
    versions = []

    if source in ('all', 'apkpure'):
        try:
            versions.extend(apkpure_get_versions(package_name, limit))
        except Exception as e:
            print(f"[-] APKPure error: {e}", file=sys.stderr)

    if source in ('all', 'uptodown'):
        try:
            versions.extend(uptodown_get_versions(package_name, limit))
        except Exception as e:
            print(f"[-] Uptodown error: {e}", file=sys.stderr)

    return versions


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Download APKs from APKPure or Uptodown")
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
    parser.add_argument("-s", "--source", type=str, default="all",
                       choices=["apkpure", "uptodown", "all"],
                       help="Source to download from")
    parser.add_argument("--json", action="store_true",
                       help="Output as JSON")
    args = parser.parse_args()

    print(f"[*] Fetching versions for {args.package} from {args.source}...", file=sys.stderr)
    versions = get_versions(args.package, args.source, limit=max(args.num_versions + 10, 30))

    if not versions:
        if args.json:
            print(json.dumps({"error": f"No versions found for {args.package}", "versions": []}))
        else:
            print(f"[-] No versions found for {args.package}!")
        return 1

    if args.list_only:
        if args.json:
            print(json.dumps({
                "package": args.package,
                "versions": [{"version": v["version"], "url": v["url"], "source": v.get("source")} for v in versions]
            }))
        else:
            print(f"\n[+] Found {len(versions)} versions for {args.package}:")
            for i, v in enumerate(versions[:20]):
                print(f"  {i+1:2}. {v['version']} ({v.get('source', 'unknown')})")
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

    print(f"\n[*] Downloading {min(args.num_versions, len(versions))} version(s)...", file=sys.stderr)

    downloaded = []
    for v in versions[:args.num_versions]:
        try:
            result = download_version(v, args.output)
            if result:
                downloaded.append({
                    "path": result,
                    "version": v["version"],
                    "package": v["package"],
                    "source": v.get("source")
                })
            time.sleep(2)
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)

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
