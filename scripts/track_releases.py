#!/usr/bin/env python3
"""
WhatsApp Release Tracker
Monitors APKMirror for new WhatsApp releases (beta and stable separately).

Usage:
    python track_releases.py --check          # Check for new releases
    python track_releases.py --list           # List recent releases
    python track_releases.py --watch          # Continuous monitoring
    python track_releases.py --webhook URL    # Send webhook on new release
"""

import requests
import xml.etree.ElementTree as ET
import re
import json
import time
import os
import sys
import argparse
from datetime import datetime
from pathlib import Path

# Source URLs - APKPure is more accessible than APKMirror
APKPURE_WHATSAPP = "https://apkpure.com/whatsapp-messenger/com.whatsapp/versions"
APKPURE_BASE = "https://apkpure.com"

# APKMirror URLs (may require special handling due to Cloudflare)
APKMIRROR_RSS = "https://www.apkmirror.com/apk/whatsapp-inc/whatsapp/feed/"
APKMIRROR_PAGE = "https://www.apkmirror.com/apk/whatsapp-inc/whatsapp/"

# State file to track seen versions
STATE_FILE = Path(__file__).parent / ".whatsapp_versions.json"

# User agent for requests
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
}

# Try to use cloudscraper if available (handles Cloudflare)
try:
    import cloudscraper
    session = cloudscraper.create_scraper(
        browser={'browser': 'chrome', 'platform': 'linux', 'desktop': True}
    )
except ImportError:
    session = requests.Session()
    session.headers.update(HEADERS)


def is_beta(version: str, title: str = "") -> bool:
    """
    Determine if a version is beta.

    Beta indicators:
    - "beta" in title/version
    - Version patch number >= 50 (heuristic)
    - Odd minor version number (sometimes)
    """
    version_lower = version.lower()
    title_lower = title.lower()

    # Explicit beta label
    if "beta" in version_lower or "beta" in title_lower:
        return True

    # Parse version: 2.XX.YY.ZZ
    match = re.match(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', version)
    if match:
        major, minor, patch, build = map(int, match.groups())
        # High build numbers often indicate beta
        # This is a heuristic and may not be 100% accurate
        if build >= 70:
            return True

    return False


def parse_version(version_str: str) -> tuple:
    """Parse version string to tuple for comparison."""
    # Remove 'beta' suffix for comparison
    clean = re.sub(r'\s*beta\s*', '', version_str, flags=re.IGNORECASE)
    match = re.match(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', clean)
    if match:
        return tuple(map(int, match.groups()))
    return (0, 0, 0, 0)


def fetch_rss_releases():
    """Fetch releases - try APKPure first, then APKMirror RSS."""
    # Try APKPure first (more accessible)
    releases = fetch_apkpure_releases()
    if releases:
        return releases

    # Fallback to APKMirror RSS
    try:
        resp = session.get(APKMIRROR_RSS, timeout=30)
        resp.raise_for_status()
        return parse_rss(resp.content)
    except Exception as e:
        print(f"[-] APKMirror RSS failed ({e})", file=sys.stderr)
        return []


def fetch_apkpure_releases():
    """Fetch releases from APKPure versions page."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("[-] BeautifulSoup not installed", file=sys.stderr)
        return []

    releases = []
    seen = set()

    try:
        resp = session.get(APKPURE_WHATSAPP, timeout=30)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        # Find version entries
        for item in soup.select('a[href*="/com.whatsapp/download"]'):
            href = item.get("href", "")
            text = item.get_text(strip=True)

            # Extract version
            version_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', href) or \
                           re.search(r'(\d+\.\d+\.\d+\.\d+)', text)
            if not version_match:
                continue

            version = version_match.group(1)
            if version in seen:
                continue
            seen.add(version)

            url = f"{APKPURE_BASE}{href}" if href.startswith("/") else href
            beta = is_beta(version, text)

            releases.append({
                "version": version,
                "title": f"WhatsApp Messenger {version}" + (" beta" if beta else ""),
                "url": url,
                "pub_date": "",
                "is_beta": beta,
                "channel": "beta" if beta else "stable",
                "arch": "universal",  # APKPure doesn't always show arch
                "package": "com.whatsapp",
                "source": "apkpure"
            })

        print(f"[*] Found {len(releases)} versions from APKPure", file=sys.stderr)

    except Exception as e:
        print(f"[-] APKPure fetch failed: {e}", file=sys.stderr)

    return releases


def parse_rss(content):
    """Parse RSS XML content."""
    releases = []

    try:
        root = ET.fromstring(content)

        for item in root.findall(".//item"):
            title_el = item.find("title")
            link_el = item.find("link")
            pub_date_el = item.find("pubDate")

            if title_el is None or link_el is None:
                continue

            title = title_el.text or ""
            link = link_el.text or ""
            pub_date = pub_date_el.text if pub_date_el is not None else ""

            release = parse_release_info(title, link, pub_date)
            if release:
                releases.append(release)

    except ET.ParseError as e:
        print(f"[-] Failed to parse RSS: {e}", file=sys.stderr)

    return releases


def fetch_html_releases():
    """Fallback: Fetch releases by parsing HTML page."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("[-] BeautifulSoup not installed, cannot parse HTML", file=sys.stderr)
        return []

    releases = []

    try:
        resp = session.get(WHATSAPP_PAGE, timeout=30)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

        # Find version links
        for widget in soup.select(".listWidget"):
            for item in widget.select(".appRow"):
                link_el = item.select_one("a.fontBlack")
                if not link_el:
                    continue

                title = link_el.get_text(strip=True)
                href = link_el.get("href", "")
                url = f"https://www.apkmirror.com{href}" if href.startswith("/") else href

                # Get date if available
                date_el = item.select_one(".dateyear_utc")
                pub_date = date_el.get("data-utcdate", "") if date_el else ""

                release = parse_release_info(title, url, pub_date)
                if release:
                    releases.append(release)

    except Exception as e:
        print(f"[-] HTML fetch failed: {e}", file=sys.stderr)

    return releases


def parse_release_info(title: str, url: str, pub_date: str = "") -> dict:
    """Parse release info from title and URL."""
    # Extract version from title
    # Format: "WhatsApp Messenger 2.26.16.73" or "2.26.16.73 beta"
    version_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', title)
    if not version_match:
        return None

    version = version_match.group(1)
    beta = is_beta(version, title)

    # Extract architecture
    arch = "universal"
    title_lower = title.lower()
    if "arm64-v8a" in title_lower or "arm64" in title_lower:
        arch = "arm64-v8a"
    elif "armeabi-v7a" in title_lower or "armeabi" in title_lower:
        arch = "armeabi-v7a"
    elif "x86_64" in title_lower:
        arch = "x86_64"
    elif "x86" in title_lower:
        arch = "x86"

    return {
        "version": version,
        "title": title,
        "url": url,
        "pub_date": pub_date,
        "is_beta": beta,
        "channel": "beta" if beta else "stable",
        "arch": arch,
        "package": "com.whatsapp"
    }


def load_state():
    """Load previously seen versions."""
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except:
            pass
    return {
        "last_check": None,
        "latest_beta": None,
        "latest_stable": None,
        "seen_versions": []
    }


def save_state(state):
    """Save state to file."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def get_latest_by_channel(releases):
    """Get latest release for each channel."""
    latest = {"beta": None, "stable": None}

    for release in releases:
        channel = release["channel"]
        if latest[channel] is None:
            latest[channel] = release
        else:
            if parse_version(release["version"]) > parse_version(latest[channel]["version"]):
                latest[channel] = release

    return latest


def check_new_releases(verbose=True):
    """Check for new releases since last check."""
    state = load_state()
    releases = fetch_rss_releases()

    if not releases:
        if verbose:
            print("[-] No releases found")
        return []

    seen = set(state.get("seen_versions", []))
    new_releases = []

    for release in releases:
        version_key = f"{release['version']}-{release['arch']}"
        if version_key not in seen:
            new_releases.append(release)
            seen.add(version_key)

    # Update state
    latest = get_latest_by_channel(releases)
    state["last_check"] = datetime.now().isoformat()
    state["seen_versions"] = list(seen)[-500:]  # Keep last 500

    if latest["beta"]:
        state["latest_beta"] = latest["beta"]["version"]
    if latest["stable"]:
        state["latest_stable"] = latest["stable"]["version"]

    save_state(state)

    if verbose:
        if new_releases:
            print(f"[+] Found {len(new_releases)} new release(s):")
            for r in new_releases:
                channel = "[BETA]" if r["is_beta"] else "[STABLE]"
                print(f"    {channel} {r['version']} ({r['arch']})")
        else:
            print("[*] No new releases since last check")

        print(f"\n[*] Latest versions:")
        print(f"    Stable: {state.get('latest_stable', 'unknown')}")
        print(f"    Beta:   {state.get('latest_beta', 'unknown')}")

    return new_releases


def list_releases(limit=20):
    """List recent releases."""
    releases = fetch_rss_releases()

    if not releases:
        print("[-] No releases found")
        return

    # Group by channel
    beta_releases = [r for r in releases if r["is_beta"]]
    stable_releases = [r for r in releases if not r["is_beta"]]

    print(f"\n{'='*60}")
    print("STABLE RELEASES")
    print('='*60)
    for r in stable_releases[:limit//2]:
        print(f"  {r['version']:20} {r['arch']:15} {r['pub_date'][:16]}")

    print(f"\n{'='*60}")
    print("BETA RELEASES")
    print('='*60)
    for r in beta_releases[:limit//2]:
        print(f"  {r['version']:20} {r['arch']:15} {r['pub_date'][:16]}")


def send_webhook(url: str, releases: list):
    """Send webhook notification for new releases."""
    if not releases:
        return

    for release in releases:
        payload = {
            "event": "new_release",
            "package": release["package"],
            "version": release["version"],
            "channel": release["channel"],
            "is_beta": release["is_beta"],
            "arch": release["arch"],
            "url": release["url"],
            "timestamp": datetime.now().isoformat()
        }

        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.ok:
                print(f"[+] Webhook sent for {release['version']}")
            else:
                print(f"[-] Webhook failed: {resp.status_code}")
        except Exception as e:
            print(f"[-] Webhook error: {e}")


def watch_releases(interval=300, webhook_url=None):
    """Continuously watch for new releases."""
    print(f"[*] Watching for new WhatsApp releases (checking every {interval}s)")
    print("[*] Press Ctrl+C to stop\n")

    while True:
        try:
            new_releases = check_new_releases(verbose=True)

            if new_releases and webhook_url:
                send_webhook(webhook_url, new_releases)

            print(f"\n[*] Next check in {interval}s...\n")
            time.sleep(interval)

        except KeyboardInterrupt:
            print("\n[*] Stopped")
            break
        except Exception as e:
            print(f"[-] Error: {e}")
            time.sleep(60)


def output_json(releases):
    """Output releases as JSON."""
    latest = get_latest_by_channel(releases)

    output = {
        "timestamp": datetime.now().isoformat(),
        "latest": {
            "stable": latest["stable"],
            "beta": latest["beta"]
        },
        "recent_releases": releases[:20]
    }

    print(json.dumps(output, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Track WhatsApp releases")
    parser.add_argument("--check", action="store_true",
                       help="Check for new releases")
    parser.add_argument("--list", action="store_true",
                       help="List recent releases")
    parser.add_argument("--watch", action="store_true",
                       help="Continuously watch for releases")
    parser.add_argument("--interval", type=int, default=300,
                       help="Watch interval in seconds (default: 300)")
    parser.add_argument("--webhook", type=str,
                       help="Webhook URL for notifications")
    parser.add_argument("--json", action="store_true",
                       help="Output as JSON")

    args = parser.parse_args()

    if args.watch:
        watch_releases(interval=args.interval, webhook_url=args.webhook)
    elif args.list:
        if args.json:
            releases = fetch_rss_releases()
            output_json(releases)
        else:
            list_releases()
    elif args.check:
        new_releases = check_new_releases(verbose=not args.json)
        if args.json:
            print(json.dumps({
                "new_releases": new_releases,
                "count": len(new_releases)
            }, indent=2))
    else:
        # Default: show status
        state = load_state()
        releases = fetch_rss_releases()
        latest = get_latest_by_channel(releases)

        print("\nWhatsApp Release Status")
        print("=" * 40)
        print(f"Last check: {state.get('last_check', 'never')}")
        print(f"\nLatest Stable: {latest['stable']['version'] if latest['stable'] else 'unknown'}")
        print(f"Latest Beta:   {latest['beta']['version'] if latest['beta'] else 'unknown'}")
        print(f"\nTotal releases in feed: {len(releases)}")
        print(f"  - Stable: {len([r for r in releases if not r['is_beta']])}")
        print(f"  - Beta:   {len([r for r in releases if r['is_beta']])}")


if __name__ == "__main__":
    main()
