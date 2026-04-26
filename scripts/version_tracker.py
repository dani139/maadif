#!/usr/bin/env python3
"""
Version tracker for Android apps.
Scrapes APKPure and APKMirror to discover app versions.
"""

import cloudscraper
from bs4 import BeautifulSoup
import re
import json
import sqlite3
import time
import hashlib
from datetime import datetime
from urllib.parse import urljoin, quote
from pathlib import Path
import sys
import argparse

# Known app slugs for popular apps
APP_SLUGS = {
    "com.whatsapp": {
        "apkpure": "whatsapp-messenger",
        "apkmirror": "whatsapp-inc/whatsapp-messenger",
        "uptodown": "whatsapp-messenger",
        "name": "WhatsApp"
    },
    "org.telegram.messenger": {
        "apkpure": "telegram",
        "apkmirror": "telegram-fz-llc/telegram",
        "uptodown": "telegram",
        "name": "Telegram"
    },
    "org.telegram.messenger.beta": {
        "apkpure": "telegram-beta",
        "uptodown": "telegram-beta",
        "name": "Telegram Beta",
        "is_beta": True
    },
    "com.instagram.android": {
        "apkpure": "instagram",
        "apkmirror": "instagram/instagram",
        "uptodown": "instagram",
        "name": "Instagram"
    },
    "com.facebook.katana": {
        "apkpure": "facebook",
        "apkmirror": "facebook-2/facebook",
        "uptodown": "facebook",
        "name": "Facebook"
    }
}

# Create scraper sessions - different configs for different sites
apkpure_session = cloudscraper.create_scraper(
    browser={'browser': 'chrome', 'platform': 'linux', 'desktop': True}
)

# APKMirror needs cloudscraper with specific settings
apkmirror_session = cloudscraper.create_scraper(
    browser={
        'browser': 'chrome',
        'platform': 'windows',
        'desktop': True,
        'mobile': False
    },
    delay=5  # Add delay for Cloudflare challenges
)


def get_soup(url, retries=3, site=None):
    """Fetch URL and return BeautifulSoup object."""
    # Choose session based on site
    if site == "apkmirror" or "apkmirror.com" in url:
        sess = apkmirror_session
    else:
        sess = apkpure_session

    for attempt in range(retries):
        try:
            print(f"[*] Fetching: {url}", file=sys.stderr)
            resp = sess.get(url, timeout=30)
            resp.raise_for_status()
            return BeautifulSoup(resp.text, "html.parser")
        except Exception as e:
            print(f"[-] Attempt {attempt+1} failed: {e}", file=sys.stderr)
            if attempt < retries - 1:
                time.sleep(2 + attempt)  # Increasing backoff
    return None


def is_beta_version(version: str, source_url: str = "", package: str = "") -> bool:
    """Detect if a version is beta."""
    # Package-level beta detection (e.g., org.telegram.messenger.beta)
    if package in APP_SLUGS and APP_SLUGS[package].get("is_beta"):
        return True

    # URL-based detection
    if "beta" in source_url.lower():
        return True

    # Version string contains beta
    if "beta" in version.lower():
        return True

    # WhatsApp pattern: versions with odd 3rd number are beta
    # e.g., 2.26.15.x = beta, 2.26.16.x = stable
    if package == "com.whatsapp":
        parts = version.split(".")
        if len(parts) >= 3:
            try:
                third = int(parts[2])
                if third % 2 == 1:  # odd = beta
                    return True
            except ValueError:
                pass

    return False


def extract_arch(text: str) -> str:
    """Extract architecture from text."""
    text_lower = text.lower()
    if "arm64" in text_lower or "arm64-v8a" in text_lower:
        return "arm64-v8a"
    elif "armeabi" in text_lower or "arm-v7a" in text_lower:
        return "armeabi-v7a"
    elif "x86_64" in text_lower:
        return "x86_64"
    elif "x86" in text_lower:
        return "x86"
    return "universal"


# =============================================================================
# APKPure Scraper
# =============================================================================

def scrape_apkpure_versions(package: str, limit: int = 50) -> list:
    """Scrape versions from APKPure."""
    versions = []

    # Get app slug
    if package in APP_SLUGS:
        slug = APP_SLUGS[package]["apkpure"]
    else:
        # Try to find slug via search
        slug = search_apkpure_slug(package)
        if not slug:
            print(f"[-] Could not find APKPure slug for {package}", file=sys.stderr)
            return versions

    # Fetch versions page
    url = f"https://apkpure.com/{slug}/{package}/versions"
    soup = get_soup(url)
    if not soup:
        return versions

    seen = set()

    # Find version links
    for a in soup.select(f'a[href*="{package}/download"]'):
        href = a.get("href", "")
        text = a.get_text(strip=True)

        # Extract version
        version_match = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', href) or \
                       re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', text)
        if not version_match:
            continue

        version = version_match.group(1)
        if version in seen:
            continue
        seen.add(version)

        # Get details
        full_url = urljoin("https://apkpure.com", href)
        arch = extract_arch(text)
        is_beta = is_beta_version(version, full_url, package)

        # Try to get file size and date from parent elements
        size = None
        release_date = None
        parent = a.find_parent("div", class_=True)
        if not parent:
            parent = a.find_parent("li")
        if not parent:
            parent = a.find_parent("div")

        if parent:
            parent_text = parent.get_text()

            # Extract size
            size_match = re.search(r'(\d+(?:\.\d+)?)\s*(MB|KB|GB)', parent_text)
            if size_match:
                size_val = float(size_match.group(1))
                unit = size_match.group(2)
                if unit == "GB":
                    size = int(size_val * 1024 * 1024 * 1024)
                elif unit == "MB":
                    size = int(size_val * 1024 * 1024)
                elif unit == "KB":
                    size = int(size_val * 1024)

            # Extract date - APKPure format: "Apr 25, 2026" or "2026-04-25"
            date_patterns = [
                (r'([A-Z][a-z]{2}\s+\d{1,2},\s+\d{4})', "%b %d, %Y"),  # Apr 25, 2026
                (r'(\d{4}-\d{2}-\d{2})', "%Y-%m-%d"),  # 2026-04-25
                (r'(\d{1,2}/\d{1,2}/\d{4})', "%m/%d/%Y"),  # 04/25/2026
                (r'(\d{1,2}\s+[A-Z][a-z]{2}\s+\d{4})', "%d %b %Y"),  # 25 Apr 2026
            ]
            for pattern, fmt in date_patterns:
                date_match = re.search(pattern, parent_text)
                if date_match:
                    try:
                        dt = datetime.strptime(date_match.group(1), fmt)
                        release_date = int(dt.timestamp())
                        break
                    except ValueError:
                        pass

        versions.append({
            "package": package,
            "version": version,
            "channel": "beta" if is_beta else "stable",
            "arch": arch,
            "source": "apkpure",
            "source_url": full_url,
            "file_size": size,
            "release_date": release_date,
            "first_seen": int(time.time())
        })

        if len(versions) >= limit:
            break

    print(f"[+] APKPure: Found {len(versions)} versions for {package}", file=sys.stderr)
    return versions


def search_apkpure_slug(package: str) -> str:
    """Search APKPure for app slug."""
    search_url = f"https://apkpure.com/search?q={quote(package)}"
    soup = get_soup(search_url)
    if not soup:
        return None

    for a in soup.select('a[href]'):
        href = a.get("href", "")
        if package in href:
            match = re.search(r'/([^/]+)/' + re.escape(package), href)
            if match:
                return match.group(1)
    return None


# =============================================================================
# APKMirror Scraper
# =============================================================================

def scrape_apkmirror_versions(package: str, limit: int = 50) -> list:
    """Scrape versions from APKMirror."""
    versions = []

    # Get app slug
    if package in APP_SLUGS:
        slug = APP_SLUGS[package]["apkmirror"]
    else:
        # Try search
        slug = search_apkmirror_slug(package)
        if not slug:
            print(f"[-] Could not find APKMirror slug for {package}", file=sys.stderr)
            return versions

    # Fetch main app page (has version list)
    url = f"https://www.apkmirror.com/apk/{slug}/"
    soup = get_soup(url)
    if not soup:
        return versions

    seen = set()

    # Find version entries - APKMirror uses specific classes
    # Look for links that contain version numbers
    for item in soup.select('.appRow, .listWidget'):
        # Find version links within this item
        for a in item.select('a.fontBlack'):
            href = a.get("href", "")
            text = a.get_text(strip=True)

            # Extract version from text or href
            version_match = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', text) or \
                           re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', href)
            if not version_match:
                continue

            version = version_match.group(1)
            key = f"{version}"
            if key in seen:
                continue
            seen.add(key)

            full_url = urljoin("https://www.apkmirror.com", href)
            is_beta = is_beta_version(version, full_url, package) or "beta" in text.lower()

            # Check for badge indicators
            badge = item.select_one('.colorLightBlack, .versionBadge')
            if badge and "beta" in badge.get_text().lower():
                is_beta = True

            versions.append({
                "package": package,
                "version": version,
                "channel": "beta" if is_beta else "stable",
                "arch": "universal",  # APKMirror lists variants separately
                "source": "apkmirror",
                "source_url": full_url,
                "file_size": None,
                "first_seen": int(time.time())
            })

            if len(versions) >= limit:
                break

        if len(versions) >= limit:
            break

    # Also try the "All versions" page
    if len(versions) < limit:
        all_versions_url = f"https://www.apkmirror.com/uploads/?appcategory={slug.split('/')[-1]}"
        soup2 = get_soup(all_versions_url)
        if soup2:
            for a in soup2.select('a.fontBlack'):
                href = a.get("href", "")
                text = a.get_text(strip=True)

                version_match = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', text)
                if not version_match:
                    continue

                version = version_match.group(1)
                key = f"{version}"
                if key in seen:
                    continue
                seen.add(key)

                full_url = urljoin("https://www.apkmirror.com", href)
                is_beta = is_beta_version(version, full_url, package) or "beta" in text.lower()

                versions.append({
                    "package": package,
                    "version": version,
                    "channel": "beta" if is_beta else "stable",
                    "arch": "universal",
                    "source": "apkmirror",
                    "source_url": full_url,
                    "file_size": None,
                    "first_seen": int(time.time())
                })

                if len(versions) >= limit:
                    break

    print(f"[+] APKMirror: Found {len(versions)} versions for {package}", file=sys.stderr)
    return versions


def search_apkmirror_slug(package: str) -> str:
    """Search APKMirror for app slug."""
    search_url = f"https://www.apkmirror.com/?post_type=app_release&searchtype=app&s={quote(package)}"
    soup = get_soup(search_url)
    if not soup:
        return None

    # Find first result that matches package
    for a in soup.select('a[href*="/apk/"]'):
        href = a.get("href", "")
        # APKMirror URLs are like /apk/publisher/app-name/
        match = re.search(r'/apk/([^/]+/[^/]+)/', href)
        if match:
            return match.group(1)
    return None


# =============================================================================
# Uptodown Scraper (more accessible than APKMirror)
# =============================================================================

def scrape_uptodown_versions(package: str, limit: int = 50) -> list:
    """Scrape versions from Uptodown."""
    versions = []

    # Get app slug
    if package in APP_SLUGS and "uptodown" in APP_SLUGS[package]:
        slug = APP_SLUGS[package]["uptodown"]
    else:
        print(f"[-] No Uptodown slug for {package}", file=sys.stderr)
        return versions

    # Fetch versions page
    url = f"https://{slug}.en.uptodown.com/android/versions"
    soup = get_soup(url)
    if not soup:
        return versions

    seen = set()
    base_url = f"https://{slug}.en.uptodown.com"

    # Find version entries - they're in divs with data-url and contain version spans
    for div in soup.select('div[data-url]'):
        # Find version span within this div
        version_span = div.select_one('.version')
        if not version_span:
            # Try to find version in text
            text = div.get_text(strip=True)
            version_match = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', text)
            if not version_match:
                continue
            version = version_match.group(1)
        else:
            version = version_span.get_text(strip=True)

        if version in seen:
            continue
        seen.add(version)

        data_url = div.get('data-url', '')
        full_url = data_url if data_url.startswith('http') else f"{base_url}/android"
        is_beta = is_beta_version(version, full_url, package)

        # Try to get date from text - multiple formats
        release_date = None
        text = div.get_text()
        date_patterns = [
            (r'([A-Z][a-z]{2}\s+\d{1,2},\s+\d{4})', "%b %d, %Y"),  # Apr 25, 2026
            (r'(\d{4}-\d{2}-\d{2})', "%Y-%m-%d"),  # 2026-04-25
            (r'(\d{1,2}/\d{1,2}/\d{2,4})', "%m/%d/%Y"),  # 04/25/2026
            (r'(\d{1,2}\s+[A-Z][a-z]{2,}\s+\d{4})', "%d %B %Y"),  # 25 April 2026
            (r'(\d{1,2}\s+[A-Z][a-z]{2}\s+\d{4})', "%d %b %Y"),  # 25 Apr 2026
        ]
        for pattern, fmt in date_patterns:
            date_match = re.search(pattern, text)
            if date_match:
                try:
                    date_str = date_match.group(1)
                    # Handle 2-digit years
                    if fmt == "%m/%d/%Y" and len(date_str.split('/')[-1]) == 2:
                        fmt = "%m/%d/%y"
                    dt = datetime.strptime(date_str, fmt)
                    release_date = int(dt.timestamp())
                    break
                except:
                    pass

        versions.append({
            "package": package,
            "version": version,
            "channel": "beta" if is_beta else "stable",
            "arch": "universal",
            "source": "uptodown",
            "source_url": full_url,
            "file_size": None,
            "release_date": release_date,
            "first_seen": int(time.time())
        })

        if len(versions) >= limit:
            break

    print(f"[+] Uptodown: Found {len(versions)} versions for {package}", file=sys.stderr)
    return versions


# =============================================================================
# Combined Tracker
# =============================================================================

def track_package(package: str, sources: list = None) -> list:
    """Track versions from all sources for a package."""
    if sources is None:
        sources = ["apkpure", "uptodown"]  # Default to working sources

    all_versions = []

    if "apkpure" in sources:
        try:
            versions = scrape_apkpure_versions(package)
            all_versions.extend(versions)
        except Exception as e:
            print(f"[-] APKPure error: {e}", file=sys.stderr)

    time.sleep(1)  # Rate limiting

    if "uptodown" in sources:
        try:
            versions = scrape_uptodown_versions(package)
            all_versions.extend(versions)
        except Exception as e:
            print(f"[-] Uptodown error: {e}", file=sys.stderr)

    time.sleep(1)

    if "apkmirror" in sources:
        try:
            versions = scrape_apkmirror_versions(package)
            all_versions.extend(versions)
        except Exception as e:
            print(f"[-] APKMirror error: {e}", file=sys.stderr)

    # Deduplicate by version+source
    seen = set()
    unique = []
    for v in all_versions:
        key = (v["version"], v["source"])
        if key not in seen:
            seen.add(key)
            unique.append(v)

    # Sort by version (newest first)
    unique.sort(key=lambda x: [int(p) for p in re.findall(r'\d+', x["version"])], reverse=True)

    return unique


# =============================================================================
# Database Operations
# =============================================================================

def init_tracking_db(db_path: str):
    """Initialize the tracking database."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS tracked_apps (
            id INTEGER PRIMARY KEY,
            package_name TEXT UNIQUE,
            display_name TEXT,
            added_at INTEGER,
            last_checked_at INTEGER,
            check_interval_hours INTEGER DEFAULT 6
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS versions (
            id INTEGER PRIMARY KEY,
            package_name TEXT,
            version_name TEXT,
            version_code INTEGER,
            channel TEXT,
            arch TEXT,
            min_sdk INTEGER,
            file_size INTEGER,
            sha256 TEXT,
            source TEXT,
            source_url TEXT,
            release_date INTEGER,
            first_seen_at INTEGER,
            downloaded_at INTEGER,
            analyzed_at INTEGER,
            analysis_db_path TEXT,
            UNIQUE(package_name, version_name, arch, source)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS check_history (
            id INTEGER PRIMARY KEY,
            package_name TEXT,
            source TEXT,
            checked_at INTEGER,
            versions_found INTEGER,
            new_versions INTEGER,
            error TEXT
        )
    """)

    c.execute("CREATE INDEX IF NOT EXISTS idx_versions_pkg ON versions(package_name)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_versions_channel ON versions(package_name, channel)")

    conn.commit()
    conn.close()
    print(f"[+] Initialized tracking database: {db_path}", file=sys.stderr)


def save_versions(db_path: str, versions: list) -> int:
    """Save versions to database. Returns count of new versions."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    new_count = 0
    for v in versions:
        try:
            c.execute("""
                INSERT OR IGNORE INTO versions
                (package_name, version_name, channel, arch, source, source_url, file_size, release_date, first_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                v["package"],
                v["version"],
                v["channel"],
                v["arch"],
                v["source"],
                v["source_url"],
                v["file_size"],
                v.get("release_date"),
                v["first_seen"]
            ))
            if c.rowcount > 0:
                new_count += 1
        except Exception as e:
            print(f"[-] Error saving version: {e}", file=sys.stderr)

    conn.commit()
    conn.close()
    return new_count


def get_versions(db_path: str, package: str, channel: str = None, limit: int = 50) -> list:
    """Get versions from database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    if channel and channel != "all":
        c.execute("""
            SELECT * FROM versions
            WHERE package_name = ? AND channel = ?
            ORDER BY first_seen_at DESC LIMIT ?
        """, (package, channel, limit))
    else:
        c.execute("""
            SELECT * FROM versions
            WHERE package_name = ?
            ORDER BY first_seen_at DESC LIMIT ?
        """, (package, limit))

    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Track Android app versions")
    parser.add_argument("-p", "--package", type=str, help="Package name to track")
    parser.add_argument("-d", "--db", type=str, default="./data/tracking.db", help="Database path")
    parser.add_argument("--init", action="store_true", help="Initialize database")
    parser.add_argument("--list", action="store_true", help="List versions from database")
    parser.add_argument("--scrape", action="store_true", help="Scrape and save new versions")
    parser.add_argument("--source", type=str, choices=["apkpure", "apkmirror", "uptodown", "all"], default="all")
    parser.add_argument("--channel", type=str, choices=["stable", "beta", "all"], default="all")
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    # Ensure data directory exists
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)

    if args.init:
        init_tracking_db(args.db)
        return 0

    if not args.package:
        parser.error("--package is required")

    # Initialize DB if doesn't exist
    if not Path(args.db).exists():
        init_tracking_db(args.db)

    if args.scrape:
        # Scrape versions
        sources = ["apkpure", "uptodown"] if args.source == "all" else [args.source]
        versions = track_package(args.package, sources)

        if versions:
            new_count = save_versions(args.db, versions)
            print(f"\n[+] Found {len(versions)} versions, {new_count} new", file=sys.stderr)

        if args.json:
            print(json.dumps({"package": args.package, "versions": versions, "new_count": new_count}))
        else:
            print(f"\n{'='*60}")
            print(f"Versions for {args.package}:")
            print(f"{'='*60}")
            for v in versions[:args.limit]:
                beta_tag = " [BETA]" if v["channel"] == "beta" else ""
                print(f"  {v['version']:20} {v['source']:12} {v['arch']:12}{beta_tag}")

    elif args.list:
        # List from database
        versions = get_versions(args.db, args.package, args.channel, args.limit)

        if args.json:
            print(json.dumps({"package": args.package, "versions": versions}))
        else:
            print(f"\n{'='*60}")
            print(f"Tracked versions for {args.package}:")
            print(f"{'='*60}")
            for v in versions:
                beta_tag = " [BETA]" if v["channel"] == "beta" else ""
                analyzed = " [ANALYZED]" if v.get("analyzed_at") else ""
                print(f"  {v['version_name']:20} {v['source']:12} {v['arch']:12}{beta_tag}{analyzed}")

    else:
        # Just scrape and print (don't save)
        sources = ["apkpure", "uptodown"] if args.source == "all" else [args.source]
        versions = track_package(args.package, sources)

        if args.json:
            print(json.dumps({"package": args.package, "versions": versions}))
        else:
            print(f"\n{'='*60}")
            print(f"Versions for {args.package}:")
            print(f"{'='*60}")
            for v in versions[:args.limit]:
                beta_tag = " [BETA]" if v["channel"] == "beta" else ""
                print(f"  {v['version']:20} {v['source']:12} {v['arch']:12}{beta_tag}")

    return 0


if __name__ == "__main__":
    exit(main())
