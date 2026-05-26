"""TraceZ Backend — Threat Intelligence Feed Sync Service."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy.orm import Session
import httpx
from app.database import BlocklistEntry, ThreatFeed

async def fetch_and_sync_feeds(db: Session) -> dict:
    """
    Fetch active threat feeds, compile, and sync with BlocklistEntry table.
    Falls back to parsing local shared JSON files if network requests fail.
    """
    feeds = db.query(ThreatFeed).filter(ThreatFeed.is_active == True).all()
    results = {}
    
    all_domains = set()
    
    # 1. Try fetching online feeds
    async with httpx.AsyncClient(timeout=10.0) as client:
        for feed in feeds:
            try:
                # In real prod we fetch feed.url. For this MVP, we parse or simulate
                resp = await client.get(feed.url)
                if resp.status_code == 200:
                    domains_added = 0
                    if feed.name == "PhishTank":
                        data = resp.json()
                        # Extract domains from phishtank JSON
                        for item in data[:500]:  # Cap to first 500 for MVP speed
                            url = item.get("url", "")
                            from urllib.parse import urlparse
                            domain = urlparse(url).netloc
                            if domain:
                                # Strip port
                                if ":" in domain:
                                    domain = domain.split(":")[0]
                                all_domains.add(domain)
                                domains_added += 1
                    
                    feed.last_sync_status = "success"
                    feed.last_sync_time = datetime.now(timezone.utc)
                    results[feed.name] = f"Synced {domains_added} domains from live API."
                else:
                    raise Exception(f"HTTP {resp.status_code}")
            except Exception as e:
                # Feed fetch failed (could be rate-limited, offline, etc.)
                feed.last_sync_status = f"failed: {str(e)}"
                feed.last_sync_time = datetime.now(timezone.utc)
                results[feed.name] = f"Sync failed. Falling back to local blocklist."

    # 2. Local fallback sync if no domains were loaded online
    # This reads shared/blocklists/phishing-domains.json
    local_path = Path(__file__).resolve().parent.parent.parent.parent / "shared" / "blocklists" / "phishing-domains.json"
    if local_path.exists():
        try:
            with open(local_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for domain in data.get("domains", []):
                    all_domains.add(domain.strip().lower())
            results["local_fallback"] = f"Seeded {len(data.get('domains', []))} domains from local blocklist file."
        except Exception as le:
            results["local_fallback_error"] = str(le)
            
    # 3. Write loaded domains to BlocklistEntry DB table
    if all_domains:
        # Get existing domains to avoid unique constraint violations
        existing_entries = db.query(BlocklistEntry.domain).all()
        existing_domains = {e[0] for e in existing_entries}
        
        new_entries = []
        for domain in all_domains:
            if domain not in existing_domains:
                new_entries.append(BlocklistEntry(
                    domain=domain,
                    category="phishing",
                    source="feed"
                ))
                
        if new_entries:
            db.bulk_save_objects(new_entries)
            db.commit()
            
    db.commit()
    return {
        "status": "completed",
        "total_active_blocklist_size": db.query(BlocklistEntry).count(),
        "feed_results": results
    }

def get_blocklist_version_hash(db: Session) -> str:
    """
    Generate a SHA256 version hash based on the domains currently in the blocklist.
    This allows extensions to quickly check if they need an update.
    """
    # Query all domains sorted
    domains = [d[0] for d in db.query(BlocklistEntry.domain).order_by(BlocklistEntry.domain).all()]
    if not domains:
        return hashlib.sha256(b"empty").hexdigest()
        
    domain_string = ",".join(domains)
    return hashlib.sha256(domain_string.encode("utf-8")).hexdigest()

def compile_blocklist_json(db: Session) -> dict:
    """Compile all active blocklist domains into structured JSON payload for extension sync."""
    entries = db.query(BlocklistEntry).all()
    domains = [entry.domain for entry in entries]
    
    return {
        "version": get_blocklist_version_hash(db),
        "updated": datetime.now(timezone.utc).date().isoformat(),
        "count": len(domains),
        "domains": domains
    }
