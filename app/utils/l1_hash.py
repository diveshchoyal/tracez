import hashlib
import os
import httpx
import asyncio

CHUNK_SIZE = 8192  # 8KB chunks

async def calculate_hash_stream(file_stream, callback=None):
    """
    Reads a file-like object in 8KB chunks, computes the SHA-256 hash.
    Avoids holding the entire file in RAM.
    Calls `callback` with progress or chunk size if provided.
    """
    hasher = hashlib.sha256()
    total_bytes = 0
    
    while True:
        chunk = await file_stream.read(CHUNK_SIZE)
        if not chunk:
            break
        hasher.update(chunk)
        total_bytes += len(chunk)
        if callback:
            await callback(total_bytes)
        # Yield execution to allow other tasks to run
        await asyncio.sleep(0)
        
    return hasher.hexdigest(), total_bytes

async def check_virus_total(file_hash: str, api_key: str = None) -> dict:
    """
    Checks the file hash against VirusTotal v3.
    Returns the count of engines that flagged it.
    """
    if not api_key:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        
    if not api_key or api_key == "MOCK_KEY" or "DEMO" in api_key:
        # Simulate check based on some mock hashes
        if file_hash == "a3f2c9d84e11b72f38cc901456de8fa29c3b77e041d2891f5a63e09b14c82031":
            return {"status": "detected", "engines_flagged": 42, "total_engines": 72, "source": "VirusTotal (Mocked)"}
        return {"status": "clean", "engines_flagged": 0, "total_engines": 72, "source": "VirusTotal (Mocked)"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())
                return {
                    "status": "detected" if (malicious + suspicious) > 0 else "clean",
                    "engines_flagged": malicious + suspicious,
                    "total_engines": total,
                    "source": "VirusTotal"
                }
            elif resp.status_code == 404:
                return {"status": "unknown", "engines_flagged": 0, "total_engines": 0, "source": "VirusTotal"}
    except Exception as e:
        return {"status": "error", "error": str(e), "source": "VirusTotal"}
        
    return {"status": "unknown", "engines_flagged": 0, "total_engines": 0, "source": "VirusTotal"}

async def check_malware_bazaar(file_hash: str) -> dict:
    """
    Checks the file hash against MalwareBazaar API.
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info", "hash": file_hash}
    
    # Mock behavior for our demo hashes
    if file_hash == "a3f2c9d84e11b72f38cc901456de8fa29c3b77e041d2891f5a63e09b14c82031":
        return {"status": "detected", "malware_family": "XLoader", "signature": "XLoader.spyware", "source": "MalwareBazaar (Mocked)"}
        
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.post(url, data=data)
            if resp.status_code == 200:
                res_data = resp.json()
                if res_data.get("query_status") == "ok":
                    info = res_data.get("data", [{}])[0]
                    return {
                        "status": "detected",
                        "malware_family": info.get("signature", "Unknown"),
                        "signature": info.get("tags", []),
                        "source": "MalwareBazaar"
                    }
    except Exception:
        pass
        
    return {"status": "clean", "source": "MalwareBazaar"}

async def check_urlhaus(file_hash: str) -> dict:
    """
    Checks file hash against URLhaus.
    """
    url = "https://urlhaus-api.abuse.ch/v1/payload/"
    data = {"sha256_hash": file_hash}
    
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.post(url, data=data)
            if resp.status_code == 200:
                res_data = resp.json()
                if res_data.get("query_status") == "ok":
                    return {
                        "status": "detected",
                        "url_count": res_data.get("url_count", 0),
                        "first_seen": res_data.get("firstseen"),
                        "source": "URLhaus"
                    }
    except Exception:
        pass
    return {"status": "clean", "source": "URLhaus"}

async def check_otx_alienvault(file_hash: str, api_key: str = None) -> dict:
    """
    Checks the file hash against OTX AlienVault.
    """
    if not api_key:
        api_key = os.getenv("OTX_API_KEY")
        
    if not api_key or api_key == "MOCK_KEY" or "DEMO" in api_key:
        if file_hash == "a3f2c9d84e11b72f38cc901456de8fa29c3b77e041d2891f5a63e09b14c82031":
            return {"status": "detected", "pulse_count": 14, "source": "OTX AlienVault (Mocked)"}
        return {"status": "clean", "pulse_count": 0, "source": "OTX AlienVault (Mocked)"}
        
    url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    headers = {"X-OTX-API-KEY": api_key}
    
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                pulses = data.get("pulse_info", {}).get("pulses", [])
                if len(pulses) > 0:
                    return {
                        "status": "detected",
                        "pulse_count": len(pulses),
                        "pulses": [p.get("name") for p in pulses[:3]],
                        "source": "OTX AlienVault"
                    }
    except Exception:
        pass
    return {"status": "clean", "source": "OTX AlienVault"}

async def run_l1_scan(file_hash: str, vt_key: str = None, otx_key: str = None) -> dict:
    """
    Orchestrates Layer 1 checks in parallel.
    """
    vt_task = check_virus_total(file_hash, vt_key)
    mb_task = check_malware_bazaar(file_hash)
    uh_task = check_urlhaus(file_hash)
    otx_task = check_otx_alienvault(file_hash, otx_key)
    
    results = await asyncio.gather(vt_task, mb_task, uh_task, otx_task, return_exceptions=True)
    
    output = {
        "virustotal": results[0] if not isinstance(results[0], Exception) else {"status": "error", "error": str(results[0]), "source": "VirusTotal"},
        "malwarebazaar": results[1] if not isinstance(results[1], Exception) else {"status": "error", "error": str(results[1]), "source": "MalwareBazaar"},
        "urlhaus": results[2] if not isinstance(results[2], Exception) else {"status": "error", "error": str(results[2]), "source": "URLhaus"},
        "otx": results[3] if not isinstance(results[3], Exception) else {"status": "error", "error": str(results[3]), "source": "OTX AlienVault"},
        "score_contribution": 0
    }
    
    # Calculate score contribution
    flagged_engines = 0
    if output["virustotal"].get("status") == "detected":
        flagged_engines = output["virustotal"].get("engines_flagged", 0)
        output["score_contribution"] += flagged_engines * 10
        
    if output["malwarebazaar"].get("status") == "detected":
        output["score_contribution"] += 35
        
    if output["urlhaus"].get("status") == "detected":
        output["score_contribution"] += 25
        
    if output["otx"].get("status") == "detected":
        output["score_contribution"] += 20
        
    return output
