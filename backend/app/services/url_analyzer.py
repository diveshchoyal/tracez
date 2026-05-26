"""TraceZ Backend — SSRF-Safe URL Analyzer Service."""

import urllib.parse
import httpx
from typing import Tuple, List
from app.utils.validators import validate_url_ssrf_safe

async def unroll_redirects_safe(url: str) -> Tuple[List[str], bool]:
    """
    Follows HTTP redirects safely by checking each hop for SSRF risks.
    Returns a tuple: (redirect_chain, is_down).
    """
    chain = [url]
    current_url = url
    is_down = False
    
    # 1. Clean and normalize
    if not (url.startswith("http://") or url.startswith("https://")):
        current_url = "https://" + url
        chain = [current_url]
        
    # 2. Trace redirects
    try:
        # We set follow_redirects=False to manually inspect and validate each hop
        async with httpx.AsyncClient(follow_redirects=False, timeout=3.0) as client:
            hops = 0
            while hops < 5:  # Limit redirect depth to prevent redirection loops/denial-of-service
                # SSRF check before requesting
                is_safe, error_msg = validate_url_ssrf_safe(current_url)
                if not is_safe:
                    # Halt chain and mark as blocked/down due to security policy
                    is_down = True
                    break
                    
                try:
                    # Attempt HEAD request for speed
                    resp = await client.head(current_url)
                    status = resp.status_code
                except (httpx.MethodNotAllowed, httpx.HTTPStatusError):
                    # Fallback to GET if HEAD is not supported
                    resp = await client.get(current_url)
                    status = resp.status_code
                    
                if status in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        break
                        
                    # Handle relative paths/joins
                    location = urllib.parse.urljoin(current_url, location)
                    if location in chain:  # Infinite loop cycle detection
                        break
                        
                    chain.append(location)
                    current_url = location
                    hops += 1
                else:
                    break
    except (httpx.ConnectError, httpx.ConnectTimeout, httpx.HTTPError, httpx.ReadTimeout):
        is_down = True
    except Exception:
        is_down = True
        
    return chain, is_down
