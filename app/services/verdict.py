"""TraceZ Backend — Scoring and Verdict Recommendation Engine."""

from typing import Dict, List

def calculate_verdict(
    url: str,
    domain: str,
    signals: List[Dict],
    reputation: Dict,
    on_blocklist: bool = False
) -> Dict:
    """
    Combines local heuristics, redirection outcomes, and external API signals
    to calculate a weighted risk score (0-100) and issue a security verdict.
    """
    # 1. Base Score calculation from heuristics
    score = 0
    
    # If explicitly on local blocklist, auto-flag as high risk
    if on_blocklist:
        score = 95
    else:
        # Sum heuristic signals
        for sig in signals:
            score += sig.get("score", 0)
            
        # 2. Add reputation penalties
        vt = reputation.get("virustotal", {})
        vt_malicious = vt.get("malicious", 0)
        if vt_malicious > 5:
            score += 45
        elif vt_malicious > 2:
            score += 25
        elif vt_malicious > 0:
            score += 10
            
        gsb = reputation.get("google_safe_browsing", "clean")
        if gsb == "phishing":
            score += 40
        elif gsb == "malware":
            score += 50
            
        otx = reputation.get("otx", {})
        if otx.get("is_malicious") or otx.get("pulse_count", 0) > 3:
            score += 20
            
    # Cap score between 0 and 100
    score = min(100, max(0, score))
    
    # 3. Classify verdict based on thresholds
    if score >= 81:
        verdict = "DANGEROUS"
    elif score >= 56:
        verdict = "WARNING"
    elif score >= 26:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
        
    # 4. Generate human-readable recommendation
    recs = []
    
    if on_blocklist:
        recs.append("This domain is on the TraceZ active blocklist of verified threats.")
        
    for sig in signals:
        if sig["layer"] == "homoglyph":
            recs.append(sig["signal"])
            
    if reputation.get("google_safe_browsing") in ("phishing", "malware"):
        recs.append(f"Google Safe Browsing flagged this site as {reputation['google_safe_browsing']}.")
        
    vt_mal = reputation.get("virustotal", {}).get("malicious", 0)
    if vt_mal > 2:
        recs.append(f"Multiple security scanners ({vt_mal}) flagged this URL on VirusTotal.")
        
    if "fitgirl" in domain.lower() and domain.lower() != "fitgirl-repacks.site":
        recs.append("This is an unofficial mirror/clone of FitGirl Repacks. It may contain malware-infected repack installers.")
        
    # Default fallback recommendations based on tier
    if not recs:
        if verdict == "DANGEROUS":
            recs.append("Highly suspicious signals detected. We strongly advise against visiting this page.")
        elif verdict == "WARNING":
            recs.append("Caution is advised. This site displays indicators commonly associated with phishing.")
        elif verdict == "SUSPICIOUS":
            recs.append("Some minor security anomalies were identified. Verify the URL before inputting credentials.")
        else:
            recs.append("No threat indicators detected. The site appears safe to browse.")
            
    recommendation = " ".join(recs)
    
    return {
        "verdict": verdict,
        "risk_score": score,
        "recommendation": recommendation
    }
