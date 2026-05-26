import httpx
import os
import json

async def call_llm_verdict(summary_data: dict, api_key: str = None) -> str:
    """
    Calls an LLM API (OpenAI or local router) to synthesize findings into plain English.
    Returns 2-3 sentences max.
    """
    if not api_key:
        api_key = os.getenv("OPENAI_API_KEY")
        
    if not api_key or api_key == "MOCK_KEY" or "DEMO" in api_key:
        # Fallback to local rule-based builder
        return build_local_verdict(summary_data)
        
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    prompt = f"""
    You are the TraceZ security intelligence engine. Synthesize these security scan findings into a concise, plain English verdict for a normal student or consumer.
    Do not use complex technical terms (like 'DEX bytecode' or 'SHA-256 hash').
    Provide exactly 2-3 sentences:
    1. A summary of what this file/link is and its threat level.
    2. The most dangerous behavior found (e.g. stealing SMS, fake website).
    3. Clear, direct action (e.g. Do not install, delete immediately).

    Scan Results JSON:
    {json.dumps(summary_data)}
    """
    
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a helpful security analyst translating technical telemetry into plain English verdicts."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 120,
        "temperature": 0.3
    }
    
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                result = resp.json()
                return result["choices"][0]["message"]["content"].strip()
    except Exception:
        pass
        
    return build_local_verdict(summary_data)

def build_local_verdict(summary_data: dict) -> str:
    """
    Fallback rule-based description builder generating natural-sounding verdicts.
    """
    verdict = summary_data.get("verdict", "SAFE")
    score = summary_data.get("risk_score", 0)
    file_type = summary_data.get("type", "FILE")
    
    if verdict == "SAFE":
        return "This scan detected no malicious indicators or suspicious behavioral patterns. The file appears safe to use, though always verify source trust before launching."
        
    sentences = []
    
    # 1. Opening Statement
    if file_type == "URL":
        sentences.append(f"This URL has been flagged as {verdict.lower()} (Risk Score: {score}/100).")
    else:
        sentences.append(f"This file has been flagged as {verdict.lower()} (Risk Score: {score}/100).")
        
    # 2. Key Findings
    threats = []
    
    # Check URL indicators
    url_results = summary_data.get("layer_results", {}).get("layer_4", {})
    if url_results:
        if url_results.get("typosquat_info", {}).get("typosquat"):
            target = url_results["typosquat_info"].get("target_brand")
            threats.append(f"it closely mimics the official {target} domain name to mislead users")
        if url_results.get("domain_age_days", 999) < 7:
            threats.append("it was registered very recently, a common tactic for temporary phishing servers")
        if url_results.get("blocklists", {}).get("google_safe_browsing") == "suspicious":
            threats.append("it is flagged on community safe browsing blacklists")
        if url_results.get("domain") == "fitgirl-repacks.site":
            threats.append("it is a known cracked software repack index, which carries risk of bundling Potentially Unwanted Programs (PUP)")
        if url_results.get("is_down"):
            threats.append("the destination server is currently offline or connection failed, which is common for short-lived malicious hostings")

    # Check Static/Similarity indicators
    l7_results = summary_data.get("layer_results", {}).get("layer_7", {})
    if l7_results and l7_results.get("similarity_score", 0) >= 0.70:
        threat_name = l7_results.get("threat_name", "spyware")
        pct = l7_results.get("similarity_score", 0) * 100
        threats.append(f"it shares {pct:.0f}% behavioral similarity with known {threat_name} malware code")

    # Check dangerous combos
    l6_results = summary_data.get("layer_results", {}).get("layer_6", {})
    if l6_results and l6_results.get("triggered_combo_rules"):
        rules = [r["name"] for r in l6_results["triggered_combo_rules"]]
        threats.append(f"it triggers behavior combo alerts for: {', '.join(rules)}")
        
    # Check sandbox triggers
    l3_results = summary_data.get("layer_results", {}).get("layer_3", {})
    if l3_results:
        if l3_results.get("trojan_constraint_detected"):
            threats.append("it exhibits dynamic evasion, changing its actions when it detects an emulator environment")
        elif l3_results.get("malicious_behavior_observed"):
            threats.append("our sandbox captured background data transmissions immediately upon startup")
            
    if threats:
        # Build second sentence
        if len(threats) > 1:
            sentences.append(f"We identified that {threats[0]}, and {threats[1]}.")
        else:
            sentences.append(f"Specifically, {threats[0]}.")
    else:
        sentences.append("It contains suspicious code patterns and elevated permissions that are frequently abused by background malware.")
        
    # 3. Action statement
    if verdict == "DANGEROUS":
        if file_type == "URL":
            sentences.append("Do not click links or enter passwords on this site. Close the tab immediately.")
        else:
            sentences.append("Do not install this application. Delete the downloaded file from your storage folder.")
    else:
        sentences.append("Exercise extreme caution if you choose to proceed. Avoid sharing personal information or credentials.")
        
    return " ".join(sentences)

def run_l5_verdict(layer_scores: dict, layer_results: dict, item_type: str) -> dict:
    """
    Computes cumulative risk score and generates a structured verdict payload.
    """
    total_score = sum(layer_scores.values())
    
    # Cap total score at 100
    risk_score = min(100, total_score)
    
    if risk_score >= 50:
        verdict = "DANGEROUS"
    elif risk_score >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
        
    summary_data = {
        "verdict": verdict,
        "risk_score": risk_score,
        "type": item_type,
        "layer_results": layer_results
    }
    
    return summary_data
