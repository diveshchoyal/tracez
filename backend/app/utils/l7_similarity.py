import math
import json
from sqlalchemy.orm import Session
from app.database import Threat

def calculate_cosine_similarity(set_a: set, set_b: set) -> float:
    """
    Computes cosine similarity on binary feature vectors (sets).
    Similarity = |A ∩ B| / sqrt(|A| * |B|)
    """
    if not set_a or not set_b:
        return 0.0
        
    intersection = len(set_a.intersection(set_b))
    denominator = math.sqrt(len(set_a) * len(set_b))
    
    if denominator == 0:
        return 0.0
        
    return intersection / denominator

def run_l7_scan(db: Session, permissions: list, packages: list, hardcoded_ips: list) -> dict:
    """
    Phase 1: Exact pattern matches.
    Phase 2: Cosine Similarity calculations against registered threats in database.
    """
    # 1. Compile scanned features set
    scanned_features = set()
    for p in permissions:
        scanned_features.add(f"permission:{p}")
    for pkg in packages:
        scanned_features.add(f"namespace:{pkg}")
    for ip in hardcoded_ips:
        scanned_features.add(f"ip:{ip}")
        
    # Append common API keywords extracted from libraries/packages
    if "android.permission.READ_SMS" in permissions:
        scanned_features.add("api:SmsManager.sendTextMessage")
    if "android.permission.RECORD_AUDIO" in permissions:
        scanned_features.add("api:AudioRecord.startRecording")
        
    # Fetch all threats from SQLite
    threats = db.query(Threat).all()
    
    best_match = None
    best_similarity = 0.0
    matched_features = []
    
    # Phase 1 & 2 execution
    for threat in threats:
        try:
            threat_features = set(json.loads(threat.features_json))
        except Exception:
            continue
            
        # Cosine Similarity check
        similarity = calculate_cosine_similarity(scanned_features, threat_features)
        
        # Check if we have exact pattern overlap (Phase 1)
        # If all features of threat are in scanned, or specific namespaces match
        exact_namespace_match = False
        for tf in threat_features:
            if tf.startswith("namespace:") and tf in scanned_features:
                exact_namespace_match = True
                
        if similarity > best_similarity:
            best_similarity = similarity
            best_match = threat
            matched_features = list(scanned_features.intersection(threat_features))
            
    # Compile findings based on similarity thresholds
    verdict = "SAFE"
    description = "No similarity to known malware profiles found."
    score_addition = 0
    trz_id = None
    threat_name = "Clean Scan"
    
    if best_similarity >= 0.95:
        verdict = "DANGEROUS"
        trz_id = best_match.id
        threat_name = best_match.name
        description = f"Variant Match: App is {best_similarity*100:.1f}% similar to {best_match.name} ({best_match.id})."
        score_addition = 35
    elif best_similarity >= 0.80:
        verdict = "DANGEROUS"
        trz_id = best_match.id
        threat_name = best_match.name
        description = f"High Similarity: App is {best_similarity*100:.1f}% similar to known threat {best_match.name} ({best_match.id})."
        score_addition = 25
    elif best_similarity >= 0.50:
        verdict = "SUSPICIOUS"
        trz_id = best_match.id
        threat_name = best_match.name
        description = f"Medium Similarity: App is {best_similarity*100:.1f}% similar to {best_match.name} ({best_match.id})."
        score_addition = 15
        
    return {
        "status": "success",
        "best_match_threat_id": trz_id,
        "threat_name": threat_name,
        "similarity_score": best_similarity,
        "matched_features": matched_features,
        "description": description,
        "verdict": verdict,
        "score_contribution": score_addition
    }
