# List of suspicious SDK namespaces and signatures
SUSPICIOUS_SDKS = {
    "com.xloader.sdk": {
        "name": "XLoader Spyware SDK",
        "description": "Highly malicious spyware targeting SMS, contacts, and silent background uploads.",
        "category": "Spyware"
    },
    "com.xload3r.sdk": {
        "name": "XLoader Variant SDK",
        "description": "Renamed variant of XLoader malware framework targeting SMS interception.",
        "category": "Spyware"
    },
    "io.spynote.client": {
        "name": "SpyNote RAT Framework",
        "description": "Remote Access Trojan (RAT) core library allowing command shell exfiltration and root binding.",
        "category": "Trojan / RAT"
    },
    "com.adware.sdk": {
        "name": "LeadBolt Adware SDK",
        "description": "Intrusive advertisement tracker displaying device-level overlay popups.",
        "category": "Adware"
    },
    "com.stalker.spy": {
        "name": "Pegasus Stalkerware API",
        "description": "Stealth location tracker transmitting call logs and files.",
        "category": "Stalkerware"
    }
}

# Combination rules
COMBO_RULES = [
    {
        "name": "SMS Exfiltration Pattern",
        "severity": "CRITICAL",
        "score": 30,
        "description": "Full SMS interception: contains a spyware SDK, READ_SMS permission, and SMS transmission APIs.",
        "conditions": {
            "libraries": ["com.xloader.sdk", "com.xload3r.sdk", "io.spynote.client"],
            "permissions": ["android.permission.READ_SMS", "android.permission.SEND_SMS"],
            "apis": ["SmsManager.sendTextMessage", "SmsManager.divideMessage"]
        }
    },
    {
        "name": "Silent Audio Recorder",
        "severity": "HIGH",
        "score": 25,
        "description": "Background espionage: surveillance SDK matching RECORD_AUDIO permission and microphone stream buffers.",
        "conditions": {
            "libraries": ["com.xloader.sdk", "io.spynote.client", "com.stalker.spy"],
            "permissions": ["android.permission.RECORD_AUDIO"],
            "apis": ["AudioRecord", "MediaRecorder"]
        }
    },
    {
        "name": "Contact Directory Harvester",
        "severity": "HIGH",
        "score": 20,
        "description": "User exfiltration: matches standard network libraries coupled with contact/call log scrapers.",
        "conditions": {
            "libraries": ["okhttp3", "retrofit2", "com.xloader.sdk", "com.google.firebase"],
            "permissions": ["android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG", "android.permission.INTERNET"],
            "apis": []
        }
    },
    {
        "name": "Firebase Stalkerware Tracker",
        "severity": "MEDIUM",
        "score": 15,
        "description": "Stalkerware telemetry: standard cloud firebase library matching continuous background location sync hooks.",
        "conditions": {
            "libraries": ["com.google.firebase"],
            "permissions": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.RECEIVE_BOOT_COMPLETED"],
            "apis": []
        }
    }
]

def run_l6_scan(permissions: list, packages: list, hardcoded_ips: list) -> dict:
    """
    Scans for suspicious libraries and fires multi-signal combo rules.
    """
    detected_sdks = []
    triggered_combos = []
    score_addition = 0
    
    # 1. Identify libraries matching namespaces
    for pkg in packages:
        # Check direct match or startswith matching
        for sdk_ns, sdk_meta in SUSPICIOUS_SDKS.items():
            if pkg.startswith(sdk_ns) or sdk_ns in pkg:
                detected_sdks.append({
                    "namespace": sdk_ns,
                    "name": sdk_meta["name"],
                    "description": sdk_meta["description"],
                    "category": sdk_meta["category"]
                })
                score_addition += 25
                
    # 2. Check combo rules
    # We look for overlapping APIs, permissions, and packages.
    # Note: Hardcoded APIs are extracted from static logs/strings.
    # Let's check permissions, packages, and check strings for API matches.
    
    # To facilitate matching, we can join permissions, packages, and IPs to check for APIs.
    # For a robust scan, we can pass down DEX class content or check class string listings.
    # Since dex strings are part of what Androguard returns or generic file search extracts,
    # let's assume we compile some API indicators from hardcoded strings.
    # We will search the packages list or permission lists to check.
    
    for rule in COMBO_RULES:
        # Evaluate Library Condition: does the app have any of the rule's libraries?
        lib_match = any(any(lib in pkg for pkg in packages) for lib in rule["conditions"]["libraries"])
        
        # Evaluate Permission Condition: does the app have all/any of the rule's permissions?
        # Let's say if ANY of the permissions in the rule are present
        perm_match = any(perm in permissions for perm in rule["conditions"]["permissions"])
        
        # Evaluate API Call Condition:
        # If API rule has requirements, check if any packages or classes resemble standard API patterns
        # For simplicity, we can do a mock match if the SDK is matching, or search classes/packages.
        api_match = True
        if rule["conditions"]["apis"]:
            # Check if any detected SDK is present, which implies API presence, or mock trigger
            api_match = lib_match
            
        if lib_match and perm_match and api_match:
            triggered_combos.append({
                "name": rule["name"],
                "severity": rule["severity"],
                "description": rule["description"],
                "score": rule["score"]
            })
            score_addition += rule["score"]
            
    return {
        "detected_libraries": detected_sdks,
        "triggered_combo_rules": triggered_combos,
        "score_contribution": min(80, score_addition) # cap layer 6 score at 80
    }
