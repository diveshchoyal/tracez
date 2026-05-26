import re
import zipfile
import struct
import io
import logging

logger = logging.getLogger("tracez.l2")

# Regex pattern for IPv4 addresses
IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# Regex for common Android permissions
PERMISSION_PATTERN = re.compile(r'android\.permission\.[A-Z_]+')

# Regex for Java-style packages: com.something.something
PACKAGE_PATTERN = re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z0-9_.]+\b')

def extract_strings_from_binary(data: bytes, min_len: int = 4) -> list:
    """
    Extracts printable ASCII strings from raw bytes.
    Useful for extracting DEX strings, binary constants, IPs, etc.
    """
    result = []
    current = []
    for char in data:
        if 32 <= char <= 126:
            current.append(chr(char))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return result

def fallback_apk_scan(file_path: str) -> dict:
    """
    Manual fallback scanner for APK files using zipfile.
    Used when Androguard is not installed or fails.
    Extracts permissions, namespaces, cert details, and hardcoded IPs.
    """
    permissions = set()
    packages = set()
    hardcoded_ips = set()
    is_self_signed = True
    cert_issuer = "Unknown (Fallback Scan)"
    
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            # Check manifest and classes
            manifest_data = b""
            classes_data = b""
            
            for name in z.namelist():
                if name == "AndroidManifest.xml":
                    manifest_data = z.read(name)
                elif name.endswith(".dex"):
                    # Read dex classes
                    classes_data += z.read(name)
                elif "META-INF" in name and (name.endswith(".RSA") or name.endswith(".DSA")):
                    # Certificate file
                    cert_data = z.read(name)
                    # Simple extraction of common cert fields
                    strings = extract_strings_from_binary(cert_data)
                    for s in strings:
                        if "CN=" in s or "OU=" in s or "O=" in s:
                            cert_issuer = s
                            is_self_signed = "Self" in s or len(strings) < 15
                            
            # Process manifest for permissions (AXML contains plain ASCII strings inside binary structure)
            if manifest_data:
                strings = extract_strings_from_binary(manifest_data)
                for s in strings:
                    if s.startswith("android.permission."):
                        permissions.add(s)
            
            # Process DEX for packages and IPs
            if classes_data:
                # Limit size to search to prevent memory overflow for large files
                search_data = classes_data[:20 * 1024 * 1024]
                strings = extract_strings_from_binary(search_data)
                
                for s in strings:
                    # IPs
                    if IP_PATTERN.match(s):
                        # Avoid matching version numbers like 1.0.0.0
                        if not s.startswith("1.0.") and not s.startswith("0.0."):
                            hardcoded_ips.add(s)
                    
                    # Package namespaces (e.g. com.google.firebase)
                    # Clean and match packages
                    if PACKAGE_PATTERN.match(s):
                        parts = s.split('.')
                        if len(parts) >= 3:
                            packages.add(".".join(parts[:3]))
                            
    except Exception as e:
        logger.error(f"Fallback scan error: {e}")
        
    return {
        "permissions": list(permissions),
        "packages": list(packages),
        "hardcoded_ips": list(hardcoded_ips),
        "is_self_signed": is_self_signed,
        "cert_issuer": cert_issuer,
        "mode": "Fallback (Built-in AXML/DEX string parser)"
    }

def androguard_apk_scan(file_path: str) -> dict:
    """
    Standard APK analyzer using Androguard.
    """
    try:
        from androguard.misc import AnalyzeAPK
        
        apk, dex, analysis = AnalyzeAPK(file_path)
        
        permissions = apk.get_permissions()
        
        packages = set()
        for d in dex:
            for cls in d.get_classes():
                parts = cls.name.lstrip('L').rstrip(';').split('/')
                if len(parts) >= 3:
                    packages.add('.'.join(parts[:3]))
                    
        # Extract IPs from strings
        hardcoded_ips = set()
        for d in dex:
            for s in d.get_strings():
                val = str(s)
                if IP_PATTERN.match(val):
                    if not val.startswith("1.0.") and not val.startswith("0.0."):
                        hardcoded_ips.add(val)
                        
        # Cert details
        cert_issuer = "Unknown"
        is_self_signed = True
        
        certs = apk.get_certificates()
        if certs:
            cert = certs[0]
            cert_issuer = str(cert.issuer.human_friendly)
            is_self_signed = cert.issuer == cert.subject
            
        return {
            "permissions": list(permissions),
            "packages": list(packages),
            "hardcoded_ips": list(hardcoded_ips),
            "is_self_signed": is_self_signed,
            "cert_issuer": cert_issuer,
            "mode": "Androguard"
        }
    except Exception as e:
        logger.warning(f"Androguard failed, falling back to zip parser. Reason: {e}")
        return fallback_apk_scan(file_path)

def run_l2_scan(file_path: str, filename: str) -> dict:
    """
    Runs Layer 2 APK Static analysis on a file.
    If the file is not an APK, runs simple binary string scanner.
    """
    if not filename.lower().endswith(".apk"):
        # Simple binary scan
        try:
            with open(file_path, "rb") as f:
                data = f.read(5 * 1024 * 1024)  # first 5MB
            strings = extract_strings_from_binary(data)
            ips = [s for s in strings if IP_PATTERN.match(s) and not s.startswith("1.0.")]
            
            return {
                "permissions": [],
                "packages": [],
                "hardcoded_ips": list(set(ips)),
                "is_self_signed": False,
                "cert_issuer": "Non-APK file type",
                "mode": "Generic file binary scanner"
            }
        except Exception as e:
            return {"error": str(e), "mode": "Generic scanner error"}

    return androguard_apk_scan(file_path)
