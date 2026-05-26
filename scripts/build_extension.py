"""TraceZ Chrome Extension Builder and Packager."""

import json
import os
import shutil
import zipfile
from pathlib import Path

def validate_manifest(manifest_path: Path) -> bool:
    """Validate key MV3 fields in the extension manifest."""
    print("[*] Validating manifest.json...")
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
            
        # Check Manifest Version
        if manifest.get("manifest_version") != 3:
            print("[!] Error: manifest_version must be exactly 3 for MV3 extension.")
            return False
            
        # Check required metadata
        if not manifest.get("name") or not manifest.get("version"):
            print("[!] Error: name and version fields are required.")
            return False
            
        # Check background service worker configuration
        bg = manifest.get("background", {})
        if not bg or not bg.get("service_worker"):
            print("[!] Error: background service_worker configuration is missing.")
            return False
            
        # Check if worker file exists on disk
        worker_path = manifest_path.parent / bg.get("service_worker")
        if not worker_path.exists():
            print(f"[!] Error: background service worker file '{bg.get('service_worker')}' not found.")
            return False
            
        # Check content script definitions
        content_scripts = manifest.get("content_scripts", [])
        for script in content_scripts:
            for js_file in script.get("js", []):
                js_path = manifest_path.parent / js_file
                if not js_path.exists():
                    print(f"[!] Error: content script js file '{js_file}' not found.")
                    return False
                    
        # Check popup UI definitions
        action = manifest.get("action", {})
        if action and action.get("default_popup"):
            popup_path = manifest_path.parent / action.get("default_popup")
            if not popup_path.exists():
                print(f"[!] Error: action default_popup file '{action.get('default_popup')}' not found.")
                return False
                
        print("[+] Manifest validation passed successfully.")
        return True
    except Exception as e:
        print(f"[!] Manifest validation failed with exception: {e}")
        return False

def zip_directory(src_dir: Path, zip_file_path: Path):
    """Compress a directory into a zip archive."""
    print(f"[*] Compressing {src_dir} into zip archive...")
    with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(src_dir):
            for file in files:
                file_path = Path(root) / file
                # Save path relative to the src_dir root (so zip doesn't have absolute system paths)
                archive_name = file_path.relative_to(src_dir)
                zip_file.write(file_path, archive_name)
    print(f"[+] Zip compiled successfully at: {zip_file_path}")

def build_extension():
    """Main build orchestrator."""
    root_dir = Path(__file__).resolve().parent.parent
    extension_dir = root_dir / "extension"
    dist_dir = root_dir / "dist"
    static_dir = root_dir / "backend" / "app" / "static"
    zip_output = static_dir / "tracez-extension.zip"
    
    print("=" * 60)
    print("                 TRACEZ EXTENSION BUILD PROCESS                ")
    print("=" * 60)
    
    # 1. Verify source folders
    if not extension_dir.exists():
        print(f"[!] Source extension directory '{extension_dir}' not found. Cannot build.")
        return False
        
    manifest_file = extension_dir / "manifest.json"
    if not manifest_file.exists():
        print(f"[!] manifest.json not found at '{manifest_file}'.")
        return False
        
    # 2. Validate manifest
    if not validate_manifest(manifest_file):
        print("[!] Build aborted due to manifest validation errors.")
        return False
        
    # 3. Clean and recreate dist/ directory
    if dist_dir.exists():
        print("[*] Cleaning existing dist/ folder...")
        shutil.rmtree(dist_dir)
    dist_dir.mkdir(parents=True, exist_ok=True)
    
    # 4. Copy extension files to dist/
    print(f"[*] Packaging extension files into '{dist_dir}'...")
    # Recursively copy all files except temporary folders or build configs
    for item in extension_dir.iterdir():
        if item.name.startswith(".") or item.name in ("node_modules", "package-lock.json"):
            continue
        
        target = dist_dir / item.name
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)
            
    # 5. Compress and compile the zip archive
    if not static_dir.exists():
        static_dir.mkdir(parents=True, exist_ok=True)
        
    zip_directory(dist_dir, zip_output)
    
    print("\n[+] TraceZ Extension successfully compiled and ready for distribution!")
    print(f"    - Release directory: {dist_dir}")
    print(f"    - Web Download target: {zip_output}\n")
    return True

if __name__ == "__main__":
    build_extension()
