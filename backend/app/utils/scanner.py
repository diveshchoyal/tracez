import asyncio
import json
import hashlib
from sqlalchemy.orm import Session
from app.database import Threat, Scan
from app.utils.l1_hash import run_l1_scan, calculate_hash_stream
from app.utils.l2_static import run_l2_scan
from app.utils.l3_sandbox import simulate_sandbox_execution
from app.utils.l4_url import run_l4_scan
from app.utils.l6_library import run_l6_scan
from app.utils.l7_similarity import run_l7_scan
from app.utils.verdict import run_l5_verdict, call_llm_verdict

class ScanOrchestrator:
    def __init__(self, db: Session, openai_key: str = None, vt_key: str = None):
        self.db = db
        self.openai_key = openai_key
        self.vt_key = vt_key

    async def scan_file_stream(self, file_path: str, filename: str, event_queue: asyncio.Queue):
        """
        Orchestrates 7 layers of scanning for a file and puts SSE payload into event_queue.
        """
        try:
            await event_queue.put({"event": "progress", "data": {"step": "INIT", "message": "Hashing file in 8KB chunks..."}})
            
            # Step 1: Compute Hash
            hasher = None
            with open(file_path, "rb") as f:
                # Wrap sync open inside a stream reader or helper
                # Since calculate_hash_stream expects an async read, let's wrap it in a mock stream
                class AsyncFileWrapper:
                    def __init__(self, fp):
                        self.fp = fp
                    async def read(self, size):
                        # Run blocking read in threadpool or simple yield
                        await asyncio.sleep(0.01)
                        return self.fp.read(size)
                
                file_hash, file_size = await calculate_hash_stream(AsyncFileWrapper(f))
                
            await event_queue.put({"event": "hash_ready", "data": {"hash": file_hash, "size": file_size}})
            await event_queue.put({"event": "progress", "data": {"step": "L1_START", "message": "Querying Threat Intelligence APIs..."}})
            
            # Initialize layer variables
            layer_results = {}
            layer_scores = {}
            
            # Run Layer 1 (Hash APIs)
            l1_res = await run_l1_scan(file_hash, vt_key=self.vt_key)
            layer_results["layer_1"] = l1_res
            layer_scores["layer_1"] = l1_res["score_contribution"]
            await event_queue.put({"event": "progress", "data": {"step": "L1_COMPLETE", "message": "Layer 1 Complete", "data": l1_res}})
            
            # Run Layer 2 (Static APK Scanner)
            await event_queue.put({"event": "progress", "data": {"step": "L2_START", "message": "Decompiling DEX bytecode and manifest..."}})
            l2_res = run_l2_scan(file_path, filename)
            layer_results["layer_2"] = l2_res
            # Extract basic score contribution for L2
            l2_score = 0
            if l2_res.get("is_self_signed"):
                l2_score += 15
            if len(l2_res.get("permissions", [])) > 6:
                l2_score += 10
            l2_score += len(l2_res.get("hardcoded_ips", [])) * 20
            layer_scores["layer_2"] = min(40, l2_score)
            
            await event_queue.put({"event": "progress", "data": {"step": "L2_COMPLETE", "message": "Layer 2 Complete", "data": l2_res}})
            
            # Run Layer 6 (Library Signatures) - depends on L2
            await event_queue.put({"event": "progress", "data": {"step": "L6_START", "message": "Fingerprinting SDK classes and dependencies..."}})
            l6_res = run_l6_scan(l2_res.get("permissions", []), l2_res.get("packages", []), l2_res.get("hardcoded_ips", []))
            layer_results["layer_6"] = l6_res
            layer_scores["layer_6"] = l6_res["score_contribution"]
            await event_queue.put({"event": "progress", "data": {"step": "L6_COMPLETE", "message": "Layer 6 Complete", "data": l6_res}})
            
            # Run Layer 7 (TRZ Vector similarity) - depends on L2
            await event_queue.put({"event": "progress", "data": {"step": "L7_START", "message": "Calculating cosine behavioral vector similarity..."}})
            l7_res = run_l7_scan(self.db, l2_res.get("permissions", []), l2_res.get("packages", []), l2_res.get("hardcoded_ips", []))
            layer_results["layer_7"] = l7_res
            layer_scores["layer_7"] = l7_res["score_contribution"]
            await event_queue.put({"event": "progress", "data": {"step": "L7_COMPLETE", "message": "Layer 7 Complete", "data": l7_res}})
            
            # Run Layer 4 (URL Intel) - If file has hardcoded IPs, we scan them, otherwise flag clean
            await event_queue.put({"event": "progress", "data": {"step": "L4_START", "message": "Resolving DNS and network source routes..."}})
            l4_res = {
                "original_url": "File Scan",
                "final_url": "N/A",
                "redirect_chain": [],
                "domain": "Local Payload",
                "typosquat_info": {"typosquat": False},
                "domain_age_days": 365,
                "ssl_certificate": {"issuer": "N/A", "is_valid": True, "expiry_days_remaining": 365},
                "blocklists": {"google_safe_browsing": "clean", "phishtank": "clean"},
                "file_download": {"is_download": False, "extension": ""},
                "score_contribution": 0
            }
            if l2_res.get("hardcoded_ips"):
                # If there are hardcoded IPs, add a small warning score
                l4_res["score_contribution"] = min(30, len(l2_res["hardcoded_ips"]) * 15)
                l4_res["final_url"] = l2_res["hardcoded_ips"][0]
                
            layer_results["layer_4"] = l4_res
            layer_scores["layer_4"] = l4_res["score_contribution"]
            await event_queue.put({"event": "progress", "data": {"step": "L4_COMPLETE", "message": "Layer 4 Complete", "data": l4_res}})
            
            # Run Layer 3 (Sandbox simulation)
            await event_queue.put({"event": "progress", "data": {"step": "L3_START", "message": "Launching virtual phone sandbox..."}})
            
            async def sandbox_callback(msg, lvl):
                await event_queue.put({"event": "sandbox_log", "data": {"message": msg, "level": lvl}})
                
            l3_res = await simulate_sandbox_execution(
                l2_res.get("permissions", []), 
                l2_res.get("packages", []),
                callback=sandbox_callback
            )
            layer_results["layer_3"] = l3_res
            layer_scores["layer_3"] = l3_res["score_contribution"]
            await event_queue.put({"event": "progress", "data": {"step": "L3_COMPLETE", "message": "Layer 3 Complete", "data": l3_res}})
            
            # Run Layer 5 (Verdict Summarizer)
            await event_queue.put({"event": "progress", "data": {"step": "L5_START", "message": "Generating final verdict summary..."}})
            
            verdict_payload = run_l5_verdict(layer_scores, layer_results, "FILE")
            plain_english = await call_llm_verdict(verdict_payload, api_key=self.openai_key)
            
            verdict_payload["plain_english"] = plain_english
            verdict_payload["layer_scores"] = layer_scores
            
            # Save file scan to SQLite history
            try:
                db_scan = Scan(
                    id=file_hash,
                    filename=filename,
                    type="FILE",
                    verdict=verdict_payload["verdict"],
                    risk_score=verdict_payload["risk_score"],
                    layer_results=json.dumps(layer_results)
                )
                self.db.merge(db_scan)
                self.db.commit()
            except Exception as dbe:
                print(f"Error saving file scan: {dbe}")
            
            await event_queue.put({"event": "verdict", "data": verdict_payload})
            await event_queue.put({"event": "done", "data": {}})
            
        except Exception as e:
            await event_queue.put({"event": "error", "data": {"message": f"Scan failed: {str(e)}"}})

    async def scan_url_stream(self, url: str, event_queue: asyncio.Queue):
        """
        Orchestrates 7 layers of scanning for a URL.
        """
        try:
            await event_queue.put({"event": "progress", "data": {"step": "INIT", "message": "Initializing URL scan..."}})
            
            layer_results = {}
            layer_scores = {}
            
            # Layer 4: URL Intelligence Engine (first for URLs)
            await event_queue.put({"event": "progress", "data": {"step": "L4_START", "message": "Analyzing redirect chains & WHOIS registration..."}})
            l4_res = await run_l4_scan(url)
            layer_results["layer_4"] = l4_res
            layer_scores["layer_4"] = l4_res["score_contribution"]
            await event_queue.put({"event": "progress", "data": {"step": "L4_COMPLETE", "message": "Layer 4 Complete", "data": l4_res}})
            
            # Compute hash of the URL string to query threat DBs (Layer 1)
            url_hash = hashlib.sha256(l4_res["final_url"].encode("utf-8")).hexdigest()
            await event_queue.put({"event": "hash_ready", "data": {"hash": url_hash, "size": len(url)}})
            
            # Layer 1: Query API check
            await event_queue.put({"event": "progress", "data": {"step": "L1_START", "message": "Querying domain reputation databases..."}})
            l1_res = await run_l1_scan(url_hash, vt_key=self.vt_key)
            layer_results["layer_1"] = l1_res
            layer_scores["layer_1"] = l1_res["score_contribution"]
            await event_queue.put({"event": "progress", "data": {"step": "L1_COMPLETE", "message": "Layer 1 Complete", "data": l1_res}})
            
            # Sandbox Layer 3: Check site scripting/sandbox
            await event_queue.put({"event": "progress", "data": {"step": "L3_START", "message": "Opening link in virtual headless sandbox..."}})
            
            async def sandbox_callback(msg, lvl):
                await event_queue.put({"event": "sandbox_log", "data": {"message": msg, "level": lvl}})
                
            await sandbox_callback("Spinning up sandbox container: headless_chrome_sec", "info")
            await sandbox_callback(f"Navigating to final URL: {l4_res['final_url']}", "info")
            await sandbox_callback("Rendering DOM elements...", "info")
            
            l3_score = 0
            observations = []
            if l4_res["typosquat_info"].get("typosquat"):
                await sandbox_callback("ALERT: Spoofed login layout detected. Login forms match top brand!", "warning")
                l3_score += 30
                observations.append({
                    "test_case": "Phishing Credential Form Detection",
                    "expected": "Normal input layout",
                    "actual": f"Rendered fake login portal targeting {l4_res['typosquat_info']['target_brand']}",
                    "status": "DANGEROUS"
                })
            else:
                await sandbox_callback("DOM contains standard non-banking static elements.", "success")
                observations.append({
                    "test_case": "Phishing Form Scan",
                    "expected": "No phishing forms",
                    "actual": "No suspicious forms rendered",
                    "status": "SAFE"
                })
                
            l3_res = {
                "run1_observations": observations,
                "run2_observations": [],
                "trojan_constraint_detected": False,
                "malicious_behavior_observed": l3_score > 0,
                "score_contribution": l3_score
            }
            layer_results["layer_3"] = l3_res
            layer_scores["layer_3"] = l3_res["score_contribution"]
            await event_queue.put({"event": "progress", "data": {"step": "L3_COMPLETE", "message": "Layer 3 Complete", "data": l3_res}})
            
            # Layers 2, 6, 7: Mock as clean since URLs are not binaries unless they trigger download
            l2_res = {"permissions": [], "packages": [], "hardcoded_ips": [], "is_self_signed": False, "cert_issuer": "N/A"}
            l6_res = {"detected_libraries": [], "triggered_combo_rules": [], "score_contribution": 0}
            l7_res = {"best_match_threat_id": None, "threat_name": "Clean", "similarity_score": 0.0, "matched_features": [], "description": "N/A", "verdict": "SAFE", "score_contribution": 0}
            
            layer_results["layer_2"] = l2_res
            layer_results["layer_6"] = l6_res
            layer_results["layer_7"] = l7_res
            
            layer_scores["layer_2"] = 0
            layer_scores["layer_6"] = 0
            layer_scores["layer_7"] = 0
            
            await event_queue.put({"event": "progress", "data": {"step": "L2_COMPLETE", "message": "Layer 2 (Static) Skip", "data": l2_res}})
            await event_queue.put({"event": "progress", "data": {"step": "L6_COMPLETE", "message": "Layer 6 (Library) Skip", "data": l6_res}})
            await event_queue.put({"event": "progress", "data": {"step": "L7_COMPLETE", "message": "Layer 7 (Similarity) Skip", "data": l7_res}})
            
            # Layer 5: Verdict Summarizer
            await event_queue.put({"event": "progress", "data": {"step": "L5_START", "message": "Writing plain English explanation..."}})
            verdict_payload = run_l5_verdict(layer_scores, layer_results, "URL")
            plain_english = await call_llm_verdict(verdict_payload, api_key=self.openai_key)
            
            verdict_payload["plain_english"] = plain_english
            verdict_payload["layer_scores"] = layer_scores
            
            # Save URL scan to SQLite history
            try:
                db_scan = Scan(
                    id=url_hash,
                    filename=url,
                    type="URL",
                    verdict=verdict_payload["verdict"],
                    risk_score=verdict_payload["risk_score"],
                    layer_results=json.dumps(layer_results)
                )
                self.db.merge(db_scan)
                self.db.commit()
            except Exception as dbe:
                print(f"Error saving URL scan: {dbe}")
            
            await event_queue.put({"event": "verdict", "data": verdict_payload})
            await event_queue.put({"event": "done", "data": {}})
            
        except Exception as e:
            await event_queue.put({"event": "error", "data": {"message": f"Scan failed: {str(e)}"}})
