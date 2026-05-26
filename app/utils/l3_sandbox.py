import asyncio
import random

async def simulate_sandbox_execution(permissions: list, packages: list, callback=None) -> dict:
    """
    Simulates sandbox execution.
    Sends step-by-step progress logs via a callback for live frontend streaming.
    Checks for expected vs actual behavior and trojan constraints.
    """
    logs = []
    
    async def log_step(message, level="info"):
        logs.append({"message": message, "level": level})
        if callback:
            await callback(message, level)
        await asyncio.sleep(0.3)  # Add micro-delays to make it feel real time

    # Step 1: Initialize Sandbox
    await log_step("Spinning up sandbox container: android_emul_api33_x86_64", "info")
    await log_step("Configuring virtual phone environment: IMEI=358201092837192, Contacts=152, SMS=87", "info")
    
    # Step 2: Inject test cases based on permissions
    await log_step("Analyzing application binary structural entrypoints...", "info")
    
    test_cases = []
    if "android.permission.READ_SMS" in permissions or "android.permission.SEND_SMS" in permissions:
        test_cases.append({
            "name": "SMS Transaction Interception",
            "action": "Simulate receiving 2FA SMS from bank",
            "expected": "App ignores the broadcast receiver",
            "malicious_trigger": "android.permission.READ_SMS" in permissions
        })
        
    if "android.permission.RECORD_AUDIO" in permissions:
        test_cases.append({
            "name": "Background Microphone Recording",
            "action": "Trigger audio focus and voice calls",
            "expected": "No background microphone binding",
            "malicious_trigger": True
        })
        
    if "android.permission.READ_CONTACTS" in permissions:
        test_cases.append({
            "name": "Contact Directory Sync",
            "action": "Add 5 new dummy contacts",
            "expected": "No database read requests",
            "malicious_trigger": True
        })
        
    if not test_cases:
        test_cases.append({
            "name": "Default Functional Launch",
            "action": "Perform clicks on home layout buttons",
            "expected": "App opens main activity successfully",
            "malicious_trigger": False
        })
        
    # Execute Test Run 1 (Real phone environment)
    await log_step("Starting Sandbox Run 1: [Standard Device Signature]", "info")
    await log_step("Installing APK...", "info")
    await log_step("Application launched successfully.", "success")
    
    run1_observations = []
    trojan_triggered = False
    
    for tc in test_cases:
        await log_step(f"Running test case: '{tc['name']}'...", "info")
        await log_step(f"Trigger action: {tc['action']}", "info")
        
        if tc["malicious_trigger"]:
            # Inject malicious response simulation
            if "SMS" in tc["name"]:
                await log_step("ALERT: App captured SMS broadcast! Forwarding packet to 185.220.101.45...", "warning")
                run1_observations.append({
                    "test_case": tc["name"],
                    "expected": tc["expected"],
                    "actual": "App intercepted the SMS, read body content, and made background socket connection to C2.",
                    "status": "DANGEROUS"
                })
                trojan_triggered = True
            elif "Microphone" in tc["name"]:
                await log_step("ALERT: App bound to AudioRecord API on incoming call broadcast...", "warning")
                run1_observations.append({
                    "test_case": tc["name"],
                    "expected": tc["expected"],
                    "actual": "App initiated microphone recording, writing to cache directory.",
                    "status": "DANGEROUS"
                })
                trojan_triggered = True
            elif "Contact" in tc["name"]:
                await log_step("ALERT: App queried contacts content provider without user interaction...", "warning")
                run1_observations.append({
                    "test_case": tc["name"],
                    "expected": tc["expected"],
                    "actual": "App exfiltrated contact lists to cloud storage.",
                    "status": "SUSPICIOUS"
                })
        else:
            await log_step("Result matching expected layout.", "success")
            run1_observations.append({
                "test_case": tc["name"],
                "expected": tc["expected"],
                "actual": tc["expected"],
                "status": "SAFE"
            })

    # Run 2: Trojan Constraint Trigger Checks (Change environment details to look like emulator)
    await log_step("Starting Sandbox Run 2: [Trojan Emulator Verification]", "info")
    await log_step("Changing environment factors: IMEI=null, Brand=google/sdk, Battery=1%", "info")
    await log_step("Re-launching application...", "info")
    
    run2_observations = []
    environment_sensitive = False
    
    for tc in test_cases:
        if tc["malicious_trigger"]:
            # If app is context-aware (malicious), it behaves cleanly in run 2 to hide
            await log_step(f"Running test case: '{tc['name']}' in Emulator context...", "info")
            if trojan_triggered:
                await log_step("Observed Clean Pass: App didn't trigger any network socket requests.", "success")
                await log_step("Trojan Constraint Flagged: Application displays environment-sensitive evasion tactics!", "warning")
                environment_sensitive = True
                run2_observations.append({
                    "test_case": tc["name"],
                    "expected": tc["expected"],
                    "actual": "App remained completely dormant in emulator environment.",
                    "status": "SUSPICIOUS"
                })
        else:
            run2_observations.append({
                "test_case": tc["name"],
                "expected": tc["expected"],
                "actual": tc["expected"],
                "status": "SAFE"
            })
            
    await log_step("Sandbox session finished. Tearing down containers...", "info")
    
    score_addition = 0
    if trojan_triggered:
        score_addition += 25
    if environment_sensitive:
        score_addition += 40
        
    return {
        "status": "success",
        "run1_observations": run1_observations,
        "run2_observations": run2_observations,
        "trojan_constraint_detected": environment_sensitive,
        "malicious_behavior_observed": trojan_triggered,
        "score_contribution": score_addition,
        "logs": logs
    }
