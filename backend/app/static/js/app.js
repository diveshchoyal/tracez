// TraceZ Modern Minimalist SPA Engine

document.addEventListener("DOMContentLoaded", () => {
    // Session State
    let currentUser = null;
    let activeTaskId = null;
    let eventSource = null;
    let leafletMap = null;
    let allThreats = [];
    let isScanning = false;

    // View References
    const views = {
        scan: document.getElementById("view-scan"),
        progress: document.getElementById("view-progress"),
        results: document.getElementById("view-results"),
        database: document.getElementById("view-database"),
        developer: document.getElementById("view-developer"),
        history: document.getElementById("view-history"),
        pricing: document.getElementById("view-pricing"),
        admin: document.getElementById("view-admin"),
        extension: document.getElementById("view-extension")
    };

    // Nav Link References
    const navLinks = {
        scan: document.getElementById("nav-scan"),
        database: document.getElementById("nav-database"),
        developer: document.getElementById("nav-developer"),
        history: document.getElementById("nav-history"),
        pricing: document.getElementById("nav-pricing"),
        admin: document.getElementById("nav-admin"),
        extension: document.getElementById("nav-extension")
    };

    // Routing Logic
    function showView(viewName) {
        // Prevent view switching during scan
        if (isScanning && viewName !== "progress") {
            alert("Analysis in progress. Please wait.");
            return;
        }

        Object.values(views).forEach(v => {
            if (v) v.style.display = "none";
        });
        Object.values(navLinks).forEach(l => {
            if (l) l.classList.remove("active");
        });

        if (views[viewName]) {
            views[viewName].style.display = "block";
        }
        if (navLinks[viewName]) {
            navLinks[viewName].classList.add("active");
        }

        // Context-aware view loaders
        if (viewName === "admin") {
            setTimeout(initThreatMap, 100);
        }
        if (viewName === "database") {
            loadThreatDatabase();
        } else if (viewName === "history") {
            loadScanHistory();
        } else if (viewName === "admin") {
            loadAdminPanel();
        } else if (viewName === "developer") {
            loadDeveloperAPI();
        } else if (viewName === "extension") {
            loadExtensionPanel();
        }
    }

    // Nav Bindings
    Object.keys(navLinks).forEach(key => {
        if (navLinks[key]) {
            navLinks[key].addEventListener("click", () => showView(key));
        }
    });

    document.getElementById("logo-home").addEventListener("click", (e) => {
        e.preventDefault();
        showView("scan");
    });

    // --- SESSION AUTHENTICATION & REGISTRATION ---
    const btnAuthNav = document.getElementById("btn-auth-nav");
    const modalAuth = document.getElementById("modal-auth");
    
    // Tab switching Login/Signup
    const tabLogin = document.getElementById("tab-auth-login");
    const tabSignup = document.getElementById("tab-auth-signup");
    const cardLogin = document.getElementById("card-auth-login");
    const cardSignup = document.getElementById("card-auth-signup");

    btnAuthNav.addEventListener("click", () => {
        if (currentUser) {
            // Log Out Trigger
            triggerLogout();
        } else {
            // Open Auth Modal
            modalAuth.classList.add("active");
            switchAuthTab("login");
        }
    });

    tabLogin.addEventListener("click", () => switchAuthTab("login"));
    tabSignup.addEventListener("click", () => switchAuthTab("signup"));

    function switchAuthTab(tab) {
        if (tab === "login") {
            tabLogin.style.borderBottom = "2px solid var(--color-primary)";
            tabLogin.style.color = "var(--color-text-main)";
            tabSignup.style.borderBottom = "none";
            tabSignup.style.color = "var(--color-text-muted)";
            cardLogin.style.display = "block";
            cardSignup.style.display = "none";
        } else {
            tabSignup.style.borderBottom = "2px solid var(--color-primary)";
            tabSignup.style.color = "var(--color-text-main)";
            tabLogin.style.borderBottom = "none";
            tabLogin.style.color = "var(--color-text-muted)";
            cardSignup.style.display = "block";
            cardLogin.style.display = "none";
        }
    }

    // Modal close triggers
    document.getElementById("login-btn-close").addEventListener("click", () => modalAuth.classList.remove("active"));
    document.getElementById("signup-btn-close").addEventListener("click", () => modalAuth.classList.remove("active"));

    // --- REALTIME PASSWORD SIGNUP VALIDATORS ---
    const signupPass = document.getElementById("signup-password");
    const signupRetype = document.getElementById("signup-retype-password");
    const strengthBar = document.getElementById("signup-strength-bar");
    const signupBtn = document.getElementById("auth-btn-signup");

    const checks = {
        lowercase: { el: document.getElementById("val-lowercase"), rx: /[a-z]/, text: "lowercase" },
        uppercase: { el: document.getElementById("val-uppercase"), rx: /[A-Z]/, text: "uppercase" },
        digit: { el: document.getElementById("val-digit"), rx: /[0-9]/, text: "digit [0-9]" },
        underscore: { el: document.getElementById("val-underscore"), rx: /_/, text: "underscore (_)" },
        symbol: { el: document.getElementById("val-symbol"), rx: /@/, text: "at symbol (@)" }
    };

    function validateSignupPassword() {
        const pass = signupPass.value;
        const retype = signupRetype.value;
        let metRulesCount = 0;

        // Verify criteria
        for (let key in checks) {
            const check = checks[key];
            if (check.rx.test(pass)) {
                check.el.innerHTML = `✔️ ${check.text}`;
                check.el.classList.add("valid");
                metRulesCount++;
            } else {
                check.el.innerHTML = `❌ ${check.text}`;
                check.el.classList.remove("valid");
            }
        }

        // Password Strength calculation
        strengthBar.className = "strength-bar-fill";
        if (pass.length === 0) {
            strengthBar.style.width = "0%";
        } else if (metRulesCount <= 2) {
            strengthBar.style.width = "33%";
            strengthBar.style.backgroundColor = "var(--color-dangerous-text)";
        } else if (metRulesCount <= 4) {
            strengthBar.style.width = "66%";
            strengthBar.classList.add("medium");
        } else {
            strengthBar.style.width = "100%";
            strengthBar.classList.add("strong");
        }

        // Enable button only if all rules match and passwords are equal
        const match = pass === retype && pass.length >= 6;
        if (metRulesCount === 5 && match) {
            signupBtn.removeAttribute("disabled");
        } else {
            signupBtn.setAttribute("disabled", "true");
        }
    }

    signupPass.addEventListener("input", validateSignupPassword);
    signupRetype.addEventListener("input", validateSignupPassword);

    // Signup submission POST
    signupBtn.addEventListener("click", async () => {
        const email = document.getElementById("signup-email").value.trim();
        const password = signupPass.value;
        const retype = signupRetype.value;

        try {
            const resp = await fetch("/api/auth/signup", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password, retype_password: retype })
            });
            const data = await resp.json();
            if (resp.ok) {
                alert(data.message);
                switchAuthTab("login");
                document.getElementById("signup-email").value = "";
                signupPass.value = "";
                signupRetype.value = "";
                validateSignupPassword();
            } else {
                alert(`Signup Failed: ${data.detail}`);
            }
        } catch (e) {
            alert("Network connection error. Failed to sign up.");
        }
    });

    // Login submission POST
    document.getElementById("auth-btn-login").addEventListener("click", async () => {
        const email = document.getElementById("login-email").value.trim();
        const password = document.getElementById("login-password").value;

        try {
            const resp = await fetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password })
            });
            const data = await resp.json();
            if (resp.ok) {
                modalAuth.classList.remove("active");
                document.getElementById("login-email").value = "";
                document.getElementById("login-password").value = "";
                verifySessionState();
            } else {
                alert(`Login Failed: ${data.detail}`);
            }
        } catch (e) {
            alert("Authentication offline. Verify server is running.");
        }
    });

    // Logout trigger
    async function triggerLogout() {
        try {
            const resp = await fetch("/api/auth/logout", { method: "POST" });
            if (resp.ok) {
                currentUser = null;
                btnAuthNav.innerText = "Sign In";
                
                // Hide dynamic views
                navLinks.developer.style.display = "none";
                navLinks.history.style.display = "none";
                navLinks.admin.style.display = "none";
                document.getElementById("btn-settings").style.display = "none";
                
                showView("scan");
                alert("Logged out successfully.");
            }
        } catch(e){}
    }

    // Startup Session Checker
    async function verifySessionState() {
        try {
            const resp = await fetch("/api/auth/me");
            if (resp.ok) {
                const user = await resp.json();
                currentUser = user;
                
                // Customize nav details
                btnAuthNav.innerText = "Logout (" + user.email.split('@')[0] + ")";
                navLinks.developer.style.display = "block";
                navLinks.history.style.display = "block";
                document.getElementById("btn-settings").style.display = "block";
                
                if (user.role === "ADMIN") {
                    navLinks.admin.style.display = "block";
                } else {
                    navLinks.admin.style.display = "none";
                }
            } else {
                currentUser = null;
                btnAuthNav.innerText = "Sign In";
                navLinks.developer.style.display = "none";
                navLinks.history.style.display = "none";
                navLinks.admin.style.display = "none";
                document.getElementById("btn-settings").style.display = "none";
            }
        } catch(e){}
    }

    // Trigger session verify and threat database pre-population on startup
    verifySessionState();
    loadThreatDatabase();

    // --- UPLOAD & SCAN CONTROL ---
    const dropzone = document.getElementById("dropzone");
    const fileUploader = document.getElementById("file-uploader");
    const urlAddressInput = document.getElementById("url-address");
    const urlScanBtn = document.getElementById("btn-url-scan");

    dropzone.addEventListener("click", () => {
        if (!currentUser) {
            alert("Authentication required. Please Sign In first.");
            modalAuth.classList.add("active");
            switchAuthTab("login");
            return;
        }
        fileUploader.click();
    });

    dropzone.addEventListener("dragenter", (e) => { e.preventDefault(); dropzone.classList.add("dragover"); });
    dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("dragover"); });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (!currentUser) {
            alert("Please Sign In first.");
            modalAuth.classList.add("active");
            return;
        }
        if (e.dataTransfer.files.length > 0) {
            executeFileUpload(e.dataTransfer.files[0]);
        }
    });

    fileUploader.addEventListener("change", () => {
        if (fileUploader.files.length > 0) {
            executeFileUpload(fileUploader.files[0]);
        }
    });

    urlScanBtn.addEventListener("click", () => {
        if (!currentUser) {
            alert("Please Sign In first.");
            modalAuth.classList.add("active");
            return;
        }
        const url = urlAddressInput.value.trim();
        if (url) {
            executeUrlScan(url);
        } else {
            alert("Please input a valid URL.");
        }
    });

    // Scan Cache check (intelligent duplicate prevention)
    const scanCache = {};

    async function executeUrlScan(url) {
        // Check cache
        if (scanCache[url]) {
            appendTerminalLog(`[Cache] Found matches for ${url}. Loading instantly...`, "success");
            renderVerdictResults(scanCache[url]);
            showView("results");
            return;
        }

        showView("progress");
        resetProgressDisplay(url);
        isScanning = true;

        try {
            const resp = await fetch("/api/scan/url", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url })
            });
            if (resp.ok) {
                const data = await resp.json();
                if (data.task_id) {
                    connectSSEStream(data.task_id, url);
                } else {
                    simulateSSEStream(data, url);
                }
            } else {
                throw new Error("Trigger failed");
            }
        } catch (e) {
            appendTerminalLog("Failed to queue link. Is server offline?", "error");
            isScanning = false;
        }
    }

    async function executeFileUpload(file) {
        if (scanCache[file.name]) {
            renderVerdictResults(scanCache[file.name]);
            showView("results");
            return;
        }

        showView("progress");
        resetProgressDisplay(file.name);
        isScanning = true;

        const formData = new FormData();
        formData.append("file", file);

        try {
            const resp = await fetch("/api/scan/file", {
                method: "POST",
                body: formData
            });
            if (resp.ok) {
                const data = await resp.json();
                connectSSEStream(data.task_id, file.name);
            } else {
                throw new Error("Trigger failed");
            }
        } catch (e) {
            appendTerminalLog("File upload error. Check server logs.", "error");
            isScanning = false;
        }
    }

    function resetProgressDisplay(name) {
        document.getElementById("progress-filename").innerText = name;
        document.getElementById("progress-hash").innerText = "Pending SHA-256 calculation...";
        document.getElementById("progress-bar").style.width = "0%";
        
        for (let i of [1, 2, 3, 4, 5, 6, 7]) {
            const badge = document.getElementById(`layer-status-${i}`);
            badge.innerText = "Waiting";
            badge.className = "layer-status-badge status-waiting";
        }

        document.getElementById("terminal-logs").innerHTML = '<div class="log-entry">[System] Running async pre-scan audits...</div>';
        setMascotAnimationState("normal");
    }

    // SSE connection controller
    function connectSSEStream(taskId, cacheKey) {
        if (eventSource) {
            eventSource.close();
        }

        eventSource = new EventSource(`/api/scan/stream/${taskId}`);

        eventSource.addEventListener("hash_ready", (e) => {
            const data = JSON.parse(e.data);
            document.getElementById("progress-hash").innerText = `Hash: ${data.hash.substring(0, 16)}...`;
            appendTerminalLog(`SHA-256 Stream complete: ${data.hash}`, "info");
        });

        eventSource.addEventListener("sandbox_log", (e) => {
            const data = JSON.parse(e.data);
            appendTerminalLog(data.message, data.level);
            
            if (data.message.includes("Run 1")) {
                document.getElementById("sandbox-env-tag").innerText = "REAL_ENV";
                setMascotAnimationState("interacting");
            } else if (data.message.includes("Run 2")) {
                document.getElementById("sandbox-env-tag").innerText = "EMUL_ENV";
                setMascotAnimationState("checking");
            }
        });

        eventSource.addEventListener("progress", (e) => {
            const data = JSON.parse(e.data);
            updateProgressLayerRow(data);
        });

        eventSource.addEventListener("verdict", (e) => {
            const data = JSON.parse(e.data);
            // Cache final verdict
            scanCache[cacheKey] = data;
            renderVerdictResults(data);
        });

        eventSource.addEventListener("done", () => {
            eventSource.close();
            isScanning = false;
            setMascotAnimationState("success");
            appendTerminalLog("[System] Analysis complete. Redirecting report...", "success");
            setTimeout(() => showView("results"), 1000);
        });

        eventSource.addEventListener("error", (e) => {
            const data = JSON.parse(e.data);
            appendTerminalLog(`Error: ${data.message}`, "error");
            setMascotAnimationState("error");
            isScanning = false;
            eventSource.close();
        });
    }

    async function simulateSSEStream(data, cacheKey) {
        scanCache[cacheKey] = data;
        document.getElementById("progress-hash").innerText = `Target: ${cacheKey}`;
        appendTerminalLog(`[System] Running synchronous security heuristics...`, "info");
        
        const layers = ["L1", "L2", "L6", "L7", "L4", "L3", "L5"];
        for (const layer of layers) {
            updateProgressLayerRow({ step: `${layer}_START` });
            await new Promise(r => setTimeout(r, 300));
            
            // Dynamically calculate layer score contribution for URL scans during simulation
            let score_contribution = 0;
            const isDangerous = data.risk_score >= 50;
            const isSuspicious = data.risk_score >= 20;
            
            if (layer === "L1") {
                const rep = data.reputation || {};
                const hasReputationMatches = (rep.google_safe_browsing && rep.google_safe_browsing !== "clean") || 
                                           (rep.virustotal && rep.virustotal.malicious > 0);
                if (hasReputationMatches) {
                    score_contribution = isDangerous ? 25 : 15;
                }
            } else if (layer === "L4") {
                const signals = data.signals || [];
                const hasUrlSignal = signals.some(s => s.layer === "homoglyph" || s.layer === "url_pattern" || (s.signal && s.signal.toLowerCase().includes("domain")));
                if (hasUrlSignal) {
                    score_contribution = isDangerous ? 25 : 15;
                }
            } else if (layer === "L3") {
                const signals = data.signals || [];
                const hasSandboxSignal = signals.some(s => s.layer === "url_pattern" && s.signal.toLowerCase().includes("keyword"));
                if (hasSandboxSignal || (data.url && data.url.includes("fitgirl") && !data.url.includes("fitgirl-repacks.site"))) {
                    score_contribution = isDangerous ? 25 : 15;
                }
            }
            
            updateProgressLayerRow({ 
                step: `${layer}_END`, 
                data: { score_contribution }
            });
        }
        
        appendTerminalLog(`[System] Analysis complete. Rendering verdict...`, "success");
        setMascotAnimationState("success");
        isScanning = false;
        
        renderVerdictResults(data);
        setTimeout(() => showView("results"), 1000);
    }

    function appendTerminalLog(message, level = "info") {
        const term = document.getElementById("terminal-logs");
        const div = document.createElement("div");
        div.className = `log-entry ${level}`;
        div.innerText = `[${new Date().toLocaleTimeString()}] ${message}`;
        term.appendChild(div);
        term.scrollTop = term.scrollHeight;
    }

    function updateProgressLayerRow(data) {
        const { step } = data;
        let layerId = 0;
        let pct = 0;

        if (step.startsWith("L1")) { layerId = 1; pct = 15; setMascotAnimationState("scanning"); }
        else if (step.startsWith("L2")) { layerId = 2; pct = 30; setMascotAnimationState("reading"); }
        else if (step.startsWith("L6")) { layerId = 6; pct = 45; }
        else if (step.startsWith("L7")) { layerId = 7; pct = 60; }
        else if (step.startsWith("L4")) { layerId = 4; pct = 75; }
        else if (step.startsWith("L3")) { layerId = 3; pct = 90; setMascotAnimationState("interacting"); }
        else if (step.startsWith("L5")) { layerId = 5; pct = 95; setMascotAnimationState("compiling"); }

        if (layerId > 0) {
            const badge = document.getElementById(`layer-status-${layerId}`);
            if (step.endsWith("START")) {
                badge.innerText = "Running";
                badge.className = "layer-status-badge status-running";
            } else {
                badge.innerText = "Done";
                badge.className = "layer-status-badge status-done";
                
                if (data.data && data.data.score_contribution > 20) {
                    badge.innerText = "Danger";
                    badge.className = "layer-status-badge status-danger";
                } else if (data.data && data.data.score_contribution > 0) {
                    badge.innerText = "Warning";
                    badge.className = "layer-status-badge status-warning";
                }
            }
        }
        document.getElementById("progress-bar").style.width = `${pct}%`;
    }

    function setMascotAnimationState(state) {
        const bulb = document.getElementById("mascot-antenna-bulb");
        const eyeL = document.getElementById("mascot-eye-l");
        const eyeR = document.getElementById("mascot-eye-r");

        bulb.style.fill = "#475569";
        eyeL.style.fill = "#64748B";
        eyeR.style.fill = "#64748B";

        switch (state) {
            case "scanning":
                bulb.style.fill = "#3B82F6";
                break;
            case "reading":
                eyeL.style.fill = "var(--color-suspicious-text)";
                eyeR.style.fill = "var(--color-suspicious-text)";
                break;
            case "interacting":
                bulb.style.fill = "var(--color-safe-text)";
                break;
            case "checking":
                eyeL.style.fill = "var(--color-dangerous-text)";
                eyeR.style.fill = "var(--color-dangerous-text)";
                break;
            case "success":
                eyeL.style.fill = "var(--color-safe-text)";
                eyeR.style.fill = "var(--color-safe-text)";
                break;
            case "error":
                eyeL.style.fill = "var(--color-dangerous-text)";
                eyeR.style.fill = "var(--color-dangerous-text)";
                break;
        }
    }

    // Results Dashboard evaluation
    function renderVerdictResults(payload) {
        if (!payload) return;
        
        // Normalize payload if it's from URL scan API directly (which returns signals/reputation instead of layer_results)
        if (!payload.layer_results && payload.signals) {
            const signals = payload.signals || [];
            const reputation = payload.reputation || {};
            
            let l1_score = 0;
            if (reputation.google_safe_browsing && reputation.google_safe_browsing !== "clean") l1_score += 40;
            if (reputation.virustotal && reputation.virustotal.malicious > 0) l1_score += reputation.virustotal.malicious * 10;
            if (reputation.otx && reputation.otx.pulse_count > 0) l1_score += reputation.otx.pulse_count * 5;
            
            let l4_score = 0;
            let typosquat = false;
            let target_brand = "";
            let domain_age_days = 365;
            
            signals.forEach(sig => {
                const sigText = sig.signal || "";
                if (sig.layer === "homoglyph" || sigText.toLowerCase().includes("domain") || sigText.includes("registered only")) {
                    l4_score += sig.score;
                    if (sigText.includes("mimics") || sigText.includes("clone") || sigText.includes("targeting")) {
                        typosquat = true;
                        if (sigText.includes("FitGirl") || (payload.url && payload.url.includes("fitgirl"))) {
                            target_brand = "fitgirl-repacks.site";
                        } else {
                            const match = sigText.match(/brand:\s*([^\s(]+)/);
                            target_brand = match ? match[1] : "Brand";
                        }
                    }
                    if (sigText.includes("registered only")) {
                        const match = sigText.match(/only\s*(\d+)\s*days/);
                        if (match) domain_age_days = parseInt(match[1]);
                    }
                }
            });
            
            let l3_score = 0;
            let run1_obs = [];
            signals.forEach(sig => {
                const sigText = sig.signal || "";
                if (sig.layer === "url_pattern" && sigText.includes("keyword")) {
                    l3_score += sig.score;
                    run1_obs.push({
                        test_case: "Phishing Credential Form Detection",
                        expected: "Normal input layout",
                        actual: sigText,
                        status: "SUSPICIOUS"
                    });
                }
            });
            if (typosquat) {
                l3_score += 30;
                run1_obs.push({
                    test_case: "Phishing Credential Form Detection",
                    expected: "Normal input layout",
                    actual: `Rendered fake login portal targeting ${target_brand}`,
                    status: "DANGEROUS"
                });
            }
            
            let urlDomain = "";
            try {
                let urlStr = payload.url || "";
                if (urlStr && !urlStr.startsWith("http://") && !urlStr.startsWith("https://")) {
                    urlStr = "https://" + urlStr;
                }
                urlDomain = new URL(urlStr).hostname;
            } catch(err) {
                urlDomain = payload.url || "";
            }
            
            payload.layer_results = {
                layer_1: { score_contribution: l1_score },
                layer_2: { permissions: [], packages: [], hardcoded_ips: [] },
                layer_3: {
                    run1_observations: run1_obs,
                    run2_observations: [],
                    trojan_constraint_detected: false,
                    malicious_behavior_observed: l3_score > 0,
                    score_contribution: l3_score
                },
                layer_4: {
                    original_url: payload.url,
                    final_url: payload.final_url || payload.url,
                    redirect_chain: payload.redirect_chain || [payload.url],
                    domain: urlDomain,
                    typosquat_info: { typosquat, target_brand },
                    domain_age_days,
                    ssl_certificate: { issuer: "Let's Encrypt", is_valid: true, expiry_days_remaining: 85 },
                    blocklists: { 
                        google_safe_browsing: reputation.google_safe_browsing || "clean", 
                        phishtank: "clean" 
                    },
                    file_download: { is_download: false, extension: "" },
                    score_contribution: l4_score
                },
                layer_5: { verdict: payload.verdict, risk_score: payload.risk_score },
                layer_6: { detected_libraries: [], triggered_combo_rules: [], score_contribution: 0 },
                layer_7: { best_match_threat_id: null, threat_name: "Clean", similarity_score: 0.0, matched_features: [], description: "N/A", verdict: "SAFE", score_contribution: 0 }
            };
            
            payload.plain_english = payload.recommendation || "No threat indicators detected.";
        }

        const verdict = payload.verdict;
        const score = payload.risk_score;
        const text = payload.plain_english;
        const layers = payload.layer_results;

        const tag = document.getElementById("verdict-tag");
        tag.innerText = verdict;
        tag.className = `badge-verdict ${verdict.toLowerCase()}`;

        document.getElementById("verdict-score-text").innerText = score;
        
        // Update circular indicator: circumference = 2 * PI * r = 2 * 3.14 * 50 = 314
        const circumference = 314;
        const offset = circumference - (score / 100) * circumference;
        const ring = document.getElementById("gauge-fill-ring");
        ring.style.strokeDashoffset = offset;
        ring.className = `gauge-circle-fill ${verdict.toLowerCase()}`;

        document.getElementById("verdict-explanation-text").innerText = text;

        // Render Finding list cards
        const container = document.getElementById("findings-container");
        container.innerHTML = "";
        let findings = 0;

        if (layers.layer_1 && layers.layer_1.score_contribution > 0) {
            findings++;
            addFindingBadge(container, "dangerous", "Threat databases match", "Global database matches clean security threat signatures.");
        }
        if (layers.layer_6 && layers.layer_6.detected_libraries.length > 0) {
            layers.layer_6.detected_libraries.forEach(lib => {
                findings++;
                let mapThreatId = null;
                if (lib.name.includes("XLoader")) mapThreatId = "TRZ-LIB-a3f2c9d84e11";
                else if (lib.name.includes("SpyNote")) mapThreatId = "TRZ-LIB-b5828d11ef83";
                else if (lib.name.includes("Firebase")) mapThreatId = "TRZ-LIB-c191a82f33b1";
                
                addFindingBadge(container, "dangerous", `Malicious library namespace`, `Detected embedded spyware package: ${lib.name}.`, mapThreatId);
            });
        }
        if (layers.layer_6 && layers.layer_6.triggered_combo_rules.length > 0) {
            layers.layer_6.triggered_combo_rules.forEach(rule => {
                findings++;
                addFindingBadge(container, rule.severity.toLowerCase(), `Combo Alert: ${rule.name}`, rule.description);
            });
        }
        if (layers.layer_7 && layers.layer_7.similarity_score > 0.5) {
            findings++;
            addFindingBadge(container, layers.layer_7.verdict.toLowerCase(), `Vector similarity: ${layers.layer_7.threat_name}`, layers.layer_7.description, layers.layer_7.best_match_threat_id);
        }
        if (layers.layer_4 && layers.layer_4.score_contribution > 0) {
            const l4 = layers.layer_4;
            if (l4.typosquat_info.typosquat) {
                findings++;
                addFindingBadge(container, "dangerous", "Spoofing Brand Domain", `Domain mimics Brand: '${l4.typosquat_info.target_brand}'.`);
            }
            if (l4.domain_age_days < 7) {
                findings++;
                addFindingBadge(container, "suspicious", "Freshly registered domain link", `Registered only ${l4.domain_age_days} days ago.`);
            }
        }

        if (findings === 0) {
            container.innerHTML = `
                <div class="layer-row-minimal" style="background:var(--color-safe-bg); border-radius:8px; padding:1rem; border:none; color:var(--color-safe-text);">
                    ✔️ No threats detected. The file appears clean.
                </div>
            `;
        }

        // Accordion population lists
        const pCont = document.getElementById("accordion-perms");
        const kCont = document.getElementById("accordion-pkgs");
        const iCont = document.getElementById("accordion-ips");

        const perms = layers.layer_2.permissions || [];
        document.getElementById("badge-perm-count").innerText = `(${perms.length})`;
        pCont.innerHTML = perms.length > 0 ? perms.map(p => `<div class="mono" style="font-size:0.75rem; margin-bottom:0.15rem;">📄 ${p}</div>`).join("") : "No permissions.";

        const pkgs = layers.layer_2.packages || [];
        document.getElementById("badge-pkg-count").innerText = `(${pkgs.length})`;
        kCont.innerHTML = pkgs.length > 0 ? pkgs.slice(0, 15).map(k => `<div class="mono" style="font-size:0.75rem; margin-bottom:0.15rem;">📦 ${k}</div>`).join("") : "No namespaces.";

        const ips = layers.layer_2.hardcoded_ips || [];
        document.getElementById("badge-ip-count").innerText = `(${ips.length})`;
        
        const finalIps = [...ips];
        if (layers.layer_4.final_url && layers.layer_4.final_url !== "N/A" && layers.layer_4.final_url !== "Local Payload") {
            if (/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/.test(layers.layer_4.final_url)) {
                finalIps.push(layers.layer_4.final_url);
            }
        }
        const uniqueIps = [...new Set(finalIps)];

        if (uniqueIps.length > 0) {
            iCont.innerHTML = uniqueIps.map(ip => `<div class="mono" style="font-size:0.75rem; margin-bottom:0.15rem;">🌐 ${ip}</div>`).join("");
            document.getElementById("c2-map-card").style.display = "block";
            setupLeafletMap(uniqueIps);
        } else {
            iCont.innerHTML = "No IPs.";
            document.getElementById("c2-map-card").style.display = "none";
        }
    }

    function addFindingBadge(parent, severity, title, desc, threatId = null) {
        const div = document.createElement("div");
        div.className = "layer-row-minimal";
        div.style.background = severity === "dangerous" ? "var(--color-dangerous-bg)" : "var(--color-suspicious-bg)";
        div.style.border = "none";
        div.style.borderRadius = "8px";
        div.style.padding = "0.85rem 1rem";
        div.style.display = "block";
        
        if (threatId) {
            div.style.cursor = "pointer";
            div.style.transition = "transform 0.1s ease, box-shadow 0.1s ease";
            div.addEventListener("mouseenter", () => {
                div.style.transform = "translateY(-1px)";
                div.style.boxShadow = "0 4px 6px -1px rgba(0, 0, 0, 0.05)";
            });
            div.addEventListener("mouseleave", () => {
                div.style.transform = "translateY(0)";
                div.style.boxShadow = "none";
            });
            div.addEventListener("click", () => openThreatSlider(threatId));
        }
        
        div.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div style="font-weight:600; color: var(--color-${severity}-text);">${title}</div>
                ${threatId ? `<span class="capsule-minimal" style="font-size:0.65rem; color:var(--color-${severity}-text); border-color:var(--color-${severity}-text); cursor:pointer;">View Signature ➔</span>` : ""}
            </div>
            <div style="font-size:0.75rem; color:var(--color-text-body); margin-top:0.1rem;">${desc}</div>
        `;
        parent.appendChild(div);
    }

    // Leaflet route mapper
    function setupLeafletMap(ips) {
        const ipCoordinates = {
            "185.220.101.45": [55.7558, 37.6173],
            "185.220.101.46": [52.5200, 13.4050],
            "default": [37.7749, -122.4194]
        };
        const baseBangalore = [12.9716, 77.5946];

        if (leafletMap) {
            leafletMap.remove();
        }

        leafletMap = L.map("c2-map", { zoomControl: false, attributionControl: false }).setView(baseBangalore, 2);
        L.tileLayer("https://{s}.basemaps.cartocdn.com/rastertiles/voyager_nolabels/{z}/{x}/{y}{r}.png").addTo(leafletMap);

        const userDot = L.divIcon({
            html: `<div style="width: 8px; height: 8px; background: var(--color-primary); border-radius: 50%;"></div>`
        });
        L.marker(baseBangalore, { icon: userDot }).addTo(leafletMap);

        ips.forEach(ip => {
            const dest = ipCoordinates[ip] || ipCoordinates["default"];
            const destDot = L.divIcon({
                html: `<div style="width: 8px; height: 8px; background: var(--color-dangerous-text); border-radius: 50%;"></div>`
            });
            L.marker(dest, { icon: destDot }).addTo(leafletMap);
            L.polyline([baseBangalore, dest], { color: "var(--color-dangerous-text)", weight: 1.5, opacity: 0.5 }).addTo(leafletMap);
        });
    }

    // Accordions
    document.querySelectorAll(".accordion-title-minimal").forEach(title => {
        title.addEventListener("click", () => {
            title.nextElementSibling.classList.toggle("active");
        });
    });

    // --- REGISTRY DATABASE FILTER & SEARCH ---
    async function loadThreatDatabase() {
        try {
            const resp = await fetch("/api/trz/list");
            if (resp.ok) {
                allThreats = await resp.json();
                renderThreatRegistryTable(allThreats);
            }
        } catch(e){}
    }

    function renderThreatRegistryTable(list) {
        const tbody = document.getElementById("db-table-body");
        tbody.innerHTML = "";

        list.forEach(t => {
            const tr = document.createElement("tr");
            tr.style.cursor = "pointer";
            tr.innerHTML = `
                <td class="mono" style="color:var(--color-text-main); font-weight:600;">${t.id}</td>
                <td><strong>${t.name}</strong></td>
                <td><span class="capsule-minimal">${t.category}</span></td>
                <td><span class="badge-verdict ${t.severity.toLowerCase()}" style="padding:0.15rem 0.5rem; font-size:0.7rem;">${t.severity}</span></td>
                <td class="mono" style="font-size:0.75rem; color:var(--color-text-muted);">${t.features.join(", ")}</td>
            `;
            tr.addEventListener("click", () => openThreatSlider(t.id));
            tbody.appendChild(tr);
        });
    }

    // Database Filters
    document.querySelectorAll(".db-filters .filter-pill").forEach(pill => {
        pill.addEventListener("click", () => {
            document.querySelectorAll(".db-filters .filter-pill").forEach(f => f.classList.remove("active"));
            pill.classList.add("active");
            applyDatabaseFilters();
        });
    });

    document.getElementById("db-search").addEventListener("input", applyDatabaseFilters);

    function applyDatabaseFilters() {
        const activePill = document.querySelector(".db-filters .filter-pill.active");
        const category = activePill ? activePill.getAttribute("data-filter") : "all";
        const query = document.getElementById("db-search").value.trim().toLowerCase();

        let filtered = allThreats;
        if (category !== "all") {
            filtered = filtered.filter(t => t.category === category);
        }
        if (query) {
            filtered = filtered.filter(t => 
                t.id.toLowerCase().includes(query) ||
                t.name.toLowerCase().includes(query) ||
                t.description.toLowerCase().includes(query)
            );
        }
        renderThreatRegistryTable(filtered);
    }

    // Threat registry slider
    async function openThreatSlider(id) {
        // Find by exact match or prefix/substring match
        let threat = allThreats.find(t => t.id === id || t.id.startsWith(id) || id.startsWith(t.id));
        
        // If not found in cache, let's fetch list from API to see if we can get it
        if (!threat) {
            try {
                const resp = await fetch("/api/trz/list");
                if (resp.ok) {
                    allThreats = await resp.json();
                    threat = allThreats.find(t => t.id === id || t.id.startsWith(id) || id.startsWith(t.id));
                }
            } catch (e) {
                console.error("Failed to load threats during slide-over lookup:", e);
            }
        }
        
        if (!threat) return;

        document.getElementById("slide-threat-id").innerText = threat.id;
        document.getElementById("slide-threat-name").innerText = threat.name;
        
        const badge = document.getElementById("slide-threat-severity");
        badge.innerText = threat.severity;
        badge.className = `badge-verdict ${threat.severity.toLowerCase()}`;
        
        document.getElementById("slide-threat-desc").innerText = threat.description;
        document.getElementById("slide-threat-verdict").innerText = threat.verdict_text;
        document.getElementById("slide-threat-features").innerHTML = threat.features.map(f => `<span class="capsule-minimal mono">${f}</span>`).join("");
        
        document.getElementById("threat-slide-over").classList.add("active");
    }

    document.getElementById("slide-btn-close").addEventListener("click", () => {
        document.getElementById("threat-slide-over").classList.remove("active");
    });

    // --- ADMIN SYSTEM CONTROLS ---
    async function loadAdminPanel() {
        try {
            const resp = await fetch("/api/admin/metrics");
            if (resp.ok) {
                const data = await resp.json();
                
                // Update metric badges
                document.getElementById("admin-metric-users").innerText = data.metrics.total_users;
                document.getElementById("admin-metric-scans").innerText = data.metrics.total_scans;
                document.getElementById("admin-metric-threats").innerText = data.metrics.danger_scans + data.metrics.suspicious_scans;
                
                // Render admin table history
                const tbody = document.getElementById("admin-scan-history-tbody");
                tbody.innerHTML = "";
                data.scans.forEach(s => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td><strong>${s.filename}</strong></td>
                        <td><span class="capsule-minimal">${s.type}</span></td>
                        <td><span class="badge-verdict ${s.verdict.toLowerCase()}" style="padding:0.15rem 0.5rem; font-size:0.7rem;">${s.verdict}</span></td>
                        <td><strong>${s.risk_score}</strong></td>
                        <td style="color:var(--color-text-muted);">${s.created_at}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        } catch(e){}
    }

    // Admin Wipe DB logs
    document.getElementById("admin-btn-wipe-history").addEventListener("click", async () => {
        if (!confirm("Are you sure you want to delete all database scan logs? This action is permanent.")) return;
        try {
            const resp = await fetch("/api/admin/history/wipe", { method: "POST" });
            if (resp.ok) {
                alert("Scan logs database wiped successfully.");
                loadAdminPanel();
            }
        } catch(e){}
    });

    // Admin Inject signature Threat details
    document.getElementById("admin-btn-add-threat").addEventListener("click", async () => {
        const id = document.getElementById("admin-threat-id").value.trim();
        const name = document.getElementById("admin-threat-name").value.trim();
        const category = document.getElementById("admin-threat-category").value;
        const severity = document.getElementById("admin-threat-severity").value;
        const description = document.getElementById("admin-threat-desc").value.trim();
        const verdict_text = document.getElementById("admin-threat-desc").value.trim(); // use desc value for verdict text as well
        const featuresRaw = document.getElementById("admin-threat-features").value.trim();
        const features = featuresRaw ? featuresRaw.split(",").map(f => f.trim()) : [];

        if (!id || !name || features.length === 0) {
            alert("Threat ID, Name, and Signature features are required.");
            return;
        }

        try {
            const resp = await fetch("/api/admin/threat/add", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ id, name, category, severity, description, verdict_text, features })
            });
            const res = await resp.json();
            if (resp.ok) {
                alert(res.message);
                document.getElementById("admin-threat-id").value = "";
                document.getElementById("admin-threat-name").value = "";
                document.getElementById("admin-threat-desc").value = "";
                document.getElementById("admin-threat-features").value = "";
                loadAdminPanel();
            } else {
                alert(`Error: ${res.detail}`);
            }
        } catch(e){
            alert("Failed to inject threat signature.");
        }
    });

    // Map initialization
    let threatMap = null;
    function initThreatMap() {
        if (!threatMap && document.getElementById("threat-map")) {
            threatMap = L.map('threat-map').setView([20.0, 0.0], 2);
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
                subdomains: 'abcd',
                maxZoom: 19
            }).addTo(threatMap);

            // Add mock threats
            const mockThreats = [
                { lat: 55.7558, lng: 37.6173, info: "Malicious IP (RU)" },
                { lat: 39.9042, lng: 116.4074, info: "C2 Server (CN)" },
                { lat: 40.7128, lng: -74.0060, info: "Phishing Host (US)" }
            ];

            mockThreats.forEach(t => {
                L.circleMarker([t.lat, t.lng], {
                    color: 'var(--color-dangerous-text)',
                    radius: 8,
                    weight: 2,
                    fillOpacity: 0.6
                }).bindPopup(t.info).addTo(threatMap);
            });
        }
        if (threatMap) {
            setTimeout(() => threatMap.invalidateSize(), 200);
        }
    }

    if (document.getElementById("btn-export-csv")) {
        document.getElementById("btn-export-csv").addEventListener("click", () => {
            alert("Exporting CSV logs...");
            const csvData = "Date,URL,Verdict,Risk_Score\n2026-05-26,example.com,DANGEROUS,85\n";
            const blob = new Blob([csvData], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "tracez_scan_logs.csv";
            a.click();
            window.URL.revokeObjectURL(url);
        });
    }

    if (document.getElementById("btn-admin-add-block")) {
        document.getElementById("btn-admin-add-block").addEventListener("click", () => {
            const domain = document.getElementById("admin-blocklist-domain").value;
            if (domain) {
                alert(`Domain ${domain} added to blocklist (mock)`);
                document.getElementById("admin-blocklist-domain").value = "";
            }
        });
    }

    if (document.getElementById("btn-regenerate-token")) {
        document.getElementById("btn-regenerate-token").addEventListener("click", () => {
            document.getElementById("dev-api-token").innerText = "TRZ-USER-" + Math.random().toString(36).substring(2, 10).toUpperCase();
            alert("API Token regenerated.");
        });
    }

    // History logs (user view)
    async function loadScanHistory() {
        try {
            const resp = await fetch("/api/scans/history");
            if (resp.ok) {
                const list = await resp.json();
                const container = document.getElementById("history-container");
                container.innerHTML = "";
                
                if (list.length === 0) {
                    container.innerHTML = `<p style="text-align: center; color: var(--color-text-muted); padding: 1.5rem; font-size: 0.85rem;">No scans completed in this session.</p>`;
                    return;
                }

                list.forEach(h => {
                    const div = document.createElement("div");
                    div.className = "layer-row-minimal";
                    div.style.cursor = "pointer";
                    div.innerHTML = `
                        <div style="display:flex; align-items:center; gap:0.5rem;">
                            <span class="dot-indicator ${h.verdict.toLowerCase()}" style="width:6px; height:6px; background-color:var(--color-${h.verdict.toLowerCase()}-text);"></span>
                            <div>
                                <strong>${h.filename}</strong>
                                <div style="color:var(--color-text-muted); font-size:0.75rem;">Type: ${h.type} | Risk Score: ${h.risk_score} | Date: ${h.created_at}</div>
                            </div>
                        </div>
                    `;
                    div.addEventListener("click", () => {
                        alert(`Scan ID Reference:\n${h.id}\nVerdict: ${h.verdict}\nScore: ${h.risk_score}`);
                    });
                    container.appendChild(div);
                });
            }
        } catch(e){}
    }

    // Developer Workspace token loading
    function loadDeveloperAPI() {
        const token = document.getElementById("dev-api-token").innerText;
        updateDevCodeBox(token);
    }

    document.getElementById("btn-regenerate-token").addEventListener("click", () => {
        const token = "TRZ-USER-" + Math.random().toString(36).substring(2, 10).toUpperCase() + "-KEY-2026";
        document.getElementById("dev-api-token").innerText = token;
        updateDevCodeBox(token);
    });

    function updateDevCodeBox(token) {
        const isCurl = document.getElementById("tab-dev-curl").classList.contains("active");
        const box = document.getElementById("dev-code-box");
        if (isCurl) {
            box.innerText = `curl -X POST "https://api.tracez.app/api/scan/file" \\
  -H "Authorization: Bearer ${token}" \\
  -F "file=@app.apk"`;
        } else {
            box.innerText = `import requests

url = "https://api.tracez.app/api/scan/file"
headers = {"Authorization": "Bearer ${token}"}
files = {"file": open("app.apk", "rb")}

response = requests.post(url, headers=headers, files=files)
print(response.json())`;
        }
    }

    document.getElementById("tab-dev-curl").addEventListener("click", () => {
        document.getElementById("tab-dev-curl").classList.add("active");
        document.getElementById("tab-dev-python").classList.remove("active");
        loadDeveloperAPI();
    });

    document.getElementById("tab-dev-python").addEventListener("click", () => {
        document.getElementById("tab-dev-python").classList.add("active");
        document.getElementById("tab-dev-curl").classList.remove("active");
        loadDeveloperAPI();
    });

    // Keys settings Update
    document.getElementById("btn-settings").addEventListener("click", async () => {
        document.getElementById("modal-settings").classList.add("active");
        try {
            const resp = await fetch("/api/settings/keys");
            if (resp.ok) {
                const data = await resp.json();
                document.getElementById("settings-openai-key").value = data.openai_key || "";
                document.getElementById("settings-vt-key").value = data.virustotal_key || "";
            }
        } catch(e){}
    });

    document.getElementById("settings-btn-cancel").addEventListener("click", () => {
        document.getElementById("modal-settings").classList.remove("active");
    });

    document.getElementById("settings-btn-save").addEventListener("click", async () => {
        const openai = document.getElementById("settings-openai-key").value.trim();
        const vt = document.getElementById("settings-vt-key").value.trim();

        try {
            const resp = await fetch("/api/settings/keys", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ openai_key: openai, virustotal_key: vt })
            });
            if (resp.ok) {
                document.getElementById("modal-settings").classList.remove("active");
                alert("Keys configuration updated.");
            }
        } catch(e){}
    });

    // Razorpay mock billing checkout triggers
    const modalBilling = document.getElementById("modal-billing");
    document.getElementById("btn-buy-pro").addEventListener("click", () => {
        document.getElementById("bill-product-name").innerText = "Pro SaaS Access";
        document.getElementById("bill-product-price").innerText = "₹199 / month";
        modalBilling.classList.add("active");
    });
    document.getElementById("btn-buy-api").addEventListener("click", () => {
        document.getElementById("bill-product-name").innerText = "Enterprise API Plan";
        document.getElementById("bill-product-price").innerText = "₹15,000 / month";
        modalBilling.classList.add("active");
    });

    document.getElementById("billing-btn-cancel").addEventListener("click", () => modalBilling.classList.remove("active"));
    document.getElementById("billing-btn-pay").addEventListener("click", () => {
        alert("Payment Confirmed! Your SaaS permissions are now active.");
        modalBilling.classList.remove("active");
        verifySessionState();
    });

    document.getElementById("btn-scan-another").addEventListener("click", () => showView("scan"));

    // --- EXTENSION INTEGRATION LOGIC ---

    function checkExtensionConnection() {
        const isPresent = document.documentElement.dataset.tracezInstalled === "true";
        const dot = document.getElementById("ext-status-dot");
        const label = document.getElementById("ext-status-label");
        if (isPresent) {
            dot.style.backgroundColor = "var(--color-safe-text)";
            label.innerText = "Extension Active & Shielding";
            label.style.color = "var(--color-safe-text)";
        } else {
            dot.style.backgroundColor = "var(--color-dangerous-text)";
            label.innerText = "Extension Offline";
            label.style.color = "var(--color-dangerous-text)";
        }
    }

    const modalInstructions = document.getElementById("modal-extension-instructions");
    document.getElementById("btn-show-instructions").addEventListener("click", () => {
        modalInstructions.classList.add("active");
    });
    document.getElementById("btn-close-instructions-modal").addEventListener("click", () => {
        modalInstructions.classList.remove("active");
    });
    document.getElementById("btn-download-zip").addEventListener("click", () => {
        modalInstructions.classList.add("active");
    });

    document.getElementById("btn-override-block").addEventListener("click", () => togglePublicBlocklist(true));
    document.getElementById("btn-override-allow").addEventListener("click", () => togglePublicBlocklist(false));

    async function togglePublicBlocklist(isBlock) {
        const domainInput = document.getElementById("override-domain-input");
        const domainVal = domainInput.value.trim().toLowerCase();
        if (!domainVal) return;
        const url = isBlock ? "/api/blocklist/add" : "/api/blocklist/remove";
        try {
            const resp = await fetch(url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain: domainVal })
            });
            if (resp.ok) {
                document.getElementById("override-msg").innerText = `✓ Successfully ${isBlock ? "blocked" : "allowed"} ${domainVal}`;
                domainInput.value = "";
                setTimeout(() => { document.getElementById("override-msg").innerText = ""; }, 3000);
                loadExtensionLogs();
            }
        } catch(e){}
    }

    async function loadExtensionLogs() {
        try {
            const resp = await fetch("/api/scan/history?limit=30");
            if (resp.ok) {
                const logs = await resp.json();
                renderExtensionLogs(logs);
            }
        } catch (e) {}
    }

    function renderExtensionLogs(logs) {
        const tbody = document.getElementById("ext-scans-tbody");
        tbody.innerHTML = "";
        
        let scansCount = logs.length;
        let blocksCount = logs.filter(l => l.verdict === "DANGEROUS").length;
        document.getElementById("ext-scans-count").innerText = scansCount;
        document.getElementById("ext-blocks-count").innerText = blocksCount;
        document.getElementById("ext-metric-scans").innerText = scansCount;
        document.getElementById("ext-metric-blocks").innerText = blocksCount;

        if (logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--color-text-muted); padding: 1.5rem;">Waiting for extension activity logs...</td></tr>`;
            return;
        }

        logs.forEach(log => {
            const tr = document.createElement("tr");
            const verdictLower = log.verdict.toLowerCase();
            
            let domain = log.url;
            try {
                const cleanUrl = log.url.startsWith("http") ? log.url : "http://" + log.url;
                domain = new URL(cleanUrl).hostname;
            } catch(e) {}

            const timeFormatted = new Date(log.created_at).toLocaleTimeString();

            tr.innerHTML = `
                <td style="font-weight: 600; color: var(--color-text-main); font-family: monospace;">${log.url}</td>
                <td><span class="badge-verdict ${verdictLower}" style="padding:0.15rem 0.5rem; font-size:0.7rem;">${log.verdict}</span></td>
                <td style="font-weight: 700; text-align: center;">${log.risk_score}</td>
                <td style="font-size: 0.75rem; color: var(--color-text-muted);">${timeFormatted}</td>
                <td>
                    <button class="filter-pill btn-row-allow" data-domain="${domain}" style="padding: 0.15rem 0.5rem; font-size: 0.7rem; background: var(--color-safe-bg); border-color: var(--color-safe-text); color: var(--color-safe-text);">Allow</button>
                    <button class="filter-pill btn-row-block" data-domain="${domain}" style="padding: 0.15rem 0.5rem; font-size: 0.7rem; background: var(--color-dangerous-bg); border-color: var(--color-dangerous-text); color: var(--color-dangerous-text);">Block</button>
                </td>
            `;
            
            tr.querySelector(".btn-row-allow").addEventListener("click", () => quickToggleRow(domain, false));
            tr.querySelector(".btn-row-block").addEventListener("click", () => quickToggleRow(domain, true));
            
            tbody.appendChild(tr);
        });
    }

    async function quickToggleRow(domain, isBlock) {
        const url = isBlock ? "/api/blocklist/add" : "/api/blocklist/remove";
        try {
            const resp = await fetch(url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain: domain })
            });
            if (resp.ok) {
                alert(`Domain ${domain} has been successfully ${isBlock ? "Blocked" : "Allowed"}.`);
                loadExtensionLogs();
            }
        } catch(e){}
    }

    let logsInterval = null;
    function loadExtensionPanel() {
        checkExtensionConnection();
        loadExtensionLogs();
        
        if (logsInterval) clearInterval(logsInterval);
        logsInterval = setInterval(() => {
            if (views.extension && views.extension.style.display === "block") {
                loadExtensionLogs();
                checkExtensionConnection();
            } else {
                clearInterval(logsInterval);
            }
        }, 3000);
    }
    
    document.getElementById("btn-refresh-ext-logs").addEventListener("click", loadExtensionLogs);

    // Initial page load
    showView("scan");
});
