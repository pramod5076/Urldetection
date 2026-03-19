document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scan-form');
    const urlInput = document.getElementById('url-input');
    const scanBtn = document.getElementById('scan-btn');
    const btnText = document.querySelector('.btn-text');
    const btnSpinner = document.getElementById('btn-spinner');
    
    const statusMsg = document.getElementById('status-message');
    const statusText = document.getElementById('status-text');
    const urlError = document.getElementById('url-error'); // NEW
    const domainDatalist = document.getElementById('domain-suggestions'); // NEW

    // Suggestions List
    const commonDomains = ['google.com', 'facebook.com', 'netflix.com', 'paypal.com', 'amazon.com', 'microsoft.com', 'office.com', 'outlook.com', 'wellsfargo.com', 'chase.com', 'instagram.com', 'apple.com', 'gmail.com', 'twitter.com', 'linkedin.com', 'ebay.com'];
    if (domainDatalist) {
        domainDatalist.innerHTML = '';
        commonDomains.forEach(domain => {
            const option = document.createElement('option');
            option.value = domain;
            domainDatalist.appendChild(option);
        });
    }
    
    const resultsPanel = document.getElementById('results-panel');
    const scanTypeBadge = document.getElementById('scan-type-badge');
    const scannedTargetLabel = document.getElementById('scanned-target-label');
    const detailUrl = document.getElementById('detail-url');
    
    // Stats Elements
    const statMalicious = document.getElementById('stat-malicious');
    const statSuspicious = document.getElementById('stat-suspicious');
    const statHarmless = document.getElementById('stat-harmless');
    const statUndetected = document.getElementById('stat-undetected');
    
    // Verdict Elements
    const verdictBanner = document.getElementById('verdict-banner');
    const verdictIcon = document.getElementById('verdict-icon');
    const verdictTitle = document.getElementById('verdict-title');
    const verdictDesc = document.getElementById('verdict-desc');

    // Email UI Elements
    const tabUrl = document.getElementById('tab-url');
    const tabEmail = document.getElementById('tab-email');
    const emailForm = document.getElementById('email-form');
    const emailInput = document.getElementById('email-input');
    const emailScanBtn = document.getElementById('email-scan-btn');
    const emailBtnText = document.getElementById('email-btn-text');
    const emailSpinner = document.getElementById('email-spinner');
    
    // Alert Modal Elements
    const alertModal = document.getElementById('alert-modal');
    const closeAlertBtn = document.getElementById('close-alert-btn');
    const alertOverlay = document.querySelector('.alert-overlay');

    const hideAlert = () => {
        alertModal.classList.add('hidden');
    };

    const showPhishingAlert = (reason = null) => {
        if (reason) {
            document.querySelector('.alert-message').innerText = reason;
        }
        alertModal.classList.remove('hidden');
    };

    closeAlertBtn.addEventListener('click', hideAlert);
    alertOverlay.addEventListener('click', hideAlert);

    // Tab Switching
    tabUrl.addEventListener('click', () => {
        tabUrl.classList.add('active');
        tabEmail.classList.remove('active');
        form.classList.remove('hidden');
        emailForm.classList.add('hidden');
        resultsPanel.classList.add('hidden');
    });

    tabEmail.addEventListener('click', () => {
        tabEmail.classList.add('active');
        tabUrl.classList.remove('active');
        emailForm.classList.remove('hidden');
        form.classList.add('hidden');
        resultsPanel.classList.add('hidden');
    });

    // --- Automatic URL Extractor (Live Detection) ---
    const liveDetection = document.getElementById('live-detection');
    const detectedUrlsList = document.getElementById('detected-urls-list');

    emailInput.addEventListener('input', () => {
        const text = emailInput.value.trim();
        if (!text) {
            liveDetection.classList.add('hidden');
            detectedUrlsList.innerHTML = '';
            return;
        }

        // Regex for URL extraction
        const urlPattern = /https?:\/\/(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"<>]+/g;
        const matches = text.match(urlPattern);

        if (matches && matches.length > 0) {
            liveDetection.classList.remove('hidden');
            
            // Extract unique domains
            const domains = [...new Set(matches.map(url => {
                try {
                    const domain = new URL(url).hostname;
                    return domain;
                } catch(e) {
                    // Fallback for malformed URLs
                    return url.replace(/https?:\/\//, '').split('/')[0];
                }
            }))];

            // Update UI
            detectedUrlsList.innerHTML = domains.map(domain => `
                <div class="url-badge">${domain}</div>
            `).join('');
        } else {
            liveDetection.classList.add('hidden');
            detectedUrlsList.innerHTML = '';
        }
    });

    // Hide error on input
    urlInput.addEventListener('input', () => {
        urlError.classList.add('hidden');
    });

    function isValidUrlOrDomain(input) {
        // Broad regex for domains and URLs (handles both netflix.com and https://netflix.com)
        const domainPattern = /^(https?:\/\/)?([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}(\/.*)?$/i;
        // IP address regex
        const ipPattern = /^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:[0-9]+)?(\/.*)?$/;
        return domainPattern.test(input) || ipPattern.test(input);
    }

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        let urlToAnalyze = urlInput.value.trim();
        
        if (!urlToAnalyze) return;

        // --- NEW: URL Validation ---
        if (!isValidUrlOrDomain(urlToAnalyze)) {
            urlError.classList.remove('hidden');
            urlInput.focus();
            return;
        }

        urlError.classList.add('hidden');

        // Normalize URL: if no protocol is present, prepend https://
        if (!urlToAnalyze.startsWith('http://') && !urlToAnalyze.startsWith('https://')) {
            urlToAnalyze = 'https://' + urlToAnalyze;
        }

        // Reset UI
        resultsPanel.classList.add('hidden');
        scanTypeBadge.innerText = 'URL Scan';
        scannedTargetLabel.innerText = 'Scanned URL';
        document.getElementById('domain-info-row').style.display = 'none';
        document.getElementById('ssl-info-row').style.display = 'none';
        document.getElementById('similarity-info-row').style.display = 'none';
        document.getElementById('screenshot-section').style.display = 'none';
        setLoading(true, false);

        try {
            // First submit URL to backend
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: urlToAnalyze })
            });
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Failed to scan URL");
            }

            let domainInfo = null;
            let sslInfo = null;
            let similarityInfo = null;
            try {
                // Fetch Domain Info, SSL Info and Similarity Info in parallel
                const [domainRes, sslRes, similarityRes] = await Promise.all([
                    fetch('/api/domain_info', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: urlToAnalyze })
                    }),
                    fetch('/api/ssl_info', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: urlToAnalyze })
                    }),
                    fetch('/api/domain_similarity', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: urlToAnalyze })
                    })
                ]);
                
                if(domainRes.ok) domainInfo = await domainRes.json();
                if(sslRes.ok) sslInfo = await sslRes.json();
                if(similarityRes.ok) similarityInfo = await similarityRes.json();
                
            } catch(e) {
                console.warn("Could not fetch auxiliary info", e);
            }

            // Fire off the screenshot analysis asynchronously (don't block the main flow)
            fetchScreenshotAnalysis(urlToAnalyze);

            if (data.status === 'found') {
                // We got the report directly
                renderStats(data.data.attributes.last_analysis_stats, urlToAnalyze, data.data.attributes.last_analysis_results, [], domainInfo, sslInfo, similarityInfo);
                setLoading(false);
            } 
            else if (data.status === 'scanning' && data.analysis_id) {
                // VT returns an analysis_id, we need to poll
                pollAnalysis(data.analysis_id, urlToAnalyze, 0, domainInfo, sslInfo, similarityInfo);
            }
            else {
                throw new Error("Unexpected server response");
            }
            
        } catch (error) {
            setLoading(false, false);
            alert(`Error: ${error.message}`);
        }
    });

    // Handle Email Form Submit
    emailForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const contentToAnalyze = emailInput.value.trim();
        if(!contentToAnalyze) return;

        // Reset UI
        resultsPanel.classList.add('hidden');
        scanTypeBadge.innerText = 'Email Content Scan';
        scannedTargetLabel.innerText = 'Extracted URLs';
        document.getElementById('domain-info-row').style.display = 'none';
        document.getElementById('ssl-info-row').style.display = 'none';
        document.getElementById('similarity-info-row').style.display = 'none';
        document.getElementById('screenshot-section').style.display = 'none';
        setLoading(true, true);

        try {
            // Submit email text to backend
            const response = await fetch('/api/scan_email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content: contentToAnalyze })
            });
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Failed to parse email");
            }

            if (data.status === 'clean' || data.urls.length === 0) {
                // No URLs found
                renderStats({malicious: 0, suspicious: 0, harmless: 0, undetected: 0}, "No links found in email.", null);
                setLoading(false, true);
                return;
            }

            // We have URLs, now we must scan them sequentially or handle the batch
            // For simplicity and to not hang the frontend UI, we'll scan the first URL found initially, 
            // or scan them and aggregate the risk.
            statusText.innerText = `Extracting ${data.urls.length} URLs... Initiating scans.`;
            
            // Collect overall stats
            let aggStats = {malicious: 0, suspicious: 0, harmless: 0, undetected: 0};
            let allEngineResults = {};
            let combinedTargetText = data.urls.join('\n');
            let detectedKeywords = data.keywords || [];

            let scanPromises = data.urls.map(url => fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            }).then(r => r.json()));

            let scanResults = await Promise.all(scanPromises);

            // Helper to poll individual analyses within the batch
            async function pollSingleAnalysis(analysisId, maxAttempts = 12) {
                for (let i = 0; i < maxAttempts; i++) {
                    const res = await fetch(`/api/analysis/${analysisId}`);
                    const data = await res.json();
                    if (!res.ok) throw new Error("Failed to fetch analysis");
                    
                    if (data.data.attributes.status === 'completed') {
                        return {
                            stats: data.data.attributes.stats,
                            results: data.data.attributes.results
                        };
                    }
                    // Wait 5 seconds before next poll
                    await new Promise(resolve => setTimeout(resolve, 5000));
                }
                return null; // Timed out
            }

            // Process all results (including polling pending ones)
            statusText.innerText = `Analyzing ${scanResults.length} URLs... this may take a moment.`;
            
            for (let res of scanResults) {
                let st = null;
                let engResults = null;

                if (res.status === 'found') {
                    st = res.data.attributes.last_analysis_stats;
                    engResults = res.data.attributes.last_analysis_results;
                } else if (res.status === 'scanning' && res.analysis_id) {
                    // Poll for this specific URL until it finishes
                    const polledData = await pollSingleAnalysis(res.analysis_id);
                    if (polledData) {
                        st = polledData.stats;
                        engResults = polledData.results;
                    } else {
                        // Timeout on this specific URL
                        aggStats.undetected += 1;
                        continue;
                    }
                }

                if (st) {
                    aggStats.malicious += st.malicious || 0;
                    aggStats.suspicious += st.suspicious || 0;
                    aggStats.harmless += st.harmless || 0;
                    aggStats.undetected += st.undetected || 0;
                }
                if (engResults) {
                    allEngineResults = { ...allEngineResults, ...engResults };
                }
            }

            renderStats(aggStats, combinedTargetText, allEngineResults, detectedKeywords, null, null, null);
            setLoading(false, true);

        } catch (error) {
            setLoading(false, true);
            alert(`Error: ${error.message}`);
        }
    });

    async function fetchScreenshotAnalysis(url) {
        const screenshotSection = document.getElementById('screenshot-section');
        const loadingContainer = document.getElementById('screenshot-loading-container');
        const progressBar = document.getElementById('screenshot-progress-bar');
        const progressText = document.getElementById('screenshot-progress-text');
        
        const verdictText = document.getElementById('cv-verdict-text');
        const brandText = document.getElementById('cv-brand-text');
        const siteScreenshot = document.getElementById('site-screenshot');
        const imageLoader = document.getElementById('image-loader-overlay');

        // Show section and loading UI immediately
        screenshotSection.style.display = 'block';
        loadingContainer.style.display = 'block';
        imageLoader.style.display = 'flex';
        
        // Clear previous/placeholder state
        verdictText.innerText = 'Analyzing Content...';
        brandText.innerText = 'Scanning UI...';
        siteScreenshot.style.opacity = '0.3';
        // Transparent 1x1 GIF to clear old image
        siteScreenshot.src = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';
        
        progressBar.style.width = '0%';
        progressText.innerText = '0%';
        loadingContainer.style.display = 'block'; // Ensure loading is visible

        // Simulated progress animation (0 to 95% over 4s)
        let startTime = Date.now();
        let duration = 4000; // 4 seconds (much more responsive)
        let progressInterval = setInterval(() => {
            let elapsed = Date.now() - startTime;
            let progress = Math.min((elapsed / duration) * 95, 95);
            progressBar.style.width = progress + '%';
            progressText.innerText = Math.floor(progress) + '%';
            
            if (progress >= 95) clearInterval(progressInterval);
        }, 100);

        try {
            const res = await fetch('/api/screenshot_analysis', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            
            clearInterval(progressInterval);
            
            if(res.ok) {
                // Snap to 100%
                progressBar.style.width = '100%';
                progressText.innerText = '100%';
                
                const data = await res.json();
                setTimeout(() => {
                    loadingContainer.style.display = 'none';
                    imageLoader.style.display = 'none';
                    renderScreenshotDetails(data);
                }, 400);
            } else {
                clearInterval(progressInterval);
                loadingContainer.style.display = 'none';
                imageLoader.style.display = 'none';
                verdictText.innerText = 'Analysis Unavailable';
                brandText.innerText = 'Server Error (500)';
                siteScreenshot.style.opacity = '0.1';
            }
        } catch (e) {
            clearInterval(progressInterval);
            loadingContainer.style.display = 'none';
            if(imageLoader) imageLoader.style.display = 'none';
            console.warn("Screenshot analysis failed", e);
        }
    }

    // We do not poll domainInfo or sslInfo for *batch emails* to save performance. So we pass them as null for batches.
    async function pollAnalysis(analysisId, urlToAnalyze, attempts = 0, domainInfo = null, sslInfo = null, similarityInfo = null) {
        if (attempts > 12) { // Poll for ~60 seconds max
            setLoading(false);
            alert("Analysis is taking longer than expected. Please try scanning again.");
            return;
        }

        try {
            const res = await fetch(`/api/analysis/${analysisId}`);
            const data = await res.json();

            if (!res.ok) throw new Error(data.error || "Failed to fetch analysis");

            const status = data.data.attributes.status;

            if (status === 'completed') {
                renderStats(data.data.attributes.stats, urlToAnalyze, data.data.attributes.results, [], domainInfo, sslInfo, similarityInfo);
                setLoading(false);
            } else {
                // still queued or in-progress
                statusText.innerText = `Analyzing URL (${status})... please wait.`;
                setTimeout(() => pollAnalysis(analysisId, urlToAnalyze, attempts + 1, domainInfo, sslInfo, similarityInfo), 5000); // 5 sec interval
            }
        } catch(err) {
            setLoading(false);
            alert(`Error pulling results: ${err.message}`);
        }
    }

    function renderStats(stats, scannedUrl, engineResults = null, detectedKeywords = [], domainInfo = null, sslInfo = null, similarityInfo = null) {
        resultsPanel.classList.remove('hidden');
        detailUrl.innerText = scannedUrl;

        // Render specific detections
        const detectionsContainer = document.getElementById('detections-container');
        const detectionsList = document.getElementById('detections-list');
        const threatCount = document.getElementById('threat-count');
        
        if (detectionsList && detectionsContainer && threatCount) {
            detectionsList.innerHTML = '';
            let count = 0;

            if (engineResults) {
                for (const [engine, details] of Object.entries(engineResults)) {
                    if (details.category === 'malicious' || details.category === 'suspicious') {
                        if (details.result && details.result !== 'clean') {
                            count++;
                            const li = document.createElement('li');
                            li.className = `detection-item ${details.category === 'suspicious' ? 'suspicious-item' : ''}`;
                            li.innerHTML = `<span class="detection-engine">${engine}</span> <span class="detection-result">${details.result}</span>`;
                            detectionsList.appendChild(li);
                        }
                    }
                }
            }

            if (count > 0) {
                detectionsContainer.classList.remove('hidden');
                threatCount.innerText = count;
            } else {
                detectionsContainer.classList.add('hidden');
            }
        }

        // Ensure stats aren't undefined
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const harmless = stats.harmless || 0;
        const undetected = stats.undetected || 0;
        const total = malicious + suspicious + harmless + undetected;

        // Calculate and Render Risk Score
        const riskCircle = document.getElementById('risk-circle');
        const riskText = document.getElementById('risk-text');
        
        // Base score from engine results
        let baseScore = 0;
        if (total > 0) {
            // Give malicious hits 4x weight, suspicious 1.5x weight
            const weightedThreats = (malicious * 4) + (suspicious * 1.5);
            // Cap engine-based contribution at 70% if no critical CV detection
            baseScore = Math.min(70, Math.ceil((weightedThreats / total) * 100));
            
            // If strictly malicious engines are found, floor the score at 40% (Suspicious)
            if (malicious > 0 && baseScore < 40) baseScore = 40;
        }

        let riskScore = baseScore;

        // --- Add Penalties (Cumulative but capped) ---
        let totalPenalty = 0;

        // Keyword penalty
        if (detectedKeywords && detectedKeywords.length > 0) {
            totalPenalty += Math.min(25, detectedKeywords.length * 8);
        }

        // Domain Age penalty
        if (domainInfo && domainInfo.risk === 'HIGH') {
            totalPenalty += 20;
        }

        // SSL penalty
        if (sslInfo && !sslInfo.valid) {
            totalPenalty += 25;
        }

        // Similarity penalty
        if (similarityInfo && similarityInfo.is_typosquat) {
            totalPenalty += 35;
        }

        riskScore = Math.min(100, riskScore + totalPenalty);

        // Apply Classification logic: 0-20 Safe, 20-50 Suspicious, 50-100 Phishing
        let classificationText = '';
        let classificationDesc = '';
        let classificationIcon = '';

        // --- NEW: Dynamic Verdict Reasoning ---
        const verdictReasons = [];
        if (malicious > 0) verdictReasons.push(`${malicious} security engine(s) flagged this as malicious.`);
        if (suspicious > 0) verdictReasons.push(`${suspicious} security engine(s) flagged this as suspicious.`);
        if (domainInfo && domainInfo.risk === 'HIGH') {
            verdictReasons.push(domainInfo.is_ip ? "Raw IP address used instead of domain name." : "Domain is very new (less than 30 days old).");
        }
        if (sslInfo && !sslInfo.valid) verdictReasons.push(`SSL Certificate issue: ${sslInfo.error || "Invalid or missing certificate"}.`);
        if (similarityInfo && similarityInfo.is_typosquat) verdictReasons.push(`Typosquatting detected: Mimics ${similarityInfo.matches[0].mimicked_domain}.`);
        if (detectedKeywords && detectedKeywords.length > 0) verdictReasons.push(`Suspicious phishing keywords found in content.`);

        let riskColor = '#00ff88'; // Default Green (Safe)
        if (riskScore >= 60) {
            riskColor = '#ff3366'; // Red
            classificationText = 'Phishing / Malicious';
            classificationDesc = `Danger: High risk score (${riskScore}%). ` + (verdictReasons.length > 0 ? "Detected Threats: " + verdictReasons.join(" | ") : "Multiple phishing traits detected.");
            classificationIcon = '🚨';
            verdictBanner.className = 'verdict danger';
            showPhishingAlert(classificationDesc); // TRIGGER POPUP with reasons
        } else if (riskScore >= 30) {
            riskColor = '#ff9900'; // Orange
            classificationText = 'Suspicious';
            classificationDesc = `Warning: Elevated risk score (${riskScore}%). ` + (verdictReasons.length > 0 ? "Warnings: " + verdictReasons.join(" | ") : "Potential threats detected.");
            classificationIcon = '⚠️';
            verdictBanner.className = 'verdict warning';
        } else {
            riskColor = '#00ff88'; // Green
            classificationText = 'Safe';
            classificationDesc = `Safe: Low risk score (${riskScore}%). No significant threats detected.`;
            classificationIcon = '✅';
            verdictBanner.className = 'verdict'; // Reset to default green
        }

        // Stroke dasharray works on percentage (0 to 100)
        const riskPercentage = riskScore;
        
        setTimeout(() => {
            if(riskCircle && riskText) {
                riskCircle.style.strokeDasharray = `${riskPercentage}, 100`;
                riskCircle.style.stroke = riskColor;
                
                // Animate text
                animateValue(riskText, 0, riskScore, Math.max(500, riskPercentage * 15), true);
            }
        }, 300);

        // Trigger counting animation
        animateValue(statMalicious, 0, malicious, 1000);
        animateValue(statSuspicious, 0, suspicious, 1000);
        animateValue(statHarmless, 0, harmless, 1000);
        animateValue(statUndetected, 0, undetected, 1000);

        // Update Verdict UI based on classification
        verdictIcon.innerText = classificationIcon;
        verdictTitle.innerText = classificationText;
        verdictDesc.innerText = classificationDesc;
        
        // --- NEW: Render Domain Info Details ---
        const domainInfoRow = document.getElementById('domain-info-row');
        const domainDetails = document.getElementById('domain-details');
        
        if (domainInfo && !domainInfo.error) {
            domainInfoRow.style.display = 'flex';
            let riskColor = domainInfo.risk === 'HIGH' ? 'var(--acc-red)' : 'var(--acc-cyan)';

            let createdText = '';
            let createdClass = '';
            let createdTooltip = '';

            if (domainInfo.is_ip) {
                createdText = 'Raw IP Address Detected 🚨';
                createdClass = 'val-danger';
                createdTooltip = "Phishing sites often use raw IPs to hide their identity.";
            } else {
                createdText = domainInfo.age_days === 'Unknown' ? 'Unknown' : `${domainInfo.age_days} days ago (${domainInfo.creation_date})`;
                createdClass = domainInfo.risk === 'HIGH' ? 'val-danger' : ''; // Apply danger class if high risk
            }

            domainDetails.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 4px;">
                    <div><span style="color: var(--text-muted); font-size: 0.85rem;">Domain:</span> <span style="font-family: 'JetBrains Mono', monospace;">${domainInfo.domain}</span></div>
                    <div><span style="color: var(--text-muted); font-size: 0.85rem;">Created:</span> <span class="${createdClass}" title="${createdTooltip}">${createdText}</span></div>
                    <div><span style="color: var(--text-muted); font-size: 0.85rem;">Domain Risk:</span> <strong style="color: ${riskColor};">${domainInfo.risk}</strong></div>
                </div>
            `;
        } else {
            domainInfoRow.style.display = 'none';
        }

        // --- NEW: Render SSL Details ---
        const sslInfoRow = document.getElementById('ssl-info-row');
        const sslDetails = document.getElementById('ssl-details');

        if (sslInfo && !sslInfo.error_internal) {
            sslInfoRow.style.display = 'flex';
            let sslStatusText = sslInfo.valid ? 'VALID' : 'INVALID';
            let sslColor = sslInfo.valid ? 'var(--acc-cyan)' : 'var(--acc-red)';
            
            // Format days cleanly
            let expiresText = sslInfo.expires_in_days + ' days';
            if (sslInfo.expires_in_days < 0) expiresText = 'Expired';
            if (sslInfo.issuer === 'Connection Timeout' || sslInfo.issuer.includes('Error')) expiresText = 'N/A';

            sslDetails.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 4px;">
                    <div><span style="color: var(--text-muted); font-size: 0.85rem;">SSL:</span> <strong style="color: ${sslColor};">${sslStatusText}</strong></div>
                    <div><span style="color: var(--text-muted); font-size: 0.85rem;">Issuer:</span> <span>${sslInfo.issuer}</span></div>
                    <div><span style="color: var(--text-muted); font-size: 0.85rem;">Expires:</span> <span>${expiresText}</span></div>
                </div>
            `;
        } else {
            sslInfoRow.style.display = 'none';
        }

        // --- NEW: Render Similarity Details ---
        const similarityInfoRow = document.getElementById('similarity-info-row');
        const similarityDetails = document.getElementById('similarity-details');

        if (similarityInfo && similarityInfo.is_typosquat) {
            similarityInfoRow.style.display = 'flex';
            const topMatch = similarityInfo.matches[0];
            similarityDetails.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 4px;">
                    <div><span style="color: var(--text-muted); font-size: 0.85rem;">Detected Mimicry:</span> <strong style="color: var(--acc-red);">Highly Suspicious</strong></div>
                    <div><span style="color: var(--text-muted); font-size: 0.85rem;">Target Brand:</span> <strong style="color: var(--acc-cyan);">${topMatch.mimicked_domain}</strong></div>
                    <div><span style="color: var(--text-muted); font-size: 0.85rem;">Levenshtein Dist:</span> <span>${topMatch.distance} characters</span></div>
                </div>
            `;
        } else {
            similarityInfoRow.style.display = 'none';
        }

        // --- NEW: Render Keywords in details section ---
        // First cleanup old keyword rows if they exist
        const oldKeywordRow = document.getElementById('keyword-detail-row');
        if (oldKeywordRow) {
            oldKeywordRow.remove();
        }

        if (detectedKeywords && detectedKeywords.length > 0) {
            const detailsGrid = document.querySelector('.details-grid');
            if (detailsGrid) {
                const keywordRow = document.createElement('div');
                keywordRow.className = 'detail-row';
                keywordRow.id = 'keyword-detail-row';
                
                // Format keywords into nice badges
                const keywordBadges = detectedKeywords.map(kw => `<span style="background: rgba(255, 153, 0, 0.2); color: var(--acc-orange); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(255,153,0,0.4); margin-right: 4px; display: inline-block; margin-bottom: 4px; font-size: 0.8rem;">${kw}</span>`).join('');

                keywordRow.innerHTML = `
                    <span class="detail-label" style="color: var(--acc-orange);">Suspicious Keywords</span>
                    <div class="detail-value" style="display: flex; flex-wrap: wrap;">${keywordBadges}</div>
                `;
                detailsGrid.appendChild(keywordRow);
            }
        }

        // Scroll to results softly
        resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // --- NEW: Render Screenshot Details asynchronously ---
    function renderScreenshotDetails(data) {
        const screenshotSection = document.getElementById('screenshot-section');
        const imgEl = document.getElementById('site-screenshot');
        const verdictText = document.getElementById('cv-verdict-text');
        const brandText = document.getElementById('cv-brand-text');
        
        screenshotSection.style.display = 'block';
        imgEl.src = 'data:image/png;base64,' + data.screenshot_base64;
        imgEl.style.opacity = '1';
        
        const cv = data.cv_analysis;
        verdictText.innerText = cv.verdict;
        brandText.innerText = cv.brand || "None";
        
        if (cv.verdict === 'FAKE LOGIN DETECTED') {
            verdictText.style.color = 'var(--acc-red)';
            brandText.style.color = 'var(--acc-red)';
            
            // Retroactively jump the risk score to 100% and update UI
            const riskCircle = document.getElementById('risk-circle');
            const riskTextEl = document.getElementById('risk-text');
            const verdictIcon = document.getElementById('verdict-icon');
            const verdictTitleElem = document.getElementById('verdict-title');
            const verdictDesc = document.getElementById('verdict-desc');
            const verdictBanner = document.getElementById('verdict-banner');
            
            riskTextEl.innerText = '100%';
            riskTextEl.style.fill = 'var(--acc-red)';
            riskCircle.style.strokeDasharray = '100, 100';
            riskCircle.style.stroke = 'var(--acc-red)';
            
            verdictIcon.innerText = '🚨';
            verdictTitleElem.innerText = 'Critical Phishing';
            verdictDesc.innerText = 'OpenCV visually detected a Fake Login Page mimicking a known brand!';
            verdictBanner.className = 'verdict danger';
        } else {
            verdictText.style.color = 'var(--acc-cyan)';
        }
    }

    function setLoading(isLoading, isEmailForm = false) {
        if (isLoading) {
            if (isEmailForm) {
                emailScanBtn.disabled = true;
                emailBtnText.innerText = "Scanning Email...";
                emailSpinner.classList.remove('hidden');
            } else {
                scanBtn.disabled = true;
                btnText.innerText = "Scanning...";
                btnSpinner.classList.remove('hidden');
            }
            statusMsg.classList.remove('hidden');
            statusText.innerText = "Connecting to Threat Intelligence...";
        } else {
            if (isEmailForm) {
                emailScanBtn.disabled = false;
                emailBtnText.innerText = "Analyze Email Content";
                emailSpinner.classList.add('hidden');
            } else {
                scanBtn.disabled = false;
                btnText.innerText = "Analyze URL";
                btnSpinner.classList.add('hidden');
            }
            statusMsg.classList.add('hidden');
        }
    }

    function animateValue(obj, start, end, duration, isScore = false) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            let val = Math.floor(progress * (end - start) + start);
            
            obj.innerHTML = isScore ? `${val}%` : val;
            
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }

});
