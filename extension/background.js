const API_URL = 'http://127.0.0.1:5000/api/check_risk';
const allowedUrls = new Set();

// Proactive Blocking: Intercept navigation before it happens
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return; // Only main frame navigations
    const url = details.url;
    if (!url.startsWith('http')) return;
    if (allowedUrls.has(url)) return;
    if (url.includes(chrome.runtime.id)) return; // Don't block our own warning page

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.is_malicious) {
                // Redirect to the internal warning page
                const warningUrl = chrome.runtime.getURL('warning.html') + 
                    `?url=${encodeURIComponent(url)}&reason=${encodeURIComponent(data.reason)}`;
                chrome.tabs.update(details.tabId, { url: warningUrl });

                // Also show a notification for prominence
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icon.png',
                    title: 'PhishGuard Proactive Alert!',
                    message: `Blocked: ${data.reason}`,
                    priority: 2
                });
            }
        }
    } catch (error) {
        console.error('PhishGuard API Error:', error);
    }
});

// Communication with warning.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "allow_url") {
        allowedUrls.add(request.url);
        // Clear from allowlist after 5 minutes
        setTimeout(() => allowedUrls.delete(request.url), 300000);
        sendResponse({ status: "success" });
    }
    return true; 
});
