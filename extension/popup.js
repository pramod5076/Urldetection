const API_URL = 'http://127.0.0.1:5000/api/check_risk';
const VERSION = '1.0.2'; // Unified Risk Check v2

document.addEventListener('DOMContentLoaded', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) return;
    
    const currentUrl = tab.url;
    try {
        const urlObj = new URL(currentUrl);
        document.getElementById('current-url').innerText = urlObj.hostname;
    } catch (e) {
        document.getElementById('current-url').innerText = currentUrl;
    }
    
    // Check if the current URL is malicious
    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: currentUrl })
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('PhishGuard API Response:', data);
            const statusBox = document.getElementById('status-box');
            
            if (data.is_malicious) {
                statusBox.innerText = data.reason || 'DANGER: PHISHING DETECTED';
                statusBox.className = 'status danger';
            } else {
                statusBox.innerText = 'SAFE: NO THREATS FOUND';
                statusBox.className = 'status safe';
            }
        }
    } catch (error) {
        document.getElementById('status-box').innerText = 'API Offline';
    }
});
