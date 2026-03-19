document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const url = params.get('url');
    const reason = params.get('reason');

    if (url) {
        try {
            document.getElementById('target-url').textContent = new URL(url).hostname;
        } catch(e) {
            document.getElementById('target-url').textContent = url;
        }
    }
    
    if (reason) {
        document.getElementById('reason').textContent = `Reason: ${reason}`;
    }

    document.getElementById('go-back').addEventListener('click', () => {
        window.history.back();
        // If no history, navigate to a safe page or close
        setTimeout(() => {
            if (window.location.href.includes('warning.html')) {
                window.location.href = 'https://www.google.com';
            }
        }, 500);
    });

    document.getElementById('proceed').addEventListener('click', () => {
        if (url) {
            // Tell background to allow this URL temporarily
            chrome.runtime.sendMessage({ action: "allow_url", url: url }, () => {
                window.location.href = url;
            });
        }
    });
});
