import base64
import requests
import re
import whois
import tldextract
import socket
import ssl
import cv2
import numpy as np
from rapidfuzz.distance import Levenshtein
# ❌ Selenium disabled for deployment
# from selenium import webdriver
# from selenium.webdriver.chrome.options import Options
# from selenium.webdriver.chrome.service import Service
# from webdriver_manager.chrome import ChromeDriverManager


from datetime import datetime, timezone
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import os
import io
import zipfile
from flask import Flask, render_template, request, jsonify, send_file

load_dotenv()

app = Flask(__name__)

# ==========================================
# API KEY (Loaded from .env)
# ==========================================
VT_API_KEY = os.getenv("VT_API_KEY")

# ✅ ADD THIS LINE BELOW
ENABLE_SCREENSHOT = os.getenv("ENABLE_SCREENSHOT", "false").lower() == "true"

def get_headers():
    return {
        "x-apikey": VT_API_KEY
    }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def scan_url():
    if not VT_API_KEY or VT_API_KEY == "PASTE_YOUR_API_KEY_HERE" or VT_API_KEY == "YOUR_API_KEY_HERE":
        return jsonify({"error": "VirusTotal API Key is missing. Add it in app.py"}), 500

    data = request.json
    url = data.get("url")
    if not url:
        return jsonify({"error": "URL is required"}), 400
        
    # Generate url_id for VirusTotal v3 API (base64url without padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    try:
        # 1. Try to get existing report
        get_report_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(get_report_endpoint, headers=get_headers())
        
        if response.status_code == 200:
            return jsonify({"status": "found", "data": response.json().get("data")})
            
        if response.status_code == 404:
            # 2. If not found, submit for scanning
            scan_endpoint = "https://www.virustotal.com/api/v3/urls"
            payload = {"url": url}
            
            # VirusTotal v3 requires form-url-encoded data for URL submission
            scan_res = requests.post(scan_endpoint, data=payload, headers=get_headers())
            
            if scan_res.status_code == 200:
                analysis_id = scan_res.json().get("data", {}).get("id")
                return jsonify({
                    "status": "scanning",
                    "message": "URL submitted for scanning. Retrieving results...",
                    "analysis_id": analysis_id
                })
            else:
                return jsonify({"error": "Failed to submit URL to VirusTotal", "details": scan_res.json()}), scan_res.status_code

        return jsonify({"error": "Error fetching report from VirusTotal", "details": response.json()}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to connect to VirusTotal API. Please check your internet connection.", "details": str(e)}), 500

@app.route("/api/scan_email", methods=["POST"])
def scan_email():
    if not VT_API_KEY or VT_API_KEY == "PASTE_YOUR_API_KEY_HERE" or VT_API_KEY == "YOUR_API_KEY_HERE":
        return jsonify({"error": "VirusTotal API Key is missing. Add it in app.py"}), 500

    data = request.json
    email_content = data.get("content", "")
    
    if not email_content:
        return jsonify({"error": "Email content is required"}), 400

    urls_found = set()

    # 1. Try to parse as HTML first using BeautifulSoup to find hidden hrefs
    soup = BeautifulSoup(email_content, "html.parser")
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        if href.startswith('http://') or href.startswith('https://'):
            urls_found.add(href)

    # 2. Extract raw URLs from plain text using Regex
    url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"<>]+')
    raw_urls = url_pattern.findall(email_content)
    for raw_url in raw_urls:
        urls_found.add(raw_url)

    urls_list = list(urls_found)
    
    if not urls_list:
        return jsonify({"status": "clean", "message": "No URLs found in the provided email content.", "urls": [], "keywords": []})

    # 3. Detect Suspicious Keywords
    suspicious_keywords = [
        "verify", "login immediately", "urgent", "suspended", "update payment",
        "action required", "account compromise", "password reset", "claim your prize", "billing error"
    ]
    
    detected_keywords = []
    lower_content = email_content.lower()
    for keyword in suspicious_keywords:
        if keyword in lower_content:
            detected_keywords.append(keyword)

    # Optional: limit batch size to prevent hitting API rate limits on free tier (4 req/min)
    if len(urls_list) > 4:
        # Just warn the frontend, or truncate. Truncating for safety of free tier.
        urls_list = urls_list[:4] 

    return jsonify({
        "status": "extracted",
        "message": f"Found {len(urls_list)} URL(s) to scan.",
        "urls": urls_list,
        "keywords": detected_keywords
    })

@app.route("/api/analysis/<path:analysis_id>", methods=["GET"])
def get_analysis(analysis_id):
    try:
        endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        response = requests.get(endpoint, headers=get_headers())
        return jsonify(response.json()), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": "Failed to connect to VirusTotal API. Please check your internet connection.", "details": str(e)}), 500

@app.route("/api/domain_info", methods=["POST"])
def domain_info():
    data = request.json
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        # Check if URL contains an IP address
        ip_pattern = r"https?://(\d+\.\d+\.\d+\.\d+)"
        ip_match = re.search(ip_pattern, url)
        
        if ip_match:
            ip_address = ip_match.group(1)
            return jsonify({
                "domain": ip_address,
                "is_ip": True,
                "risk": "HIGH",
                "message": "Raw IP Address detected instead of domain name."
            })

        # Extract the root domain (e.g. example.com)
        extracted = tldextract.extract(url)
        if not extracted.domain or not extracted.suffix:
            return jsonify({"error": "Invalid URL or domain"}), 400
        
        domain = f"{extracted.domain}.{extracted.suffix}"
        
        # Perform WHOIS lookup with timeout
        try:
            w = whois.whois(domain)
        except Exception as e:
            return jsonify({
                "domain": domain,
                "age_days": "Unknown",
                "risk": "HIGH", # High risk if domain cannot be found/verified
                "message": f"WHOIS lookup failed. Domain might not exist or is private: {str(e)}"
            })
        
        creation_date = w.creation_date
        
        # Whois can return a list of dates or a single date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if not creation_date:
            return jsonify({
                "domain": domain,
                "age_days": "Unknown",
                "risk": "HIGH",
                "message": "Domain exists but WHOIS record contains no creation date."
            })
            
        # Ensure it's timezone-aware or naive safely
        now = datetime.now()
        if creation_date.tzinfo is not None:
             now = datetime.now(timezone.utc)
             
        age_delta = now - creation_date
        age_days = age_delta.days
        
        # Determine risk based on age (e.g., < 30 days is HIGH risk)
        risk = "HIGH" if age_days < 30 else "LOW"
        
        return jsonify({
            "domain": domain,
            "age_days": age_days,
            "risk": risk,
            "creation_date": creation_date.strftime("%Y-%m-%d")
        })
        
    except Exception as e:
        return jsonify({"error": "Failed to look up domain info", "details": str(e)}), 500

@app.route("/api/ssl_info", methods=["POST"])
def ssl_info():
    data = request.json
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        # Extract the root domain (e.g. example.com)
        extracted = tldextract.extract(url)
        if not extracted.domain or not extracted.suffix:
            return jsonify({"error": "Invalid URL or domain"}), 400
        
        # Need the full hostname for SSL check
        hostname = url.split("://")[-1].split("/")[0].split(":")[0]

        context = ssl.create_default_context()
        
        # Connect to retrieve certificate
        try:
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
        except socket.gaierror:
            return jsonify({
                "valid": False,
                "issuer": "None",
                "expires_in_days": -1,
                "error": "Domain Name Resolution Failed (DNS Error)"
            })
        except (socket.timeout, ConnectionRefusedError):
            return jsonify({
                "valid": False,
                "issuer": "Connection timeout",
                "expires_in_days": -1,
                "error": "Service unreachable on port 443"
            })

        # Parse Expiration
        not_after = cert.get("notAfter") if cert else None
        if not not_after:
            return jsonify({
                "valid": False,
                "issuer": "Unknown",
                "expires_in_days": -1,
                "error": "Could not retrieve certificate expiration date"
            })
            
        expires_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        remaining_days = (expires_date - datetime.utcnow()).days

        # Parse Issuer name safely
        issuer = "Unknown Issuer"
        if cert and cert.get("issuer"):
            for item in cert.get("issuer", []):
                for sub_item in item:
                    if sub_item[0] == "organizationName":
                        issuer = sub_item[1]
                        break
                    elif sub_item[0] == "commonName" and issuer == "Unknown Issuer":
                        issuer = sub_item[1]

        return jsonify({
            "valid": True,
            "issuer": issuer,
            "expires_in_days": remaining_days,
            "error": None
        })

    except ssl.SSLCertVerificationError:
        return jsonify({
            "valid": False,
            "issuer": "Invalid / Self-Signed",
            "expires_in_days": -1,
            "error": "SSL Verification Failed"
        })
    except Exception as e:
        return jsonify({
            "valid": False,
            "issuer": "Error",
            "expires_in_days": -1,
            "error": str(e)
        })

PROTECTED_DOMAINS = [
    "paypal.com", "microsoft.com", "facebook.com", "google.com", "apple.com", 
    "amazon.com", "netflix.com", "instagram.com", "twitter.com", "linkedin.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com"
]

@app.route("/api/domain_similarity", methods=["POST"])
def domain_similarity():
    data = request.json
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        extracted = tldextract.extract(url)
        if not extracted.domain or not extracted.suffix:
            return jsonify({"error": "Invalid URL or domain"}), 400
        
        target_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        
        matches = []
        for protected in PROTECTED_DOMAINS:
            # Skip if it's an exact match (legitimate site)
            if target_domain == protected:
                continue
            
            distance = Levenshtein.distance(target_domain, protected)
            
            # Distance of 1 or 2 is highly suspicious typosquatting
            if distance <= 2:
                matches.append({
                    "mimicked_domain": protected,
                    "distance": distance
                })
        
        # Sort by closest match
        matches.sort(key=lambda x: x['distance'])
        
        return jsonify({
            "target_domain": target_domain,
            "is_typosquat": len(matches) > 0,
            "matches": matches
        })
        
    except Exception as e:
        return jsonify({"error": "Similarity check failed", "details": str(e)}), 500

# Minimal branded color/text detection heuristic.
# Full template matching requires accurate brand image files, so we use a structural heuristic approach for demonstration.
def analyze_screenshot_for_brands(screenshot_bytes, url_domain):
    try:
        # Decode the image into OpenCV format
        nparr = np.frombuffer(screenshot_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            return {"verdict": "ERROR", "reason": "Failed to decode screenshot."}

        # --- SIMULATED COMPUTER VISION LOGIC ---
        # In a production environment, this would use cv2.matchTemplate with actual brand logos.
        # Since we cannot guarantee the logo templates exist locally, we use basic color histograms to approximate.
        # Example approximation: High dominance of PayPal blue (#003087) on a plain white background
        
        # Convert to HSV for better color thresholding
        hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
        
        def calculate_color_percentage(lower, upper):
            mask = cv2.inRange(hsv, lower, upper)
            return cv2.countNonZero(mask) / (img.shape[0] * img.shape[1])

        # 1. PayPal Blue (#003087 approx)
        if calculate_color_percentage(np.array([100, 150, 50]), np.array([140, 255, 255])) > 0.05:
            if "paypal.com" not in url_domain.lower():
                return {
                    "verdict": "FAKE LOGIN DETECTED", 
                    "brand": "PayPal",
                    "reason": "Visual signature of 'PayPal' (Deep Blue) detected on unauthorized domain."
                }

        # 2. Facebook Blue (#1877F2 approx)
        if calculate_color_percentage(np.array([100, 100, 100]), np.array([120, 255, 255])) > 0.06:
            if "facebook.com" not in url_domain.lower():
                return {
                    "verdict": "FAKE LOGIN DETECTED",
                    "brand": "Facebook",
                    "reason": "Visual signature of 'Facebook' (Corporate Blue) detected on unauthorized domain."
                }

        # 3. Microsoft/Office Orange/Red (#F25022 approx)
        if calculate_color_percentage(np.array([0, 150, 100]), np.array([15, 255, 255])) > 0.04:
            if "microsoft.com" not in url_domain.lower() and "office.com" not in url_domain.lower() and "live.com" not in url_domain.lower():
                return {
                    "verdict": "FAKE LOGIN DETECTED",
                    "brand": "Microsoft / Office",
                    "reason": "Visual signature of 'Microsoft/Office' detected on unauthorized domain."
                }

        # Fallback to no major threats detected visually
        return {"verdict": "CLEAN", "reason": "No major phishing brands visually detected in screenshot."}

    except Exception as e:
        return {"verdict": "ERROR", "reason": f"CV2 Error: {str(e)}"}


@app.route("/api/screenshot_analysis", methods=["POST"])
def screenshot_analysis():

    # 🚫 Disable in deployment
    if not ENABLE_SCREENSHOT:
        return jsonify({
            "message": "Screenshot disabled in deployment",
            "cv_analysis": {
                "verdict": "DISABLED",
                "reason": "Selenium not supported"
            }
        })

    # ✅ ENABLED LOCALLY
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        data = request.json
        url = data.get("url", "")

        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")

        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)

        screenshot_png = driver.get_screenshot_as_png()
        driver.quit()

        # Run your existing visual analysis
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"

        result = analyze_screenshot_for_brands(screenshot_png, domain)

        return jsonify({
            "screenshot_base64": base64.b64encode(screenshot_png).decode(),
            "cv_analysis": result
        })

    except Exception as e:
        return jsonify({
            "error": "Screenshot failed",
            "details": str(e)
        }), 500
@app.after_request
def add_cors_headers(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route("/api/check_risk", methods=["POST"])
def check_risk():
    data = request.json
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        extracted = tldextract.extract(url)
        if not extracted.domain or not extracted.suffix:
             return jsonify({"is_malicious": False, "reason": "Invalid URL"}), 200
             
        # 1. Registration Domain Check (Typosquatting)
        target_reg_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        
        for protected in PROTECTED_DOMAINS:
            if target_reg_domain == protected:
                return jsonify({"is_malicious": False, "reason": "Verified Brand", "score": 0})
            
            distance = Levenshtein.distance(target_reg_domain, protected)
            if distance <= 2:
                return jsonify({
                    "is_malicious": True,
                    "reason": f"SQUATTING: Possible mimic of {protected}",
                    "score": 85
                })

        # 2. Subdomain check for Brands/Typosquats
        full_hostname = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}".lower()
        
        # Keywords to look for (e.g., 'paypal' from 'paypal.com')
        for protected in PROTECTED_DOMAINS:
            brand_keyword = protected.split('.')[0]
            
            # Simple keyword match in subdomain
            if brand_keyword in extracted.subdomain.lower():
                 return jsonify({
                    "is_malicious": True,
                    "reason": f"BRAND MISUSE: '{brand_keyword}' found in subdomain",
                    "score": 80
                })
                
            # Fuzzy match keywords in the entire hostname (excluding the legitimate domain)
            # This catches 'paypa1'
            parts = full_hostname.split('.')
            for part in parts:
                if len(part) < 4: continue # Skip short parts
                if part == brand_keyword: continue # Exact brand part in a safe place? unlikely without registration
                
                dist = Levenshtein.distance(part, brand_keyword)
                if dist > 0 and dist <= 2:
                    return jsonify({
                        "is_malicious": True,
                        "reason": f"SQUATTING: '{part}' mimics '{brand_keyword}'",
                        "score": 90
                    })

        # 3. VirusTotal Quick Check (Cache)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        get_report_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(get_report_endpoint, headers=get_headers())
        
        if response.status_code == 200:
            vt_data = response.json().get("data", {})
            stats = vt_data.get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                return jsonify({
                    "is_malicious": True,
                    "reason": f"VIRUSTOTAL: Flagged by {malicious} engines",
                    "score": 95
                })

        return jsonify({
            "is_malicious": False,
            "reason": "Safe",
            "score": 0
        })

    except Exception as e:
        return jsonify({"is_malicious": False, "reason": "Check failed", "details": str(e)}), 200

@app.route("/api/download_extension")
def download_extension():
    # Folder to zip
    extension_dir = "extension"
    
    if not os.path.exists(extension_dir):
        return jsonify({"error": "Extension directory not found"}), 404
        
    # Create an in-memory zip file
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(extension_dir):
            for file in files:
                file_path = os.path.join(root, file)
                # Keep the structure inside the zip
                arcname = os.path.relpath(file_path, extension_dir)
                zf.write(file_path, arcname)
    
    memory_file.seek(0)
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name='phishguard_extension.zip'
    )

if __name__ == "__main__":
    app.run()