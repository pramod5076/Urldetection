import base64
import re
import whois
import tldextract
import socket
import ssl
import cv2
import numpy as np
from rapidfuzz.distance import Levenshtein
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import os
import io
import zipfile
import httpx

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

load_dotenv()

app = FastAPI(title="PhishGuard AI Backend", version="2.0.0")

# Setup CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static and templates directories
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Load environment variables
VT_API_KEY = os.getenv("VT_API_KEY")
ENABLE_SCREENSHOT = os.getenv("ENABLE_SCREENSHOT", "false").lower() == "true"
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

PROTECTED_DOMAINS = [
    "paypal.com", "microsoft.com", "facebook.com", "google.com", "apple.com", 
    "amazon.com", "netflix.com", "instagram.com", "twitter.com", "linkedin.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com"
]

class ScanRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    content: str

def get_headers():
    return {
        "x-apikey": VT_API_KEY
    }

# ==========================================
# Threat API Clients
# ==========================================

async def check_google_safe_browsing(url: str) -> dict:
    """Check a URL against the Google Safe Browsing Lookup API."""
    key = os.getenv("SAFE_BROWSING_API_KEY")
    if not key or "PASTE" in key or "YOUR" in key or not key.strip():
        return {"is_flagged": False, "reason": None}
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
    payload = {
        "client": {
            "clientId": "phishguard",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", 
                "SOCIAL_ENGINEERING", 
                "UNWANTED_SOFTWARE", 
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        async with httpx.AsyncClient() as client:
            res = await client.post(endpoint, json=payload, timeout=5.0)
            if res.status_code == 200:
                data = res.json()
                matches = data.get("matches", [])
                if matches:
                    threat_type = matches[0].get("threatType")
                    return {
                        "is_flagged": True, 
                        "reason": f"GOOGLE_SAFE_BROWSING: Flagged as {threat_type}"
                    }
    except Exception as e:
        print(f"Google Safe Browsing API error: {e}")
    return {"is_flagged": False, "reason": None}


def resolve_hostname_to_ip(url: str) -> str:
    """Resolve a URL's hostname to an IP address."""
    try:
        # Check if URL contains an IP address directly
        ip_pattern = r"https?://(\d+\.\d+\.\d+\.\d+)"
        ip_match = re.search(ip_pattern, url)
        if ip_match:
            return ip_match.group(1)
        
        # Otherwise parse the hostname and resolve
        hostname = url.split("://")[-1].split("/")[0].split(":")[0]
        return socket.gethostbyname(hostname)
    except Exception:
        return None


async def check_abuseipdb(ip: str) -> dict:
    """Check an IP address reputation using AbuseIPDB API."""
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key or "PASTE" in key or "YOUR" in key or not key.strip() or not ip:
        return {"abuse_score": 0, "is_malicious": False, "reason": None}
        
    endpoint = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(endpoint, headers=headers, params=params, timeout=5.0)
            if res.status_code == 200:
                data = res.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                if score >= 20: # Flag if confidence score >= 20%
                    return {
                        "abuse_score": score,
                        "is_malicious": True,
                        "reason": f"ABUSEIPDB: IP {ip} flagged with {score}% abuse confidence"
                    }
                return {"abuse_score": score, "is_malicious": False, "reason": None}
    except Exception as e:
        print(f"AbuseIPDB API error: {e}")
    return {"abuse_score": 0, "is_malicious": False, "reason": None}

# ==========================================
# Routes & Endpoints
# ==========================================

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/api/scan")
async def scan_url(req: ScanRequest):
    if not VT_API_KEY or VT_API_KEY in ["PASTE_YOUR_API_KEY_HERE", "YOUR_API_KEY_HERE", ""]:
        raise HTTPException(status_code=500, detail="VirusTotal API Key is missing. Add it in .env")

    url = req.url
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
        
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    try:
        get_report_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        async with httpx.AsyncClient() as client:
            response = await client.get(get_report_endpoint, headers=get_headers())
            
            if response.status_code == 200:
                return {"status": "found", "data": response.json().get("data")}
                
            if response.status_code == 404:
                scan_endpoint = "https://www.virustotal.com/api/v3/urls"
                payload = {"url": url}
                scan_res = await client.post(scan_endpoint, data=payload, headers=get_headers())
                
                if scan_res.status_code == 200:
                    analysis_id = scan_res.json().get("data", {}).get("id")
                    return {
                        "status": "scanning",
                        "message": "URL submitted for scanning. Retrieving results...",
                        "analysis_id": analysis_id
                    }
                else:
                    return JSONResponse(
                        status_code=scan_res.status_code, 
                        content={"error": "Failed to submit URL to VirusTotal", "details": scan_res.json()}
                    )

            return JSONResponse(
                status_code=response.status_code, 
                content={"error": "Error fetching report from VirusTotal", "details": response.json()}
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to connect to VirusTotal API: {str(e)}")


@app.post("/api/scan_email")
async def scan_email(req: EmailRequest):
    if not VT_API_KEY or VT_API_KEY in ["PASTE_YOUR_API_KEY_HERE", "YOUR_API_KEY_HERE", ""]:
        raise HTTPException(status_code=500, detail="VirusTotal API Key is missing. Add it in .env")

    email_content = req.content
    if not email_content:
        raise HTTPException(status_code=400, detail="Email content is required")

    urls_found = set()

    # 1. Parse HTML to find hidden hrefs
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
        return {"status": "clean", "message": "No URLs found in the provided email content.", "urls": [], "keywords": []}

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

    if len(urls_list) > 4:
        urls_list = urls_list[:4] 

    return {
        "status": "extracted",
        "message": f"Found {len(urls_list)} URL(s) to scan.",
        "urls": urls_list,
        "keywords": detected_keywords
    }


@app.get("/api/analysis/{analysis_id:path}")
async def get_analysis(analysis_id: str):
    try:
        endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        async with httpx.AsyncClient() as client:
            response = await client.get(endpoint, headers=get_headers())
            return JSONResponse(status_code=response.status_code, content=response.json())
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to connect to VirusTotal API: {str(e)}")


@app.post("/api/domain_info")
async def domain_info(req: ScanRequest):
    url = req.url
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    try:
        # Check if URL contains an IP address
        ip_pattern = r"https?://(\d+\.\d+\.\d+\.\d+)"
        ip_match = re.search(ip_pattern, url)
        
        if ip_match:
            ip_address = ip_match.group(1)
            abuse_res = await check_abuseipdb(ip_address)
            msg = "Raw IP Address detected instead of domain name."
            if abuse_res["is_malicious"]:
                msg += f" {abuse_res['reason']}"
            return {
                "domain": ip_address,
                "is_ip": True,
                "risk": "HIGH",
                "message": msg
            }

        # Extract root domain
        extracted = tldextract.extract(url)
        if not extracted.domain or not extracted.suffix:
            raise HTTPException(status_code=400, detail="Invalid URL or domain")
        
        domain = f"{extracted.domain}.{extracted.suffix}"
        
        # Run WHOIS lookup in a threadpool to keep FastAPI non-blocking
        from anyio.to_thread import run_sync
        try:
            w = await run_sync(whois.whois, domain)
        except Exception as e:
            return {
                "domain": domain,
                "age_days": "Unknown",
                "risk": "HIGH",
                "message": f"WHOIS lookup failed: {str(e)}"
            }
        
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if not creation_date:
            return {
                "domain": domain,
                "age_days": "Unknown",
                "risk": "HIGH",
                "message": "Domain exists but WHOIS record contains no creation date."
            }
            
        now = datetime.now()
        if creation_date.tzinfo is not None:
             now = datetime.now(timezone.utc)
             
        age_delta = now - creation_date
        age_days = age_delta.days
        
        risk = "HIGH" if age_days < 30 else "LOW"
        
        # Resolve domain and check AbuseIPDB
        ip_addr = resolve_hostname_to_ip(url)
        abuse_res = await check_abuseipdb(ip_addr)
        msg = None
        if abuse_res["is_malicious"]:
            risk = "HIGH"
            msg = abuse_res["reason"]

        return {
            "domain": domain,
            "age_days": age_days,
            "risk": risk,
            "creation_date": creation_date.strftime("%Y-%m-%d"),
            "message": msg
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to look up domain info: {str(e)}")


def check_ssl_sync(hostname: str) -> dict:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=3) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.getpeercert()


@app.post("/api/ssl_info")
async def ssl_info(req: ScanRequest):
    url = req.url
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    try:
        extracted = tldextract.extract(url)
        if not extracted.domain or not extracted.suffix:
            raise HTTPException(status_code=400, detail="Invalid URL or domain")
        
        hostname = url.split("://")[-1].split("/")[0].split(":")[0]

        from anyio.to_thread import run_sync
        try:
            cert = await run_sync(check_ssl_sync, hostname)
        except socket.gaierror:
            return {
                "valid": False,
                "issuer": "None",
                "expires_in_days": -1,
                "error": "Domain Name Resolution Failed (DNS Error)"
            }
        except (socket.timeout, ConnectionRefusedError):
            return {
                "valid": False,
                "issuer": "Connection timeout",
                "expires_in_days": -1,
                "error": "Service unreachable on port 443"
            }

        not_after = cert.get("notAfter") if cert else None
        if not not_after:
            return {
                "valid": False,
                "issuer": "Unknown",
                "expires_in_days": -1,
                "error": "Could not retrieve certificate expiration date"
            }
            
        expires_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        remaining_days = (expires_date - datetime.utcnow()).days

        issuer = "Unknown Issuer"
        if cert and cert.get("issuer"):
            for item in cert.get("issuer", []):
                for sub_item in item:
                    if sub_item[0] == "organizationName":
                        issuer = sub_item[1]
                        break
                    elif sub_item[0] == "commonName" and issuer == "Unknown Issuer":
                        issuer = sub_item[1]

        return {
            "valid": True,
            "issuer": issuer,
            "expires_in_days": remaining_days,
            "error": None
        }

    except ssl.SSLCertVerificationError:
        return {
            "valid": False,
            "issuer": "Invalid / Self-Signed",
            "expires_in_days": -1,
            "error": "SSL Verification Failed"
        }
    except Exception as e:
        return {
            "valid": False,
            "issuer": "Error",
            "expires_in_days": -1,
            "error": str(e)
        }


@app.post("/api/domain_similarity")
async def domain_similarity(req: ScanRequest):
    url = req.url
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    try:
        extracted = tldextract.extract(url)
        if not extracted.domain or not extracted.suffix:
            raise HTTPException(status_code=400, detail="Invalid URL or domain")
        
        target_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        
        matches = []
        for protected in PROTECTED_DOMAINS:
            if target_domain == protected:
                continue
            
            distance = Levenshtein.distance(target_domain, protected)
            if distance <= 2:
                matches.append({
                    "mimicked_domain": protected,
                    "distance": distance
                })
        
        matches.sort(key=lambda x: x['distance'])
        
        return {
            "target_domain": target_domain,
            "is_typosquat": len(matches) > 0,
            "matches": matches
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Similarity check failed: {str(e)}")


def analyze_screenshot_for_brands(screenshot_bytes, url_domain):
    try:
        nparr = np.frombuffer(screenshot_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            return {"verdict": "ERROR", "reason": "Failed to decode screenshot."}
        
        hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
        
        def calculate_color_percentage(lower, upper):
            mask = cv2.inRange(hsv, lower, upper)
            return cv2.countNonZero(mask) / (img.shape[0] * img.shape[1])

        # 1. PayPal Blue
        if calculate_color_percentage(np.array([100, 150, 50]), np.array([140, 255, 255])) > 0.05:
            if "paypal.com" not in url_domain.lower():
                return {
                    "verdict": "FAKE LOGIN DETECTED", 
                    "brand": "PayPal",
                    "reason": "Visual signature of 'PayPal' (Deep Blue) detected on unauthorized domain."
                }

        # 2. Facebook Blue
        if calculate_color_percentage(np.array([100, 100, 100]), np.array([120, 255, 255])) > 0.06:
            if "facebook.com" not in url_domain.lower():
                return {
                    "verdict": "FAKE LOGIN DETECTED",
                    "brand": "Facebook",
                    "reason": "Visual signature of 'Facebook' (Corporate Blue) detected on unauthorized domain."
                }

        # 3. Microsoft/Office Orange/Red
        if calculate_color_percentage(np.array([0, 150, 100]), np.array([15, 255, 255])) > 0.04:
            if "microsoft.com" not in url_domain.lower() and "office.com" not in url_domain.lower() and "live.com" not in url_domain.lower():
                return {
                    "verdict": "FAKE LOGIN DETECTED",
                    "brand": "Microsoft / Office",
                    "reason": "Visual signature of 'Microsoft/Office' detected on unauthorized domain."
                }

        return {"verdict": "CLEAN", "reason": "No major phishing brands visually detected in screenshot."}

    except Exception as e:
        return {"verdict": "ERROR", "reason": f"CV2 Error: {str(e)}"}


def capture_screenshot_sync(url: str, root_domain: str) -> dict:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager

    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1280,720")
    
    driver_path = ChromeDriverManager().install()
    
    if os.name == 'nt' and not str(driver_path).lower().endswith('.exe'):
        base_dir = os.path.dirname(driver_path)
        for root, dirs, files in os.walk(base_dir):
            for file in files:
                if file.lower() == 'chromedriver.exe':
                    driver_path = os.path.join(root, file)
                    break
    
    service = Service(driver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.set_page_load_timeout(15)
    
    try:
        driver.get(url)
        screenshot_png = driver.get_screenshot_as_png()
    finally:
        driver.quit()

    analysis_result = analyze_screenshot_for_brands(screenshot_png, root_domain)
    b64_screenshot = base64.b64encode(screenshot_png).decode("utf-8")

    return {
        "screenshot_base64": b64_screenshot,
        "cv_analysis": analysis_result
    }


@app.post("/api/screenshot_analysis")
async def screenshot_analysis(req: ScanRequest):
    if not ENABLE_SCREENSHOT:
        return {
            "message": "Screenshot disabled in deployment",
            "cv_analysis": {
                "verdict": "DISABLED",
                "reason": "Selenium not supported"
            }
        }

    url = req.url
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    try:
        extracted = tldextract.extract(url)
        root_domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

        from anyio.to_thread import run_sync
        result = await run_sync(capture_screenshot_sync, url, root_domain)
        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Screenshot failed: {str(e)}")


@app.post("/api/check_risk")
async def check_risk(req: ScanRequest):
    url = req.url
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")

    try:
        extracted = tldextract.extract(url)
        if not extracted.domain or not extracted.suffix:
             return {"is_malicious": False, "reason": "Invalid URL", "score": 0}
             
        # 1. Registration Domain Check (Typosquatting)
        target_reg_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        for protected in PROTECTED_DOMAINS:
            if target_reg_domain == protected:
                return {"is_malicious": False, "reason": "Verified Brand", "score": 0}
            
            distance = Levenshtein.distance(target_reg_domain, protected)
            if distance <= 2:
                return {
                    "is_malicious": True,
                    "reason": f"SQUATTING: Possible mimic of {protected}",
                    "score": 85
                }

        # 2. Subdomain check for Brands/Typosquats
        full_hostname = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}".lower()
        for protected in PROTECTED_DOMAINS:
            brand_keyword = protected.split('.')[0]
            if brand_keyword in extracted.subdomain.lower():
                 return {
                    "is_malicious": True,
                    "reason": f"BRAND MISUSE: '{brand_keyword}' found in subdomain",
                    "score": 80
                }
                
            parts = full_hostname.split('.')
            for part in parts:
                if len(part) < 4: continue
                if part == brand_keyword: continue
                dist = Levenshtein.distance(part, brand_keyword)
                if dist > 0 and dist <= 2:
                    return {
                        "is_malicious": True,
                        "reason": f"SQUATTING: '{part}' mimics '{brand_keyword}'",
                        "score": 90
                    }

        # 3. Google Safe Browsing Check
        gsb_result = await check_google_safe_browsing(url)
        if gsb_result["is_flagged"]:
            return {
                "is_malicious": True,
                "reason": gsb_result["reason"],
                "score": 95
            }

        # 4. AbuseIPDB Check
        ip_addr = resolve_hostname_to_ip(url)
        abuse_result = await check_abuseipdb(ip_addr)
        if abuse_result["is_malicious"]:
            return {
                "is_malicious": True,
                "reason": abuse_result["reason"],
                "score": 85
            }

        # 5. VirusTotal Quick Check (Cache)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        get_report_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(get_report_endpoint, headers=get_headers())
            if response.status_code == 200:
                vt_data = response.json().get("data", {})
                stats = vt_data.get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                if malicious > 0:
                    return {
                        "is_malicious": True,
                        "reason": f"VIRUSTOTAL: Flagged by {malicious} engines",
                        "score": 95
                    }

        return {
            "is_malicious": False,
            "reason": "Safe",
            "score": 0
        }

    except Exception as e:
        return {"is_malicious": False, "reason": f"Check failed: {str(e)}", "score": 0}


@app.get("/api/download_extension")
async def download_extension():
    extension_dir = "extension"
    if not os.path.exists(extension_dir):
        raise HTTPException(status_code=404, detail="Extension directory not found")
        
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(extension_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, extension_dir)
                zf.write(file_path, arcname)
    
    memory_file.seek(0)
    
    return StreamingResponse(
        memory_file,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=phishguard_extension.zip"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=5000, reload=True)
