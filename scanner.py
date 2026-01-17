import requests
import socket
import ssl
import re
import datetime
import time
import urllib3
from urllib.parse import urlparse
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def analyze_security(url):
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url 

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Initialize Report
    report = {
        "target": url,
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "grade": "A",
        "risk_score": 0,
        "vulnerabilities": [],
        "good_practices": [],
        "server_info": {
            "ip": "Unknown",
            "location": "Unknown",
            "latency": "0ms",
            "ssl_expiry": "N/A" # Default
        },
        "stats": {"high": 0, "medium": 0, "low": 0, "safe": 0}
    }

    headers_ua = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        # --- PHASE 0: Server Intelligence ---
        try:
            ip = socket.gethostbyname(domain)
            report["server_info"]["ip"] = ip
            
            geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
            if geo['status'] == 'success':
                report["server_info"]["location"] = f"{geo['city']}, {geo['country']}"
        except:
            pass

        # --- PHASE 1: SSL Inspection (Updated) ---
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Date Parsing
                    not_after = cert['notAfter'] 
                    expiry_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry_date - datetime.datetime.utcnow()).days
                    
                    report["server_info"]["ssl_expiry"] = f"{days_left} Days"

                    if days_left < 0:
                        report["vulnerabilities"].append({
                            "title": "SSL Certificate Expired",
                            "severity": "Critical",
                            "layman": f"Expired {abs(days_left)} days ago.",
                            "tech_fix": "Renew SSL certificate immediately."
                        })
                        report["risk_score"] += 45
                        report["stats"]["high"] += 1
                    elif days_left < 30:
                        report["vulnerabilities"].append({
                            "title": "SSL Expiring Soon",
                            "severity": "Medium",
                            "layman": f"Certificate expires in {days_left} days.",
                            "tech_fix": "Plan renewal process."
                        })
                        report["risk_score"] += 20
                        report["stats"]["medium"] += 1
                    else:
                        report["good_practices"].append(f"Valid SSL (Expires in {days_left} days).")
                        report["stats"]["safe"] += 1

        except Exception:
            report["server_info"]["ssl_expiry"] = "Invalid"
            report["vulnerabilities"].append({
                "title": "No Valid SSL",
                "severity": "Critical",
                "layman": "Connection is not private or host unreachable.",
                "tech_fix": "Install a valid SSL Certificate."
            })
            report["risk_score"] += 40
            report["stats"]["high"] += 1

        # --- PHASE 2: Headers & Performance ---
        start_time = time.time()
        try:
            response = requests.get(url, headers=headers_ua, timeout=10, verify=False)
            latency = round((time.time() - start_time) * 1000)
            report["server_info"]["latency"] = f"{latency}ms"
            
            soup = BeautifulSoup(response.text, 'html.parser')
            headers = response.headers
        except Exception:
            return {"error": "Target unreachable."}

        # Header Checks
        checks = {
            "X-Frame-Options": ("Clickjacking", 10, "Medium"),
            "Content-Security-Policy": ("XSS Attacks", 15, "Medium"),
            "Strict-Transport-Security": ("MITM Attacks", 10, "Low"),
            "X-Content-Type-Options": ("MIME Sniffing", 5, "Low")
        }

        for h, (risk, score, sev) in checks.items():
            if h not in headers:
                report["vulnerabilities"].append({
                    "title": f"Missing {h}",
                    "severity": sev,
                    "layman": f"Vulnerable to {risk}.",
                    "tech_fix": f"Add '{h}' header."
                })
                report["risk_score"] += score
                report["stats"][sev.lower()] += 1
            else:
                report["good_practices"].append(f"Header {h} found.")
                report["stats"]["safe"] += 1

        # --- PHASE 3: Content Analysis ---
        # Insecure Forms
        forms = soup.find_all('form')
        for form in forms:
            if form.get('action', '').startswith("http://"):
                report["vulnerabilities"].append({
                    "title": "Insecure Login Form",
                    "severity": "High",
                    "layman": "Sends data over HTTP.",
                    "tech_fix": "Use HTTPS for form actions."
                })
                report["risk_score"] += 20
                report["stats"]["high"] += 1
                break

        # Email Exposure
        if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", response.text):
            report["vulnerabilities"].append({
                "title": "Email Exposure",
                "severity": "Low",
                "layman": "Emails visible to spammers.",
                "tech_fix": "Obfuscate emails."
            })
            report["risk_score"] += 5
            report["stats"]["low"] += 1

    except Exception:
        pass

    # Grading Logic
    score = min(report["risk_score"], 100)
    report["risk_score"] = score
    if score >= 80: report["grade"] = "F"
    elif score >= 60: report["grade"] = "D"
    elif score >= 40: report["grade"] = "C"
    elif score >= 20: report["grade"] = "B"
    else: report["grade"] = "A"

    return report