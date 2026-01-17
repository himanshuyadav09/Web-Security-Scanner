# 🛡️ Web Security Scanner

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Flask](https://img.shields.io/badge/Framework-Flask-green)
![License](https://img.shields.io/badge/License-MIT-orange)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

## 📖 Overview

The **Enterprise Web Security Scanner** is a "Black Box" vulnerability assessment tool designed to help developers and system administrators quickly audit the security posture of their websites. 

Unlike complex enterprise tools that take hours to run, this scanner provides an **instant, real-time analysis** of critical security headers, SSL certificate validity, and server configuration—all presented in a modern, easy-to-read dashboard.

## ✨ Key Features

* **🔍 Deep Header Analysis:** Checks for missing security headers (CSP, X-Frame-Options, HSTS, etc.) that protect against Clickjacking and XSS.
* **🔒 SSL/TLS Inspection:** Connects directly to port 443 to verify SSL certificates and calculates the exact **days remaining** until expiration.
* **📊 Risk Scoring Algorithm:** Generates a weighted Risk Score (0-100) and assigns a Letter Grade (A-F) based on findings.
* **🌍 Server Intelligence:** Fingerprints the target server to identify IP address, geolocation, and response latency.
* **📉 Visual Reporting:** Uses **Chart.js** to visualize the ratio of Critical, Medium, and Low vulnerabilities.
* **📄 PDF Export:** One-click "Save Report" feature for documentation and compliance.

## 🛠️ Tech Stack

* **Backend:** Python, Flask, Socket, SSL Module, BeautifulSoup4.
* **Frontend:** HTML5, CSS3, Vanilla JavaScript (ES6+).
* **Visualization:** Chart.js.
* **API:** Internal REST API for asynchronous scanning.

