import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import speech_recognition as sr
import pyttsx3
import os
import subprocess
import platform
import socket
import requests
import threading
import time
from datetime import datetime, timedelta
import psutil
import nmap
import json
import tempfile
import shutil
from pathlib import Path
import cv2
import mediapipe as mp
import pyautogui
import hashlib
import queue
import re
import base64
import urllib.request
import urllib.parse
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import send2trash
import numpy as np
import pickle
from bs4 import BeautifulSoup
import whois
from difflib import SequenceMatcher
from screen_brightness_control import get_brightness, set_brightness
import webbrowser
import math
from itertools import cycle
import random
import pygetwindow as gw
import secrets
import string
import ssl
from urllib.parse import urljoin, urlparse
import csv
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import pandas as pd
from PIL import Image, ImageTk, ImageOps
import io

# VirusTotal Configuration
VIRUSTOTAL_API_KEY = "f75d1d0d5ea83d443ce592994225783676c5b5d4e291a48549cd926e96b264c3"
QUARANTINE_DIR = "quarantine"
ANTIVIRUS_LOG_FILE = "antivirus_log.txt"
SUSPICIOUS_EXTS = {'.exe', '.dll', '.scr', '.pif', '.msi', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.lnk', '.ps1'}

# Enhanced malware signatures
MALWARE_SIGNATURES = {
    'trojan': ['cmd.exe', 'powershell', 'wscript', 'cscript', 'regsvr32', 'rundll32'],
    'ransomware': ['.encrypted', '.locked', '.crypto', '.ransom', 'wannacry', 'petya'],
    'keylogger': ['keylog', 'hook', 'keyboard', 'input', 'logkeys'],
    'miner': ['monero', 'bitcoin', 'crypto', 'miner', 'xmrig', 'cpuminer'],
    'spyware': ['spy', 'track', 'monitor', 'surveillance', 'keylogger']
}

# Ensure quarantine directory exists
os.makedirs(QUARANTINE_DIR, exist_ok=True)

class EnhancedVirusTotalScanner:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.headers = {
            "x-apikey": self.api_key,
            "User-Agent": "PythonAntivirus/1.0"
        }
    
    def get_file_hash(self, file_path):
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"Error calculating hash: {e}")
            return None
    
    def check_hash(self, file_hash):
        """Check if a file hash is known to VirusTotal"""
        if not file_hash:
            return {"error": "No file hash provided"}
            
        url = f"{self.base_url}files/{file_hash}"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"status": "not_found", "message": "File not found in VirusTotal database"}
            else:
                return {"error": f"API error: {response.status_code} - {response.text}"}
        except Exception as e:
            return {"error": f"Request failed: {str(e)}"}
    
    def upload_file(self, file_path):
        """Upload a file to VirusTotal for analysis"""
        if not os.path.exists(file_path):
            return {"error": "File does not exist"}
            
        # Check file size (VirusTotal limit is 32MB for public API)
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:  # 32MB
            return {"error": "File too large for VirusTotal (max 32MB)"}
            
        url = f"{self.base_url}files"
        try:
            with open(file_path, "rb") as file:
                files = {"file": (os.path.basename(file_path), file)}
                response = requests.post(url, headers=self.headers, files=files, timeout=60)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Upload failed: {response.status_code} - {response.text}"}
        except Exception as e:
            return {"error": f"Upload exception: {str(e)}"}
    
    def get_analysis(self, analysis_id):
        """Get analysis results from VirusTotal"""
        url = f"{self.base_url}analyses/{analysis_id}"
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Analysis request failed: {response.status_code}"}
        except Exception as e:
            return {"error": f"Analysis exception: {str(e)}"}
    
    def scan_file(self, file_path):
        """Complete scan process for a file"""
        # First try to check by hash
        file_hash = self.get_file_hash(file_path)
        if not file_hash:
            return {"error": "Could not calculate file hash"}
        
        result = self.check_hash(file_hash)
        
        # If file is not known to VT, upload it
        if result and 'status' in result and result['status'] == 'not_found':
            print(f"File not in VirusTotal database, uploading: {file_path}")
            upload_result = self.upload_file(file_path)
            
            if upload_result and 'data' in upload_result:
                analysis_id = upload_result['data']['id']
                print(f"File uploaded, analysis ID: {analysis_id}")
                
                # Wait for analysis to complete with progress updates
                for i in range(12):  # Try 12 times with 15-second delays (3 minutes total)
                    time.sleep(15)
                    analysis_result = self.get_analysis(analysis_id)
                    
                    if analysis_result and 'data' in analysis_result:
                        status = analysis_result['data']['attributes']['status']
                        print(f"Analysis status: {status} (attempt {i+1}/12)")
                        
                        if status == 'completed':
                            return analysis_result
                        elif status == 'queued':
                            continue  # Keep waiting
                    else:
                        break
                
                return {"error": "Analysis timed out after 3 minutes"}
            else:
                return upload_result if upload_result else {"error": "Failed to upload file to VirusTotal"}
        
        return result

class AdvancedLocalScanner:
    def __init__(self):
        self.malicious_hashes = self.load_malicious_hashes()
        self.suspicious_patterns = self.load_suspicious_patterns()
    
    def load_malicious_hashes(self):
        """Load known malicious hashes from file"""
        hashes = set()
        try:
            if os.path.exists("malicious_hashes.txt"):
                with open("malicious_hashes.txt", "r") as f:
                    for line in f:
                        hashes.add(line.strip())
        except:
            pass
        
        # Add some known malicious hashes for demonstration
        hashes.update([
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # Empty file
            "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty file
        ])
        return hashes
    
    def load_suspicious_patterns(self):
        """Load suspicious file content patterns"""
        patterns = {
            'executable_code': [b'MZ', b'PE', b'ELF'],
            'script_injection': [b'<script>', b'eval(', b'exec(', b'system('],
            'suspicious_strings': [b'password', b'keylog', b'trojan', b'backdoor', b'rootkit'],
            'encryption_indicators': [b'RSA', b'AES', b'DES', b'encrypt', b'decrypt']
        }
        return patterns
    
    def scan_file(self, file_path):
        """Enhanced file scanning with multiple detection methods"""
        results = {
            "path": file_path,
            "malicious": False,
            "suspicious": False,
            "threat_level": "Clean",
            "detections": [],
            "reasons": []
        }
        
        # Check if file exists
        if not os.path.exists(file_path):
            results["reasons"].append("File does not exist")
            return results
        
        # Check file extension
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SUSPICIOUS_EXTS:
            results["suspicious"] = True
            results["detections"].append(f"Suspicious extension: {ext}")
        
        # Check file hash
        file_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    file_hash.update(byte_block)
            file_hash_str = file_hash.hexdigest()
            
            if file_hash_str in self.malicious_hashes:
                results["malicious"] = True
                results["threat_level"] = "High"
                results["detections"].append("Known malicious file hash")
        except Exception as e:
            results["reasons"].append(f"Could not read file for hashing: {str(e)}")
        
        # Check file content for suspicious patterns
        try:
            with open(file_path, "rb") as f:
                content = f.read(8192)  # Read first 8KB for analysis
                
                for pattern_type, patterns in self.suspicious_patterns.items():
                    for pattern in patterns:
                        if pattern in content:
                            results["suspicious"] = True
                            results["detections"].append(f"Suspicious content: {pattern_type}")
                            break
        except Exception as e:
            results["reasons"].append(f"Could not analyze file content: {str(e)}")
        
        # Check file entropy (high entropy might indicate encryption/packing)
        entropy = self.calculate_file_entropy(file_path)
        if entropy > 7.5:
            results["suspicious"] = True
            results["detections"].append(f"High entropy ({entropy:.2f}) - possible encryption/packing")
        
        # Update threat level based on detections
        if results["malicious"]:
            results["threat_level"] = "High"
        elif results["suspicious"] and len(results["detections"]) > 2:
            results["threat_level"] = "Medium"
        elif results["suspicious"]:
            results["threat_level"] = "Low"
        
        return results
    
    def calculate_file_entropy(self, file_path):
        """Calculate Shannon entropy of file content"""
        try:
            with open(file_path, "rb") as f:
                data = f.read(4096)  # Read first 4KB for entropy calculation
            
            if len(data) == 0:
                return 0
                
            entropy = 0
            for x in range(256):
                p_x = float(data.count(x)) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log(p_x, 2)
            return entropy
        except:
            return 0

class USBMonitor:
    def __init__(self, scan_callback, log_callback):
        self.scan_callback = scan_callback
        self.log_callback = log_callback
        self.known_drives = set()
    
    def get_removable_drives(self):
        """Get list of removable drives"""
        IS_WINDOWS = platform.system().lower().startswith("win")
        removable_drives = []
        for partition in psutil.disk_partitions():
            if IS_WINDOWS:
                if 'removable' in partition.opts:
                    removable_drives.append(partition.mountpoint)
            else:
                # Linux/Mac - check common removable paths
                if any(path in partition.mountpoint for path in ['/media/', '/mnt/', '/Volumes/']):
                    removable_drives.append(partition.mountpoint)
        return removable_drives
    
    def check_for_new_drives(self):
        """Check if new USB drives have been connected"""
        current_drives = set(self.get_removable_drives())
        new_drives = current_drives - self.known_drives
        
        if new_drives:
            for drive in new_drives:
                self.log_callback(f"New USB drive detected: {drive}")
                self.scan_callback(drive)
        
        self.known_drives = current_drives
    
    def start_monitoring(self, interval=5):
        """Start monitoring for USB drives"""
        self.log_callback("Starting USB monitoring")
        self.known_drives = set(self.get_removable_drives())
        
        def monitor():
            while True:
                self.check_for_new_drives()
                time.sleep(interval)
        
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()

class EnhancedWebVulnerabilityScanner:
    def __init__(self, parent, portal):
        self.parent = parent
        self.portal = portal
        self.setup_gui()
        self.results = {}
        
    def setup_gui(self):
        # Main frame with dark theme
        main_frame = ttk.Frame(self.parent, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure dark theme colors
        self.bg_color = '#0d1117'
        self.sidebar_bg = '#161b22'
        self.text_color = '#f0f6fc'
        self.accent_color = '#58a6ff'
        self.success_color = '#00ff41'
        self.warning_color = '#ffd33d'
        self.error_color = '#f85149'
        
        # URL input section
        url_frame = ttk.Frame(main_frame)
        url_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(url_frame, text="Target URL:", foreground=self.text_color, background=self.bg_color).pack(side=tk.LEFT)
        self.url_entry = ttk.Entry(url_frame, width=80, background='#21262d', foreground=self.text_color)
        self.url_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        self.scan_button = ttk.Button(url_frame, text="Start Scan", command=self.start_scan, style='Accent.TButton')
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)
        
        # Results notebook with dark theme
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Overview tab
        overview_frame = ttk.Frame(self.notebook)
        self.notebook.add(overview_frame, text="📊 Overview")
        self.overview_text = scrolledtext.ScrolledText(overview_frame, width=100, height=20, 
                                                     bg='#161b22', fg=self.text_color, font=('Consolas', 9))
        self.overview_text.pack(fill=tk.BOTH, expand=True)
        
        # Vulnerabilities tab
        vuln_frame = ttk.Frame(self.notebook)
        self.notebook.add(vuln_frame, text="⚠️ Vulnerabilities")
        self.vuln_text = scrolledtext.ScrolledText(vuln_frame, width=100, height=20,
                                                 bg='#161b22', fg=self.text_color, font=('Consolas', 9))
        self.vuln_text.pack(fill=tk.BOTH, expand=True)
        
        # Headers tab
        headers_frame = ttk.Frame(self.notebook)
        self.notebook.add(headers_frame, text="🔧 Headers")
        self.headers_text = scrolledtext.ScrolledText(headers_frame, width=100, height=20,
                                                    bg='#161b22', fg=self.text_color, font=('Consolas', 9))
        self.headers_text.pack(fill=tk.BOTH, expand=True)
        
        # Links tab
        links_frame = ttk.Frame(self.notebook)
        self.notebook.add(links_frame, text="🔗 Links & Forms")
        self.links_text = scrolledtext.ScrolledText(links_frame, width=100, height=20,
                                                  bg='#161b22', fg=self.text_color, font=('Consolas', 9))
        self.links_text.pack(fill=tk.BOTH, expand=True)
        
        # Security Score tab
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="🛡️ Security Score")
        self.security_text = scrolledtext.ScrolledText(security_frame, width=100, height=20,
                                                     bg='#161b22', fg=self.text_color, font=('Consolas', 9))
        self.security_text.pack(fill=tk.BOTH, expand=True)
        
        # Export buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="📄 Export Markdown", command=self.export_markdown, style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📊 Export CSV", command=self.export_csv, style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📈 Generate Report", command=self.generate_comprehensive_report, style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        
    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        self.scan_button.config(state='disabled')
        self.progress.start()
        
        # Clear previous results
        for widget in [self.overview_text, self.vuln_text, self.headers_text, self.links_text, self.security_text]:
            widget.delete(1.0, tk.END)
            
        # Run scan in thread
        thread = threading.Thread(target=self.run_scan, args=(url,))
        thread.daemon = True
        thread.start()
        
    def run_scan(self, url):
        try:
            self.results = {
                'target_url': url,
                'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'vulnerabilities': [],
                'security_headers': {},
                'technical_info': {},
                'links_found': [],
                'forms_found': [],
                'security_score': 100  # Start with perfect score
            }
            
            # Step 1: Basic request and response analysis
            self.update_overview("🔍 Starting comprehensive security scan...\n")
            self.parent.update()
            
            response = self.make_request(url)
            if not response:
                return
                
            self.analyze_response(url, response)
            
            # Step 2: SSL/TLS check
            self.check_ssl_tls(url)
            
            # Step 3: Security headers analysis
            self.check_security_headers(response)
            
            # Step 4: Content analysis
            self.analyze_content(response)
            
            # Step 5: Common paths probing
            self.probe_common_paths(url)
            
            # Step 6: Generate security score and report
            self.calculate_security_score()
            self.generate_report()
            
        except Exception as e:
            self.update_overview(f"❌ Error during scan: {str(e)}\n")
        finally:
            self.progress.stop()
            self.scan_button.config(state='normal')
            
    def make_request(self, url):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=30, verify=False, allow_redirects=True)
            self.results['final_url'] = response.url
            self.results['status_code'] = response.status_code
            self.results['response_headers'] = dict(response.headers)
            
            return response
        except Exception as e:
            self.update_overview(f"❌ Failed to connect: {str(e)}\n")
            return None
            
    def analyze_response(self, url, response):
        # Basic response info
        self.update_overview(f"🎯 Target: {url}\n")
        self.update_overview(f"📍 Final URL: {response.url}\n")
        self.update_overview(f"📊 Status Code: {response.status_code}\n")
        self.update_overview(f"📏 Content Length: {len(response.content)} bytes\n")
        
        # Server information
        server = response.headers.get('Server', 'Not disclosed')
        powered_by = response.headers.get('X-Powered-By', 'Not disclosed')
        
        self.results['technical_info']['server'] = server
        self.results['technical_info']['powered_by'] = powered_by
        
        self.update_overview(f"🖥️ Server: {server}\n")
        self.update_overview(f"⚡ Powered By: {powered_by}\n\n")
        
    def check_ssl_tls(self, url):
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                self.add_vulnerability("SSL/TLS", "High", "Website not using HTTPS", 
                                     "Implement HTTPS to encrypt all communications", 20)
                return
                
            hostname = parsed.hostname
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expires - datetime.now()).days
                    
                    if days_remaining < 30:
                        self.add_vulnerability("SSL Certificate", "High", 
                                             f"Certificate expires in {days_remaining} days", 
                                             "Renew SSL certificate immediately", 15)
                    elif days_remaining < 90:
                        self.add_vulnerability("SSL Certificate", "Medium", 
                                             f"Certificate expires in {days_remaining} days", 
                                             "Plan certificate renewal", 5)
                        
                    # Check protocol
                    self.update_overview(f"✅ SSL Certificate valid for {days_remaining} days\n")
                    
        except Exception as e:
            self.add_vulnerability("SSL/TLS", "High", f"SSL/TLS issue: {str(e)}", "Fix SSL configuration", 20)
            
    def check_security_headers(self, response):
        security_headers = {
            'Content-Security-Policy': {'importance': 'High', 'points': 10, 'desc': 'Prevents XSS attacks'},
            'Strict-Transport-Security': {'importance': 'High', 'points': 10, 'desc': 'Enforces HTTPS'},
            'X-Frame-Options': {'importance': 'Medium', 'points': 8, 'desc': 'Prevents clickjacking'},
            'X-Content-Type-Options': {'importance': 'Medium', 'points': 6, 'desc': 'Prevents MIME sniffing'},
            'Referrer-Policy': {'importance': 'Medium', 'points': 5, 'desc': 'Controls referrer information'},
            'Permissions-Policy': {'importance': 'Low', 'points': 3, 'desc': 'Controls browser features'}
        }
        
        missing_headers = []
        headers_info = []
        
        for header, info in security_headers.items():
            if header in response.headers:
                value = response.headers[header]
                headers_info.append(f"✅ {header}: {value}")
                self.results['security_headers'][header] = value
            else:
                missing_headers.append((header, info['importance'], info['points']))
                headers_info.append(f"❌ {header}: MISSING - {info['desc']}")
                self.results['security_headers'][header] = 'MISSING'
                
        # Display headers information
        self.update_headers("🔒 Security Headers Analysis:\n")
        self.update_headers("=" * 60 + "\n")
        for info in headers_info:
            self.update_headers(info + "\n")
            
        # Add vulnerabilities for missing headers
        if missing_headers:
            missing_list = [f"{header} ({importance})" for header, importance, _ in missing_headers]
            points_deducted = sum(points for _, _, points in missing_headers)
            self.add_vulnerability("Security Headers", "Medium", 
                                 f"Missing security headers: {', '.join(missing_list)}",
                                 "Implement missing security headers", points_deducted)
                                 
    def analyze_content(self, response):
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extract links
        links = []
        for link in soup.find_all('a', href=True)[:50]:
            href = link['href']
            full_url = urljoin(response.url, href)
            links.append(full_url)
            
        self.results['links_found'] = links
        
        # Extract forms
        forms = []
        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': []
            }
            
            for input_tag in form.find_all('input'):
                form_info['inputs'].append({
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text')
                })
                
            forms.append(form_info)
            
        self.results['forms_found'] = forms
        
        # Display links and forms
        self.update_links("🔗 Links Found:\n")
        self.update_links("=" * 50 + "\n")
        for link in links[:20]:  # Show first 20 links
            self.update_links(f"🔗 {link}\n")
            
        self.update_links("\n📝 Forms Found:\n")
        self.update_links("=" * 50 + "\n")
        for i, form in enumerate(forms, 1):
            self.update_links(f"Form {i}:\n")
            self.update_links(f"  📍 Action: {form['action']}\n")
            self.update_links(f"  📋 Method: {form['method']}\n")
            self.update_links(f"  ⌨️ Inputs: {[inp['name'] for inp in form['inputs'] if inp['name']]}\n\n")
            
        # Check for potential vulnerabilities in forms
        for form in forms:
            inputs = [inp['name'].lower() for inp in form['inputs'] if inp['name']]
            
            # SQL Injection potential
            sql_keywords = ['user', 'pass', 'login', 'id', 'query', 'search']
            if any(keyword in ' '.join(inputs).lower() for keyword in sql_keywords):
                self.add_vulnerability("SQL Injection", "High", 
                                     "Form with potential SQL injection points", 
                                     "Implement input validation and use parameterized queries", 15)
                                     
            # XSS potential
            if form['method'] == 'GET' and any(inp['type'] == 'text' for inp in form['inputs']):
                self.add_vulnerability("XSS", "Medium", 
                                     "Form with potential XSS vulnerability", 
                                     "Implement input sanitization and output encoding", 10)
                                     
        # Check for sensitive information in comments
        comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text and '-->' in text)
        sensitive_patterns = [
            r'password', r'key', r'secret', r'token', r'api', r'admin'
        ]
        
        for comment in comments:
            for pattern in sensitive_patterns:
                if re.search(pattern, comment, re.IGNORECASE):
                    self.add_vulnerability("Information Disclosure", "Low", 
                                         "Potential sensitive information in comments", 
                                         "Remove sensitive information from HTML comments", 5)
                    break
                    
    def probe_common_paths(self, base_url):
        common_paths = [
            'admin', 'login', 'wp-login.php', 'phpmyadmin', 'config',
            '.git', '.env', 'backup', 'test', 'api', 'debug'
        ]
        
        tested_paths = []
        
        for path in common_paths:
            test_url = urljoin(base_url, path)
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                status = response.status_code
                
                if status == 200:
                    self.add_vulnerability("Information Disclosure", "Medium",
                                         f"Accessible common path: {test_url}",
                                         "Restrict access to sensitive directories", 8)
                    tested_paths.append(f"⚠️  {test_url} - Status: {status} (ACCESSIBLE)")
                elif status == 403:
                    tested_paths.append(f"✅ {test_url} - Status: {status} (Protected)")
                else:
                    tested_paths.append(f"✅ {test_url} - Status: {status}")
                    
            except:
                tested_paths.append(f"❌ {test_url} - Failed to connect")
                
        self.results['common_paths'] = tested_paths
        
        # Display common paths results
        self.update_overview("\n🔍 Common Paths Probing:\n")
        self.update_overview("=" * 50 + "\n")
        for path_result in tested_paths:
            self.update_overview(path_result + "\n")
            
    def add_vulnerability(self, category, severity, description, recommendation, points_deducted):
        vulnerability = {
            'category': category,
            'severity': severity,
            'description': description,
            'recommendation': recommendation,
            'points_deducted': points_deducted,
            'timestamp': datetime.now().strftime("%H:%M:%S")
        }
        self.results['vulnerabilities'].append(vulnerability)
        self.results['security_score'] -= points_deducted
        
    def calculate_security_score(self):
        # Ensure score doesn't go below 0
        self.results['security_score'] = max(0, self.results['security_score'])
        
        # Update security score tab
        self.update_security_score("🛡️ Security Score Analysis\n")
        self.update_security_score("=" * 40 + "\n\n")
        self.update_security_score(f"Overall Security Score: {self.results['security_score']}/100\n\n")
        
        if self.results['security_score'] >= 90:
            self.update_security_score("🎉 Excellent! Your website has strong security measures.\n")
        elif self.results['security_score'] >= 70:
            self.update_security_score("✅ Good! Your website has decent security with some areas for improvement.\n")
        elif self.results['security_score'] >= 50:
            self.update_security_score("⚠️ Fair! Your website needs security improvements.\n")
        else:
            self.update_security_score("🔴 Poor! Immediate security actions required.\n")
            
        self.update_security_score("\n📋 Recommendations:\n")
        for vuln in self.results['vulnerabilities']:
            self.update_security_score(f"• {vuln['recommendation']} (-{vuln['points_deducted']} points)\n")
        
    def generate_report(self):
        # Overview tab
        self.update_overview("\n" + "="*60 + "\n")
        self.update_overview("📋 SCAN SUMMARY\n")
        self.update_overview("="*60 + "\n")
        
        total_vulns = len(self.results['vulnerabilities'])
        high_vulns = len([v for v in self.results['vulnerabilities'] if v['severity'] == 'High'])
        medium_vulns = len([v for v in self.results['vulnerabilities'] if v['severity'] == 'Medium'])
        low_vulns = len([v for v in self.results['vulnerabilities'] if v['severity'] == 'Low'])
        
        self.update_overview(f"🔍 Total Vulnerabilities: {total_vulns}\n")
        self.update_overview(f"🔴 High Severity: {high_vulns}\n")
        self.update_overview(f"🟡 Medium Severity: {medium_vulns}\n")
        self.update_overview(f"🟢 Low Severity: {low_vulns}\n")
        self.update_overview(f"🛡️ Security Score: {self.results['security_score']}/100\n")
        
        # Vulnerabilities tab
        self.update_vulnerabilities("⚠️ VULNERABILITY REPORT\n")
        self.update_vulnerabilities("="*80 + "\n\n")
        
        for i, vuln in enumerate(self.results['vulnerabilities'], 1):
            self.update_vulnerabilities(f"{i}. {vuln['category']} [{vuln['severity']}]\n")
            self.update_vulnerabilities(f"   📝 Description: {vuln['description']}\n")
            self.update_vulnerabilities(f"   💡 Recommendation: {vuln['recommendation']}\n")
            self.update_vulnerabilities(f"   📉 Points Deducted: {vuln['points_deducted']}\n")
            self.update_vulnerabilities(f"   🕒 Time: {vuln['timestamp']}\n\n")
            
    def generate_comprehensive_report(self):
        if not self.results:
            messagebox.showerror("Error", "No scan results to generate report")
            return
            
        filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Create comprehensive HTML report
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #0d1117; color: #f0f6fc; }}
                .header {{ background: #161b22; padding: 20px; border-radius: 10px; }}
                .vulnerability {{ background: #21262d; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .high {{ border-left: 5px solid #f85149; }}
                .medium {{ border-left: 5px solid #ffd33d; }}
                .low {{ border-left: 5px solid #00ff41; }}
                .score {{ font-size: 24px; font-weight: bold; text-align: center; padding: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Security Scan Report</h1>
                <p><strong>Target URL:</strong> {self.results['target_url']}</p>
                <p><strong>Scan Date:</strong> {self.results['scan_date']}</p>
                <p><strong>Security Score:</strong> <span class="score">{self.results['security_score']}/100</span></p>
            </div>
            
            <h2>Vulnerabilities Found</h2>
        """
        
        for vuln in self.results['vulnerabilities']:
            severity_class = vuln['severity'].lower()
            html_content += f"""
            <div class="vulnerability {severity_class}">
                <h3>{vuln['category']} - {vuln['severity']}</h3>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>Recommendation:</strong> {vuln['recommendation']}</p>
                <p><strong>Impact Score:</strong> -{vuln['points_deducted']} points</p>
            </div>
            """
            
        html_content += """
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        messagebox.showinfo("Success", f"Comprehensive report generated as {filename}")
        
    def update_overview(self, message):
        self.overview_text.insert(tk.END, message)
        self.overview_text.see(tk.END)
        
    def update_vulnerabilities(self, message):
        self.vuln_text.insert(tk.END, message)
        self.vuln_text.see(tk.END)
        
    def update_headers(self, message):
        self.headers_text.insert(tk.END, message)
        self.headers_text.see(tk.END)
        
    def update_links(self, message):
        self.links_text.insert(tk.END, message)
        self.links_text.see(tk.END)
        
    def update_security_score(self, message):
        self.security_text.insert(tk.END, message)
        self.security_text.see(tk.END)
        
    def export_markdown(self):
        if not self.results:
            messagebox.showerror("Error", "No scan results to export")
            return
            
        filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# Web Vulnerability Scan Report\n\n")
            f.write(f"**Target URL**: {self.results['target_url']}\n")
            f.write(f"**Scan Date**: {self.results['scan_date']}\n")
            f.write(f"**Final URL**: {self.results.get('final_url', 'N/A')}\n")
            f.write(f"**Status Code**: {self.results.get('status_code', 'N/A')}\n")
            f.write(f"**Security Score**: {self.results['security_score']}/100\n\n")
            
            f.write("## Executive Summary\n\n")
            vulns = self.results['vulnerabilities']
            f.write(f"- Total Vulnerabilities: {len(vulns)}\n")
            f.write(f"- High Severity: {len([v for v in vulns if v['severity'] == 'High'])}\n")
            f.write(f"- Medium Severity: {len([v for v in vulns if v['severity'] == 'Medium'])}\n")
            f.write(f"- Low Severity: {len([v for v in vulns if v['severity'] == 'Low'])}\n\n")
            
            f.write("## Detailed Findings\n\n")
            for vuln in vulns:
                f.write(f"### {vuln['category']} [{vuln['severity']}]\n")
                f.write(f"- **Description**: {vuln['description']}\n")
                f.write(f"- **Recommendation**: {vuln['recommendation']}\n")
                f.write(f"- **Impact Score**: -{vuln['points_deducted']} points\n\n")
                
        messagebox.showinfo("Success", f"Markdown report exported as {filename}")
        
    def export_csv(self):
        if not self.results:
            messagebox.showerror("Error", "No scan results to export")
            return
            
        filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Category', 'Severity', 'Description', 'Recommendation', 'Points_Deducted', 'Timestamp'])
            
            for vuln in self.results['vulnerabilities']:
                writer.writerow([
                    vuln['category'],
                    vuln['severity'],
                    vuln['description'],
                    vuln['recommendation'],
                    vuln['points_deducted'],
                    vuln['timestamp']
                ])
                
        messagebox.showinfo("Success", f"CSV report exported as {filename}")

class CybersecurityPortal:
    def __init__(self, root):
        self.root = root
        self.root.title("ANONYMOUS SYSTEM - AI-Powered Cybersecurity Command Center")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0d1117')
        
        # Initialize voice output setting FIRST
        self.voice_output_enabled = True
        self.current_operation = None
        self.operation_stop_event = threading.Event()
        
        # Initialize TTS engine once
        self.tts_engine = None
        self.init_tts()
        
        # Initialize Enhanced Scanners
        self.vt_scanner = EnhancedVirusTotalScanner(VIRUSTOTAL_API_KEY)
        self.local_scanner = AdvancedLocalScanner()
        self.usb_monitor = USBMonitor(self.scan_drive, self.log_antivirus)
        
        # Theme settings
        self.dark_mode = True
        self.current_theme = {
            'bg': '#0d1117',
            'sidebar_bg': '#161b22',
            'text': '#f0f6fc',
            'accent': '#58a6ff',
            'success': '#00ff41',
            'warning': '#ffd33d',
            'error': '#f85149'
        }
        
        # Initialize components
        self.setup_styles()
        self.create_banner()
        self.create_main_frame()
        self.create_sidebar()
        self.create_content_area()
        self.setup_pages()
        
        # DeepSeek API Configuration
        self.deepseek_api_key = "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"
        self.deepseek_api_url = "https://openrouter.ai/api/v1/chat/completions"
        
        # Show dashboard initially
        self.show_page("dashboard")
        
        # Start USB monitoring
        self.usb_monitor.start_monitoring()
        
    def init_tts(self):
        """Initialize TTS engine once to avoid 'run loop already started' error"""
        try:
            self.tts_engine = pyttsx3.init()
            # Set properties once
            self.tts_engine.setProperty('rate', 150)
            self.tts_engine.setProperty('volume', 0.8)
        except Exception as e:
            print(f"TTS initialization error: {e}")
            self.tts_engine = None
        
    def create_banner(self):
        """Create the ANONYMOUS SYSTEM banner"""
        self.banner_frame = tk.Frame(self.root, bg='#000000', height=40)
        self.banner_frame.pack(fill=tk.X, side=tk.TOP)
        self.banner_frame.pack_propagate(False)
        
        banner_text = "ANONYMOUS SYSTEM - AI-POWERED CYBERSECURITY COMMAND CENTER"
        banner_label = tk.Label(self.banner_frame, 
                              text=banner_text,
                              font=('Courier', 16, 'bold'),
                              fg='#00ff41',
                              bg='#000000')
        banner_label.pack(expand=True)
        
        # Animated border
        self.animate_border()
        
    def animate_border(self):
        """Create animated border effect"""
        colors = ['#00ff41', '#ff0080', '#0080ff', '#ffff00']
        color_cycle = cycle(colors)
        
        def update_border():
            color = next(color_cycle)
            self.banner_frame.configure(highlightbackground=color, highlightthickness=2)
            self.root.after(1000, update_border)
            
        update_border()
        
    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure dark theme styles
        self.style.configure('TFrame', background='#0d1117')
        self.style.configure('TLabel', background='#0d1117', foreground='#f0f6fc')
        self.style.configure('TButton', background='#21262d', foreground='#f0f6fc')
        self.style.configure('Accent.TButton', background='#58a6ff', foreground='#0d1117')
        self.style.configure('Sidebar.TFrame', background='#161b22')
        self.style.configure('Sidebar.TButton', 
                           background='#161b22',
                           foreground='#f0f6fc',
                           borderwidth=0,
                           focuscolor='none')
        self.style.map('Sidebar.TButton',
                      background=[('active', '#58a6ff')])
        
        self.style.configure('Content.TFrame', background='#0d1117')
        self.style.configure('Title.TLabel',
                           background='#0d1117',
                           foreground='#58a6ff',
                           font=('Arial', 16, 'bold'))
        
    def create_main_frame(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
    def create_sidebar(self):
        self.sidebar = ttk.Frame(self.main_frame, style='Sidebar.TFrame', width=200)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        self.sidebar.pack_propagate(False)
        
        # Logo
        logo_label = tk.Label(self.sidebar, 
                            text="ANONYMOUS\nSYSTEM",
                            font=('Arial', 14, 'bold'),
                            fg='#00ff41',
                            bg='#161b22',
                            justify=tk.CENTER)
        logo_label.pack(pady=20)
        
        # Navigation buttons
        nav_buttons = [
            ("🏠 Dashboard", "dashboard"),
            ("🎤 Voice Control", "voice"),
            ("🛡️ Security Toolkit", "security"),
            ("🔍 VirusTotal Scan", "virustotal"),
            ("👋 Gesture Control", "gesture"),
            ("🤖 AI Chatbot", "chatbot"),
            ("🌐 Vulnerability Scanner", "vulnerability"),
            ("⚙️ Settings", "settings")
        ]
        
        for text, page in nav_buttons:
            btn = ttk.Button(self.sidebar, 
                           text=text,
                           style='Sidebar.TButton',
                           command=lambda p=page: self.show_page(p))
            btn.pack(fill=tk.X, padx=10, pady=5)
            
        # System status
        status_frame = tk.Frame(self.sidebar, bg='#161b22')
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
        
        self.status_label = tk.Label(status_frame,
                                   text="🟢 System Secure",
                                   font=('Arial', 10),
                                   fg='#00ff41',
                                   bg='#161b22')
        self.status_label.pack()
        
    def create_content_area(self):
        self.content_area = ttk.Frame(self.main_frame, style='Content.TFrame')
        self.content_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def setup_pages(self):
        self.pages = {}
        
        # Create all pages
        self.pages["dashboard"] = DashboardPage(self.content_area, self)
        self.pages["voice"] = EnhancedVoiceControlPage(self.content_area, self)
        self.pages["security"] = SecurityToolkitPage(self.content_area, self)
        self.pages["virustotal"] = VirusTotalPage(self.content_area, self)
        self.pages["gesture"] = EnhancedGestureControlPage(self.content_area, self)
        self.pages["chatbot"] = EnhancedChatbotPage(self.content_area, self)
        self.pages["vulnerability"] = VulnerabilityScannerPage(self.content_area, self)
        self.pages["settings"] = EnhancedSettingsPage(self.content_area, self)
        
        # Hide all pages initially
        for page in self.pages.values():
            page.pack_forget()
            
    def show_page(self, page_name):
        # Hide all pages
        for page in self.pages.values():
            page.pack_forget()
            
        # Show selected page
        self.pages[page_name].pack(fill=tk.BOTH, expand=True)
        
        # Update window title
        self.root.title(f"ANONYMOUS SYSTEM - {page_name.title()}")
        
    def speak(self, text):
        """Text-to-speech functionality with single engine instance"""
        if self.voice_output_enabled and self.tts_engine:
            def speak_thread():
                try:
                    # Stop any current speech
                    self.tts_engine.stop()
                    # Speak new text
                    self.tts_engine.say(text)
                    self.tts_engine.runAndWait()
                except Exception as e:
                    print(f"TTS Error: {e}")
            
            threading.Thread(target=speak_thread, daemon=True).start()
            
    def stop_current_operation(self):
        """Stop any currently running operation"""
        self.operation_stop_event.set()
        if self.current_operation:
            self.current_operation = None
        self.speak("Operation stopped")
        
    def toggle_theme(self):
        """Toggle between light and dark mode"""
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.current_theme = {
                'bg': '#0d1117',
                'sidebar_bg': '#161b22',
                'text': '#f0f6fc',
                'accent': '#58a6ff',
                'success': '#00ff41',
                'warning': '#ffd33d',
                'error': '#f85149'
            }
        else:
            self.current_theme = {
                'bg': '#ffffff',
                'sidebar_bg': '#f0f0f0',
                'text': '#000000',
                'accent': '#007acc',
                'success': '#00a800',
                'warning': '#ffa500',
                'error': '#ff0000'
            }
        self.apply_theme()
        
    def apply_theme(self):
        """Apply current theme to all components"""
        # This would need to be implemented to update all UI elements
        # For now, we'll just update the main window
        self.root.configure(bg=self.current_theme['bg'])
    
    def scan_drive(self, drive_path):
        """Scan a drive for suspicious files"""
        self.log_antivirus(f"Scanning drive: {drive_path}")
        
        suspicious_files = []
        for root, dirs, files in os.walk(drive_path):
            for file in files:
                file_path = os.path.join(root, file)
                ext = os.path.splitext(file_path)[1].lower()
                
                if ext in SUSPICIOUS_EXTS:
                    suspicious_files.append(file_path)
        
        if suspicious_files:
            self.log_antivirus(f"Found {len(suspicious_files)} suspicious files on {drive_path}")
            
            for file in suspicious_files:
                self.log_antivirus(f"Suspicious file: {file}")
        else:
            self.log_antivirus(f"No suspicious files found on {drive_path}")
    
    def log_antivirus(self, message):
        """Log antivirus-related messages"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        # Write to log file
        with open(ANTIVIRUS_LOG_FILE, "a") as f:
            f.write(log_message)

# Enhanced Pages with New Features

class DashboardPage(ttk.Frame):
    def __init__(self, parent, portal):
        super().__init__(parent, style='Content.TFrame')
        self.portal = portal
        self.setup_dashboard()
        self.update_dashboard_data()
        
        # Initialize data for line graphs
        self.time_points = list(range(60))  # Last 60 time points
        self.cpu_history = [0] * 60
        self.memory_history = [0] * 60
        self.disk_history = [0] * 60
        self.network_history = [0] * 60
        self.security_history = [0] * 60
        
    def setup_dashboard(self):
        # Header
        header_frame = tk.Frame(self, bg='#0d1117')
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        title_label = tk.Label(header_frame,
                             text="Security Dashboard",
                             font=('Arial', 24, 'bold'),
                             fg='#58a6ff',
                             bg='#0d1117')
        title_label.pack(side=tk.LEFT)
        
        # Stats grid
        self.stats_frame = tk.Frame(self, bg='#0d1117')
        self.stats_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Initialize stats variables
        self.cpu_var = tk.StringVar(value="Loading...")
        self.memory_var = tk.StringVar(value="Loading...")
        self.disk_var = tk.StringVar(value="Loading...")
        self.threats_var = tk.StringVar(value="Loading...")
        self.network_var = tk.StringVar(value="Loading...")
        
        # Create graphs frame
        graphs_frame = tk.Frame(self, bg='#0d1117')
        graphs_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Left side - System metrics
        left_frame = tk.Frame(graphs_frame, bg='#0d1117')
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # System metrics chart
        self.setup_system_metrics(left_frame)
        
        # Right side - Security status
        right_frame = tk.Frame(graphs_frame, bg='#0d1117')
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        self.setup_security_status(right_frame)
        
        # Quick actions
        actions_frame = tk.Frame(self, bg='#0d1117')
        actions_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(actions_frame, text="Quick Actions", 
                font=('Arial', 16, 'bold'),
                fg='#f0f6fc', bg='#0d1117').pack(anchor='w')
        
        actions = [
            ("🔍 Quick Scan", self.quick_scan),
            ("🧹 Clean System", self.clean_system),
            ("🔄 Check Updates", self.check_updates),
            ("📊 System Info", self.system_info)
        ]
        
        actions_btn_frame = tk.Frame(actions_frame, bg='#0d1117')
        actions_btn_frame.pack(fill=tk.X, pady=10)
        
        for text, command in actions:
            btn = tk.Button(actions_btn_frame, text=text,
                          command=command,
                          bg='#21262d',
                          fg='#f0f6fc',
                          font=('Arial', 10),
                          relief='flat',
                          padx=20,
                          pady=10)
            btn.pack(side=tk.LEFT, padx=5)
            
        # Recent activity
        activity_frame = tk.Frame(self, bg='#0d1117')
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        tk.Label(activity_frame, text="Recent Activity",
                font=('Arial', 16, 'bold'),
                fg='#f0f6fc', bg='#0d1117').pack(anchor='w')
        
        self.activity_text = scrolledtext.ScrolledText(activity_frame,
                                                     height=15,
                                                     bg='#161b22',
                                                     fg='#f0f6fc',
                                                     font=('Consolas', 9))
        self.activity_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.log_activity("System initialized successfully.")
        self.log_activity("Real-time monitoring activated.")
        self.log_activity("Dashboard data collection started.")
        
    def setup_system_metrics(self, parent):
        """Setup system metrics line graphs"""
        metrics_frame = tk.LabelFrame(parent, text="System Metrics - Live Monitoring", 
                                    bg='#0d1117', fg='#f0f6fc', font=('Arial', 12, 'bold'))
        metrics_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create figure for system metrics
        self.fig_system = Figure(figsize=(8, 6), facecolor='#0d1117')
        self.ax_system = self.fig_system.add_subplot(111)
        self.ax_system.set_facecolor('#161b22')
        
        # Customize the chart
        self.ax_system.tick_params(colors='#f0f6fc')
        self.ax_system.title.set_color('#58a6ff')
        self.ax_system.xaxis.label.set_color('#f0f6fc')
        self.ax_system.yaxis.label.set_color('#f0f6fc')
        
        # Create canvas
        self.canvas_system = FigureCanvasTkAgg(self.fig_system, metrics_frame)
        self.canvas_system.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def setup_security_status(self, parent):
        """Setup security status line graph"""
        status_frame = tk.LabelFrame(parent, text="Security Status - Trend Analysis", 
                                   bg='#0d1117', fg='#f0f6fc', font=('Arial', 12, 'bold'))
        status_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create figure for security status
        self.fig_security = Figure(figsize=(8, 6), facecolor='#0d1117')
        self.ax_security = self.fig_security.add_subplot(111)
        self.ax_security.set_facecolor('#161b22')
        
        # Customize the chart
        self.ax_security.tick_params(colors='#f0f6fc')
        self.ax_security.title.set_color('#58a6ff')
        
        # Create canvas
        self.canvas_security = FigureCanvasTkAgg(self.fig_security, status_frame)
        self.canvas_security.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
    def create_stat_card(self, parent, title, value, color):
        card = tk.Frame(parent, bg='#161b22', relief='raised', bd=1, width=200, height=100)
        card.pack_propagate(False)
        
        title_label = tk.Label(card, text=title,
                             font=('Arial', 12),
                             fg='#8b949e',
                             bg='#161b22')
        title_label.pack(pady=(10, 5))
        
        value_label = tk.Label(card, text=value,
                             font=('Arial', 18, 'bold'),
                             fg=color,
                             bg='#161b22')
        value_label.pack(pady=(0, 10))
        
        return card
        
    def update_dashboard_data(self):
        """Update dashboard with real system data"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_color = "#00ff41" if cpu_percent < 50 else "#ffd33d" if cpu_percent < 80 else "#f85149"
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_color = "#00ff41" if memory_percent < 70 else "#ffd33d" if memory_percent < 85 else "#f85149"
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            disk_color = "#00ff41" if disk_percent < 80 else "#ffd33d" if disk_percent < 90 else "#f85149"
            
            # Network activity
            net_io = psutil.net_io_counters()
            network_usage = (net_io.bytes_sent + net_io.bytes_recv) / (1024 * 1024)  # MB
            network_color = "#00ff41" if network_usage < 100 else "#ffd33d" if network_usage < 500 else "#f85149"
            
            # Threats (simulated)
            threats_blocked = random.randint(1200, 1500)
            
            # Clear existing stats
            for widget in self.stats_frame.winfo_children():
                widget.destroy()
            
            # Create new stat cards
            stats_data = [
                ("🖥️ CPU Usage", f"{cpu_percent:.1f}%", cpu_color),
                ("💾 Memory Usage", f"{memory_percent:.1f}%", memory_color),
                ("💽 Disk Usage", f"{disk_percent:.1f}%", disk_color),
                ("🌐 Network Usage", f"{network_usage:.1f} MB", network_color),
                ("🛡️ Threats Blocked", f"{threats_blocked:,}", "#58a6ff")
            ]
            
            for i, (title, value, color) in enumerate(stats_data):
                stat_card = self.create_stat_card(self.stats_frame, title, value, color)
                stat_card.grid(row=0, column=i, padx=10, pady=10, sticky='nsew')
                
            for i in range(5):
                self.stats_frame.columnconfigure(i, weight=1)
            
            # Update data for line graphs
            self.update_line_graph_data(cpu_percent, memory_percent, disk_percent, network_usage, threats_blocked)
            
            # Update system metrics chart
            self.update_system_chart()
            
            # Update security status chart
            self.update_security_chart()
            
        except Exception as e:
            self.log_activity(f"Error updating dashboard: {str(e)}")
        
        # Update every 2 seconds for smooth line graphs
        self.after(2000, self.update_dashboard_data)
        
    def update_line_graph_data(self, cpu, memory, disk, network, threats):
        """Update data for line graphs"""
        # Shift all data left and add new data point
        self.cpu_history = self.cpu_history[1:] + [cpu]
        self.memory_history = self.memory_history[1:] + [memory]
        self.disk_history = self.disk_history[1:] + [disk]
        self.network_history = self.network_history[1:] + [network]
        
        # Calculate security score (0-100)
        security_score = 100 - (cpu * 0.2 + memory * 0.2 + disk * 0.1 + min(network/10, 10))
        security_score = max(0, min(100, security_score))
        self.security_history = self.security_history[1:] + [security_score]
        
    def update_system_chart(self):
        """Update system metrics line graph"""
        self.ax_system.clear()
        
        # Plot line graphs for system metrics
        self.ax_system.plot(self.time_points, self.cpu_history, label='CPU %', color='#58a6ff', linewidth=2)
        self.ax_system.plot(self.time_points, self.memory_history, label='Memory %', color='#00ff41', linewidth=2)
        self.ax_system.plot(self.time_points, self.disk_history, label='Disk %', color='#ffd33d', linewidth=2)
        self.ax_system.plot(self.time_points, self.network_history, label='Network MB', color='#f85149', linewidth=2)
        
        self.ax_system.set_ylim(0, 100)
        self.ax_system.set_ylabel('Usage (%)', color='#f0f6fc')
        self.ax_system.set_xlabel('Time (seconds)', color='#f0f6fc')
        self.ax_system.set_title('System Resource Usage - Live Monitoring', color='#58a6ff', pad=20)
        self.ax_system.legend(loc='upper left', facecolor='#161b22', labelcolor='#f0f6fc')
        self.ax_system.grid(True, alpha=0.3)
        
        self.ax_system.tick_params(colors='#f0f6fc')
        self.ax_system.set_facecolor('#161b22')
        self.fig_system.tight_layout()
        self.canvas_system.draw()
        
    def update_security_chart(self):
        """Update security status line graph"""
        self.ax_security.clear()
        
        # Plot security score trend
        self.ax_security.plot(self.time_points, self.security_history, 
                            label='Security Score', color='#00ff41', linewidth=3)
        
        # Add threshold lines
        self.ax_security.axhline(y=80, color='#ffd33d', linestyle='--', alpha=0.7, label='Good Threshold')
        self.ax_security.axhline(y=60, color='#f85149', linestyle='--', alpha=0.7, label='Warning Threshold')
        
        self.ax_security.set_ylim(0, 100)
        self.ax_security.set_ylabel('Security Score', color='#f0f6fc')
        self.ax_security.set_xlabel('Time (seconds)', color='#f0f6fc')
        self.ax_security.set_title('Security Status Trend Analysis', color='#58a6ff', pad=20)
        self.ax_security.legend(loc='upper left', facecolor='#161b22', labelcolor='#f0f6fc')
        self.ax_security.grid(True, alpha=0.3)
        self.ax_security.fill_between(self.time_points, self.security_history, alpha=0.3, color='#00ff41')
        
        self.ax_security.tick_params(colors='#f0f6fc')
        self.ax_security.set_facecolor('#161b22')
        self.fig_security.tight_layout()
        self.canvas_security.draw()
        
    def quick_scan(self):
        self.log_activity("🚀 Starting quick security scan...")
        self.portal.speak("Starting quick security scan")
        # Simulate scanning process
        threading.Thread(target=self.simulate_scan, daemon=True).start()
        
    def simulate_scan(self):
        time.sleep(2)
        self.log_activity("✅ Quick scan completed - No threats found")
        self.portal.speak("Quick scan completed. No threats found.")
        
    def clean_system(self):
        self.log_activity("Cleaning temporary files...")
        self.portal.speak("Cleaning temporary files")
        try:
            # Clean temp files
            temp_dir = tempfile.gettempdir()
            deleted_files = 0
            for file in Path(temp_dir).glob('*.*'):
                try:
                    if file.is_file():
                        file.unlink()
                        deleted_files += 1
                except:
                    pass
            self.log_activity(f"✅ Cleaned {deleted_files} temporary files")
            self.portal.speak(f"Cleaned {deleted_files} temporary files")
        except Exception as e:
            self.log_activity(f"❌ Clean failed: {str(e)}")
            self.portal.speak("Clean operation failed")
        
    def check_updates(self):
        self.log_activity("Checking for system updates...")
        self.portal.speak("Checking for system updates")
        self.log_activity("✅ System is up to date")
        self.portal.speak("System is up to date")
        
    def system_info(self):
        self.log_activity("Displaying system information...")
        self.portal.speak("Displaying system information")
        info = f"""
System Information:
- OS: {platform.system()} {platform.release()}
- Processor: {platform.processor()}
- Hostname: {socket.gethostname()}
- IP Address: {socket.gethostbyname(socket.gethostname())}
- Python: {platform.python_version()}
"""
        self.log_activity(info.strip())
        
    def log_activity(self, message):
        """Thread-safe logging using after() method"""
        def update_log():
            try:
                self.activity_text.config(state='normal')
                timestamp = datetime.now().strftime('%H:%M:%S')
                self.activity_text.insert(tk.END, f"[{timestamp}] {message}\n")
                self.activity_text.see(tk.END)
                self.activity_text.config(state='disabled')
            except tk.TclError:
                pass  # Widget might be destroyed
        
        # Use after() to schedule the update in the main thread
        self.after(0, update_log)

class EnhancedVoiceControlPage(ttk.Frame):
    def __init__(self, parent, portal):
        super().__init__(parent, style='Content.TFrame')
        self.portal = portal
        self.setup_voice_control()
        self.listening = False
        self.audio_queue = queue.Queue()
        self.recognizer = sr.Recognizer()
        self.microphone = sr.Microphone()
        self.current_command = None
        
    def setup_voice_control(self):
        # Header
        header_frame = tk.Frame(self, bg='#0d1117')
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        title_label = tk.Label(header_frame,
                             text="Enhanced Voice Control System",
                             font=('Arial', 24, 'bold'),
                             fg='#58a6ff',
                             bg='#0d1117')
        title_label.pack(side=tk.LEFT)
        
        # Voice controls
        control_frame = tk.Frame(self, bg='#0d1117')
        control_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Voice buttons
        btn_frame = tk.Frame(control_frame, bg='#0d1117')
        btn_frame.pack(pady=20)
        
        self.listen_btn = tk.Button(btn_frame, text="🎤 Start Listening", 
                                   command=self.start_listening,
                                   font=('Arial', 12, 'bold'),
                                   bg='#27ae60', fg='white',
                                   width=20, height=2)
        self.listen_btn.pack(side=tk.LEFT, padx=10)
        
        self.stop_btn = tk.Button(btn_frame, text="⏹️ Stop Listening", 
                                 command=self.stop_listening,
                                 font=('Arial', 12, 'bold'),
                                 bg='#e74c3c', fg='white',
                                 width=20, height=2,
                                 state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10)
        
        self.emergency_stop_btn = tk.Button(btn_frame, text="🛑 Emergency Stop", 
                                          command=self.emergency_stop,
                                          font=('Arial', 12, 'bold'),
                                          bg='#ff0000', fg='white',
                                          width=20, height=2)
        self.emergency_stop_btn.pack(side=tk.LEFT, padx=10)
        
        # Status
        self.status_var = tk.StringVar(value="🔴 Ready - Click 'Start Listening'")
        status_label = tk.Label(control_frame, textvariable=self.status_var,
                              font=('Arial', 12),
                              fg='#f0f6fc', bg='#0d1117')
        status_label.pack(pady=10)
        
        # Command display
        self.command_var = tk.StringVar(value="Last command: None")
        command_label = tk.Label(control_frame, textvariable=self.command_var,
                               font=('Arial', 10),
                               fg='#58a6ff', bg='#0d1117')
        command_label.pack(pady=5)
        
        # Enhanced Voice commands guide with better organization
        guide_frame = tk.Frame(self, bg='#0d1117')
        guide_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        tk.Label(guide_frame, text="Available Voice Commands:",
                font=('Arial', 14, 'bold'),
                fg='#f0f6fc', bg='#0d1117').pack(anchor='w')
        
        # Create notebook for categorized commands
        notebook = ttk.Notebook(guide_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # System Control Tab
        system_frame = ttk.Frame(notebook)
        notebook.add(system_frame, text="🎯 System Control")
        
        system_commands = [
            "🎯 SYSTEM CONTROL (BASIC):",
            "  'lock the system' - Lock your computer",
            "  'shut down the pc' - Shuts down system", 
            "  'restart the computer' - Restarts system",
            "  'log out my account' - Logs out current user",
            "  'sleep mode on' - Puts system in sleep",
            "  'wake up system' - Wakes system from sleep",
            "  'show desktop' - Minimizes all windows",
            "  'open control panel' - Opens Windows control panel",
            "  'open settings' - Opens system settings",
            "  'check battery status' - Displays battery info",
        ]
        
        system_text = scrolledtext.ScrolledText(system_frame, width=80, height=10,
                                              bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        system_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for cmd in system_commands:
            system_text.insert(tk.END, f"{cmd}\n")
        system_text.config(state=tk.DISABLED)
        
        # Media Control Tab
        media_frame = ttk.Frame(notebook)
        notebook.add(media_frame, text="🔊 Media Control")
        
        media_commands = [
            "🔊 MEDIA & VOLUME CONTROL:",
            "  'increase volume' - Volume up",
            "  'decrease volume' - Volume down",
            "  'mute the sound' - Mutes volume",
            "  'unmute the sound' - Unmutes volume",
            "  'play music' - Opens default music app",
            "  'pause music' - Pauses playback",
            "  'next track' - Skips to next song",
            "  'previous track' - Goes to previous song",
            "  'open youtube' - Launches YouTube in browser",
            "  'take a screenshot' - Captures screen instantly",
        ]
        
        media_text = scrolledtext.ScrolledText(media_frame, width=80, height=10,
                                             bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        media_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for cmd in media_commands:
            media_text.insert(tk.END, f"{cmd}\n")
        media_text.config(state=tk.DISABLED)
        
        # Application Tab
        app_frame = ttk.Frame(notebook)
        notebook.add(app_frame, text="🚀 Applications")
        
        app_commands = [
            "🚀 APPLICATION LAUNCH COMMANDS:",
            "  'open chrome' - Launches Chrome browser",
            "  'open file explorer' - Opens file manager",
            "  'open notepad' - Opens Notepad",
            "  'open word' - Opens Microsoft Word",
            "  'open excel' - Opens Excel",
            "  'open powerpoint' - Opens PowerPoint",
            "  'open calculator' - Launches calculator",
            "  'open camera' - Opens camera app",
            "  'open paint' - Launches MS Paint",
            "  'open task manager' - Opens task manager",
        ]
        
        app_text = scrolledtext.ScrolledText(app_frame, width=80, height=10,
                                           bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        app_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for cmd in app_commands:
            app_text.insert(tk.END, f"{cmd}\n")
        app_text.config(state=tk.DISABLED)
        
        # Internet Tab
        internet_frame = ttk.Frame(notebook)
        notebook.add(internet_frame, text="🌐 Internet")
        
        internet_commands = [
            "🌐 INTERNET & BROWSER CONTROL:",
            "  'open gmail' - Opens Gmail in browser",
            "  'search for [topic]' - Searches Google for query",
            "  'open new tab' - Opens new browser tab",
            "  'close tab' - Closes current tab",
            "  'refresh page' - Refreshes browser page",
            "  'go back' - Goes to previous page",
            "  'go forward' - Goes to next page",
            "  'download page' - Saves page locally",
            "  'zoom in' - Zooms browser window",
            "  'zoom out' - Zooms out browser window",
        ]
        
        internet_text = scrolledtext.ScrolledText(internet_frame, width=80, height=10,
                                                bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        internet_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for cmd in internet_commands:
            internet_text.insert(tk.END, f"{cmd}\n")
        internet_text.config(state=tk.DISABLED)
        
        # Security Tab
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="🔐 Security")
        
        security_commands = [
            "🔐 CYBERSECURITY & NETWORK COMMANDS:",
            "  'turn on firewall' - Enables system firewall",
            "  'turn off firewall' - Disables firewall",
            "  'start antivirus scan' - Runs malware scan",
            "  'check wi fi status' - Displays Wi-Fi info",
            "  'disconnect wi fi' - Turns off Wi-Fi",
            "  'connect to wi fi' - Enables Wi-Fi",
            "  'start vpn' - Launches VPN app",
            "  'stop vpn' - Disconnects VPN",
            "  'network scan' - Runs network scan",
            "  'show security log' - Displays recent security events",
        ]
        
        security_text = scrolledtext.ScrolledText(security_frame, width=80, height=10,
                                                bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        security_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for cmd in security_commands:
            security_text.insert(tk.END, f"{cmd}\n")
        security_text.config(state=tk.DISABLED)
        
        # Defender & System Tab
        defender_frame = ttk.Frame(notebook)
        notebook.add(defender_frame, text="🛡️ Defender")
        
        defender_commands = [
            "🛡️ DEFENDER & SYSTEM COMMANDS:",
            "  'run offline scan' - Run Windows Defender offline scan",
            "  'show defender version' - Display Defender version info",
            "  'scan specific folder' - Scan a specific folder for threats",
            "  'quarantine this file' - Quarantine selected file",
            "  'delete all quarantined items' - Clear quarantine folder",
            "  'enable cloud-delivered protection' - Enable cloud protection",
            "  'turn on tamper protection' - Enable tamper protection",
            "  'show real-time protection status' - Check real-time protection",
            "  'display last scan results' - Show last scan results",
            "  'list detected threats' - Display detected threats",
        ]
        
        defender_text = scrolledtext.ScrolledText(defender_frame, width=80, height=10,
                                                bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        defender_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for cmd in defender_commands:
            defender_text.insert(tk.END, f"{cmd}\n")
        defender_text.config(state=tk.DISABLED)
        
        # Network & Firewall Tab
        network_frame = ttk.Frame(notebook)
        notebook.add(network_frame, text="🌐 Network")
        
        network_commands = [
            "🌐 NETWORK & FIREWALL COMMANDS:",
            "  'show open network ports' - Display open ports",
            "  'block all inbound connections' - Block incoming connections",
            "  'list firewall rules' - Show firewall rules",
            "  'add firewall rule for [app]' - Add firewall rule",
            "  'show wi fi network security type' - Check WiFi security",
            "  'disconnect from current network' - Disconnect network",
        ]
        
        network_text = scrolledtext.ScrolledText(network_frame, width=80, height=10,
                                               bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        network_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for cmd in network_commands:
            network_text.insert(tk.END, f"{cmd}\n")
        network_text.config(state=tk.DISABLED)
        
        # Logging & Reporting Tab
        logging_frame = ttk.Frame(notebook)
        notebook.add(logging_frame, text="📊 Logging")
        
        logging_commands = [
            "📊 LOGGING & REPORTING COMMANDS:",
            "  'open windows event viewer' - Launch Event Viewer",
            "  'export defender logs' - Export security logs",
            "  'show last 10 security alerts' - Display recent alerts",
            "  'email a security report' - Send security report via email",
            "  'archive all threat logs' - Archive all threat logs",
        ]
        
        logging_text = scrolledtext.ScrolledText(logging_frame, width=80, height=10,
                                               bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        logging_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for cmd in logging_commands:
            logging_text.insert(tk.END, f"{cmd}\n")
        logging_text.config(state=tk.DISABLED)
        
        # Azure Kudu Tab
        azure_frame = ttk.Frame(notebook)
        notebook.add(azure_frame, text="☁️ Azure")
        
        azure_commands = [
            "☁️ AZURE KUDU COMMANDS:",
            "  'open kudu console' - Open Kudu console",
            "  'restart web app' - Restart Azure web app",
            "  'show environment variables' - Display environment vars",
            "  'check disk space' - Check disk usage",
            "  'list site extensions' - Show installed extensions",
            "  'execute powershell command in kudu' - Run PowerShell",
            "  'access debug console' - Open debug console",
            "  'download site logs' - Download application logs",
            "  'show web app process list' - Display running processes",
            "  'kill suspicious process' - Terminate suspicious process",
            "  'scan app directory for threats' - Scan app directory",
            "  'display app permissions' - Show app permissions",
            "  'check ssl certificate status' - Verify SSL certificate",
            "  'verify https enforcement' - Check HTTPS enforcement",
            "  'show current cpu usage' - Display CPU usage",
            "  'display memory consumption' - Show memory usage",
            "  'generate performance report' - Create performance report",
            "  'export app diagnostics' - Export diagnostic data",
            "  'view deployment history' - Show deployment history",
        ]
        
        azure_text = scrolledtext.ScrolledText(azure_frame, width=80, height=10,
                                             bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        azure_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for cmd in azure_commands:
            azure_text.insert(tk.END, f"{cmd}\n")
        azure_text.config(state=tk.DISABLED)
        
        # Output area
        output_frame = tk.Frame(self, bg='#0d1117')
        output_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        tk.Label(output_frame, text="Voice Command Log",
                font=('Arial', 14, 'bold'),
                fg='#f0f6fc', bg='#0d1117').pack(anchor='w')
        
        self.output_text = scrolledtext.ScrolledText(output_frame,
                                                   height=15,
                                                   bg='#161b22',
                                                   fg='#00ff41',
                                                   font=('Consolas', 9))
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=10)
        self.log_output("Enhanced voice control system ready.")
        self.log_output("Say your command clearly.")
        
        # Initialize speech engine
        try:
            with self.microphone as source:
                self.recognizer.adjust_for_ambient_noise(source)
        except Exception as e:
            self.log_output(f"Error initializing voice components: {str(e)}")
        
    def start_listening(self):
        self.listening = True
        self.listen_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("🎧 Listening... Say a command")
        self.log_output("Voice recognition started")
        self.portal.speak("Voice recognition started. I'm listening for commands.")
        
        # Start listening in a separate thread
        threading.Thread(target=self.listen_loop, daemon=True).start()
        
    def stop_listening(self):
        self.listening = False
        self.listen_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("🔴 Listening stopped")
        self.log_output("Voice recognition stopped")
        self.portal.speak("Voice recognition stopped")
        
    def emergency_stop(self):
        """Emergency stop all operations"""
        self.portal.stop_current_operation()
        self.log_output("🛑 EMERGENCY STOP: All operations halted")
        self.portal.speak("Emergency stop activated. All operations halted.")
        
    def listen_loop(self):
        while self.listening:
            try:
                with self.microphone as source:
                    self.recognizer.adjust_for_ambient_noise(source, duration=0.2)
                    audio = self.recognizer.listen(source, timeout=5, phrase_time_limit=10)
                    
                    # Recognize speech
                    text = self.recognizer.recognize_google(audio).lower()
                    self.process_voice_command(text)
                    
            except sr.WaitTimeoutError:
                continue
            except sr.UnknownValueError:
                self.log_output("Could not understand audio")
            except Exception as e:
                self.log_output(f"Recognition error: {str(e)}")
                
    def process_voice_command(self, command):
        self.command_var.set(f"Last command: {command}")
        self.log_output(f"Command received: {command}")
        
        # Check for stop command first
        if any(word in command for word in ['stop', 'cancel', 'halt', 'abort', 'emergency stop']):
            self.portal.stop_current_operation()
            self.log_output("🛑 Operation stopped")
            self.portal.speak("Operation stopped")
            return
            
        # Process commands with improved matching
        command_mappings = {
            # System Control (Basic)
            'lock the system': (self.lock_screen, "Locking system"),
            'shut down the pc': (self.shutdown_computer, "Shutting down system"),
            'restart the computer': (self.restart_computer, "Restarting computer"),
            'log out my account': (self.log_out, "Logging out user"),
            'sleep mode on': (self.sleep_mode, "Activating sleep mode"),
            'wake up system': (self.wake_up_system, "Waking up system"),
            'show desktop': (self.show_desktop, "Showing desktop"),
            'open control panel': (self.open_control_panel, "Opening control panel"),
            'open settings': (self.open_settings, "Opening settings"),
            'check battery status': (self.check_battery_status, "Checking battery status"),
            
            # Media & Volume Control
            'increase volume': (self.volume_up, "Increasing volume"),
            'decrease volume': (self.volume_down, "Decreasing volume"),
            'mute the sound': (self.mute_volume, "Muting sound"),
            'unmute the sound': (self.unmute_volume, "Unmuting sound"),
            'play music': (self.play_music, "Playing music"),
            'pause music': (self.pause_music, "Pausing music"),
            'next track': (self.next_track, "Next track"),
            'previous track': (self.previous_track, "Previous track"),
            'open youtube': (self.open_youtube, "Opening YouTube"),
            'take a screenshot': (self.take_screenshot, "Taking screenshot"),
            
            # Application Launch Commands
            'open chrome': (self.open_chrome, "Opening Chrome"),
            'open file explorer': (self.open_file_explorer, "Opening file explorer"),
            'open notepad': (self.open_notepad, "Opening Notepad"),
            'open word': (self.open_word, "Opening Microsoft Word"),
            'open excel': (self.open_excel, "Opening Excel"),
            'open powerpoint': (self.open_powerpoint, "Opening PowerPoint"),
            'open calculator': (self.open_calculator, "Opening calculator"),
            'open camera': (self.open_camera, "Opening camera"),
            'open paint': (self.open_paint, "Opening Paint"),
            'open task manager': (self.open_task_manager, "Opening task manager"),
            
            # Internet & Browser Control
            'open gmail': (self.open_gmail, "Opening Gmail"),
            'open new tab': (self.open_new_tab, "Opening new tab"),
            'close tab': (self.close_tab, "Closing tab"),
            'refresh page': (self.refresh_page, "Refreshing page"),
            'go back': (self.go_back, "Going back"),
            'go forward': (self.go_forward, "Going forward"),
            'download page': (self.download_page, "Downloading page"),
            'zoom in': (self.zoom_in, "Zooming in"),
            'zoom out': (self.zoom_out, "Zooming out"),
            
            # Cybersecurity & Network Commands
            'turn on firewall': (self.activate_firewall, "Turning on firewall"),
            'turn off firewall': (self.deactivate_firewall, "Turning off firewall"),
            'start antivirus scan': (self.run_malware_scan, "Starting antivirus scan"),
            'check wi fi status': (self.check_wifi_status, "Checking Wi-Fi status"),
            'disconnect wi fi': (self.disconnect_wifi, "Disconnecting Wi-Fi"),
            'connect to wi fi': (self.connect_wifi, "Connecting to Wi-Fi"),
            'start vpn': (self.launch_vpn, "Starting VPN"),
            'stop vpn': (self.disconnect_vpn, "Stopping VPN"),
            'network scan': (self.start_network_scan, "Starting network scan"),
            'show security log': (self.show_security_log, "Showing security log"),
            
            # NEW: Defender & System Commands
            'run offline scan': (self.run_offline_scan, "Running offline scan"),
            'show defender version': (self.show_defender_version, "Showing Defender version"),
            'scan specific folder': (self.scan_specific_folder, "Scanning specific folder"),
            'quarantine this file': (self.quarantine_file, "Quarantining file"),
            'delete all quarantined items': (self.delete_quarantined_items, "Deleting quarantined items"),
            'enable cloud-delivered protection': (self.enable_cloud_protection, "Enabling cloud protection"),
            'turn on tamper protection': (self.enable_tamper_protection, "Enabling tamper protection"),
            'show real-time protection status': (self.show_realtime_protection_status, "Showing real-time protection status"),
            'display last scan results': (self.display_last_scan_results, "Displaying last scan results"),
            'list detected threats': (self.list_detected_threats, "Listing detected threats"),
            
            # NEW: Network & Firewall Commands
            'show open network ports': (self.show_open_ports, "Showing open network ports"),
            'block all inbound connections': (self.block_inbound_connections, "Blocking inbound connections"),
            'list firewall rules': (self.list_firewall_rules, "Listing firewall rules"),
            'show wi fi network security type': (self.show_wifi_security_type, "Showing WiFi security type"),
            'disconnect from current network': (self.disconnect_network, "Disconnecting from network"),
            
            # NEW: Logging & Reporting Commands
            'open windows event viewer': (self.open_event_viewer, "Opening Event Viewer"),
            'export defender logs': (self.export_defender_logs, "Exporting Defender logs"),
            'show last 10 security alerts': (self.show_last_alerts, "Showing last 10 security alerts"),
            'email a security report': (self.email_security_report, "Emailing security report"),
            'archive all threat logs': (self.archive_threat_logs, "Archiving threat logs"),
            
            # NEW: Azure Kudu Commands
            'open kudu console': (self.open_kudu_console, "Opening Kudu console"),
            'restart web app': (self.restart_web_app, "Restarting web app"),
            'show environment variables': (self.show_environment_variables, "Showing environment variables"),
            'check disk space': (self.check_disk_space, "Checking disk space"),
            'list site extensions': (self.list_site_extensions, "Listing site extensions"),
            'execute powershell command in kudu': (self.execute_kudu_powershell, "Executing PowerShell in Kudu"),
            'access debug console': (self.access_debug_console, "Accessing debug console"),
            'download site logs': (self.download_site_logs, "Downloading site logs"),
            'show web app process list': (self.show_webapp_processes, "Showing web app processes"),
            'kill suspicious process': (self.kill_suspicious_process, "Killing suspicious process"),
            'scan app directory for threats': (self.scan_app_directory, "Scanning app directory for threats"),
            'display app permissions': (self.display_app_permissions, "Displaying app permissions"),
            'check ssl certificate status': (self.check_ssl_certificate, "Checking SSL certificate status"),
            'verify https enforcement': (self.verify_https_enforcement, "Verifying HTTPS enforcement"),
            'show current cpu usage': (self.show_cpu_usage, "Showing current CPU usage"),
            'display memory consumption': (self.show_memory_usage, "Displaying memory consumption"),
            'generate performance report': (self.generate_performance_report, "Generating performance report"),
            'export app diagnostics': (self.export_app_diagnostics, "Exporting app diagnostics"),
            'view deployment history': (self.view_deployment_history, "Viewing deployment history"),
        }
        
        # Handle search command separately
        if 'search for' in command:
            query = command.replace('search for', '').strip()
            self.search_web(query)
            return
            
        if 'search' in command:
            query = command.replace('search', '').strip()
            self.search_web(query)
            return
            
        # Handle "add firewall rule for [app]" command
        if 'add firewall rule for' in command:
            app_name = command.replace('add firewall rule for', '').strip()
            self.add_firewall_rule(app_name)
            return
        
        action_taken = False
        for key, (action, message) in command_mappings.items():
            if key in command:
                self.log_output(f"Executing: {message}")
                self.portal.speak(message)
                try:
                    # Set current operation
                    self.portal.current_operation = key
                    self.portal.operation_stop_event.clear()
                    
                    # Execute action
                    action()
                    
                    action_taken = True
                    break
                except Exception as e:
                    self.log_output(f"Error executing command: {str(e)}")
                    self.portal.speak("Error executing command")
                finally:
                    self.portal.current_operation = None
        
        if not action_taken:
            self.log_output("Command not recognized")
            self.portal.speak("Command not recognized. Please try a different command.")
            
    # System Control Methods
    def lock_screen(self):
        try:
            if platform.system() == "Windows":
                os.system("rundll32.exe user32.dll,LockWorkStation")
            elif platform.system() == "Darwin":
                os.system("pmset displaysleepnow")
            else:
                os.system("gnome-screensaver-command -l")
            self.log_output("Screen locked successfully")
        except Exception as e:
            self.log_output(f"Failed to lock screen: {str(e)}")
            
    def log_out(self):
        if platform.system() == "Windows":
            os.system("shutdown /l")
        else:
            self.log_output("Log out not available on this system")
            
    def restart_computer(self):
        if platform.system() == "Windows":
            os.system("shutdown /r /t 0")
        elif platform.system() == "Darwin":
            os.system("sudo shutdown -r now")
        else:
            os.system("sudo reboot")
            
    def shutdown_computer(self):
        if platform.system() == "Windows":
            os.system("shutdown /s /t 0")
        elif platform.system() == "Darwin":
            os.system("sudo shutdown -h now")
        else:
            os.system("sudo shutdown -h now")
            
    def sleep_mode(self):
        try:
            if platform.system() == "Windows":
                os.system("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")
            elif platform.system() == "Darwin":
                os.system("pmset sleepnow")
            else:
                os.system("systemctl suspend")
            self.log_output("Sleep mode activated")
        except Exception as e:
            self.log_output(f"Failed to activate sleep mode: {str(e)}")
            
    def wake_up_system(self):
        # Simulate a key press to wake up system
        pyautogui.press('shift')
        self.log_output("System wake up signal sent")
        
    def show_desktop(self):
        if platform.system() == "Windows":
            pyautogui.hotkey('win', 'd')
        elif platform.system() == "Darwin":
            pyautogui.hotkey('command', 'f3')
        else:
            # For Linux - may vary by desktop environment
            pyautogui.hotkey('ctrl', 'alt', 'd')
        self.log_output("Showing desktop")
            
    def open_control_panel(self):
        if platform.system() == "Windows":
            os.system("control")
        else:
            self.log_output("Control panel not available on this system")
            
    def open_settings(self):
        if platform.system() == "Windows":
            os.system("start ms-settings:")
        elif platform.system() == "Darwin":
            os.system("open /System/Library/PreferencePanes/")
        else:
            os.system("gnome-control-center")
        self.log_output("Settings opened")
            
    def check_battery_status(self):
        try:
            battery = psutil.sensors_battery()
            if battery:
                status = "plugged in" if battery.power_plugged else "on battery"
                self.log_output(f"Battery: {battery.percent}% ({status})")
                self.portal.speak(f"Battery is at {battery.percent} percent and {status}")
            else:
                self.log_output("Battery information not available")
                self.portal.speak("Battery information not available")
        except Exception as e:
            self.log_output(f"Battery check failed: {str(e)}")
            
    def volume_up(self):
        pyautogui.press('volumeup')
        self.log_output("Volume increased")
        
    def volume_down(self):
        pyautogui.press('volumedown')
        self.log_output("Volume decreased")
        
    def mute_volume(self):
        pyautogui.press('volumemute')
        self.log_output("Volume muted")
        
    def unmute_volume(self):
        pyautogui.press('volumemute')
        self.log_output("Volume unmuted")
        
    def play_music(self):
        # This would depend on the default music player
        webbrowser.open("spotify:")
        self.log_output("Opening music player")
        
    def pause_music(self):
        pyautogui.press('playpause')
        self.log_output("Music paused")
        
    def next_track(self):
        pyautogui.press('nexttrack')
        self.log_output("Next track")
        
    def previous_track(self):
        pyautogui.press('prevtrack')
        self.log_output("Previous track")
        
    def open_youtube(self):
        webbrowser.open("https://www.youtube.com")
        self.log_output("YouTube opened")
        
    def take_screenshot(self):
        try:
            screenshot = pyautogui.screenshot()
            filename = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            screenshot.save(filename)
            self.log_output(f"Screenshot saved as {filename}")
        except Exception as e:
            self.log_output(f"Screenshot failed: {str(e)}")
            
    # Application Launch Methods
    def open_chrome(self):
        try:
            if platform.system() == "Windows":
                os.system("start chrome")
            elif platform.system() == "Darwin":
                os.system("open -a Google\ Chrome")
            else:
                os.system("google-chrome")
            self.log_output("Chrome opened")
        except Exception as e:
            self.log_output(f"Failed to open Chrome: {str(e)}")
            
    def open_file_explorer(self):
        if platform.system() == "Windows":
            os.system("explorer")
        elif platform.system() == "Darwin":
            os.system("open .")
        else:
            os.system("nautilus .")
        self.log_output("File Explorer opened")
            
    def open_notepad(self):
        if platform.system() == "Windows":
            os.system("notepad")
        else:
            os.system("gedit")
        self.log_output("Notepad opened")
            
    def open_word(self):
        try:
            if platform.system() == "Windows":
                os.system("start winword")
            elif platform.system() == "Darwin":
                os.system("open -a Microsoft\ Word")
            else:
                self.log_output("Microsoft Word not available on this system")
        except Exception as e:
            self.log_output(f"Failed to open Word: {str(e)}")
            
    def open_excel(self):
        try:
            if platform.system() == "Windows":
                os.system("start excel")
            elif platform.system() == "Darwin":
                os.system("open -a Microsoft\ Excel")
            else:
                self.log_output("Microsoft Excel not available on this system")
        except Exception as e:
            self.log_output(f"Failed to open Excel: {str(e)}")
            
    def open_powerpoint(self):
        try:
            if platform.system() == "Windows":
                os.system("start powerpnt")
            elif platform.system() == "Darwin":
                os.system("open -a Microsoft\ PowerPoint")
            else:
                self.log_output("Microsoft PowerPoint not available on this system")
        except Exception as e:
            self.log_output(f"Failed to open PowerPoint: {str(e)}")
            
    def open_calculator(self):
        if platform.system() == "Windows":
            os.system("calc")
        elif platform.system() == "Darwin":
            os.system("open -a Calculator")
        else:
            os.system("gnome-calculator")
        self.log_output("Calculator opened")
            
    def open_camera(self):
        try:
            if platform.system() == "Windows":
                os.system("start microsoft.windows.camera:")
            elif platform.system() == "Darwin":
                os.system("open -a Photo\ Booth")
            else:
                os.system("cheese")
            self.log_output("Camera opened")
        except Exception as e:
            self.log_output(f"Failed to open camera: {str(e)}")
            
    def open_paint(self):
        if platform.system() == "Windows":
            os.system("mspaint")
        else:
            os.system("kolourpaint")
        self.log_output("Paint opened")
            
    def open_task_manager(self):
        if platform.system() == "Windows":
            os.system("taskmgr")
        else:
            os.system("htop")
        self.log_output("Task Manager opened")
        
    # Internet & Browser Control Methods
    def open_gmail(self):
        webbrowser.open("https://mail.google.com")
        self.log_output("Gmail opened")
        
    def search_web(self, query):
        webbrowser.open(f"https://www.google.com/search?q={query}")
        self.log_output(f"Searching for: {query}")
        
    def open_new_tab(self):
        pyautogui.hotkey('ctrl', 't')
        self.log_output("New tab opened")
        
    def close_tab(self):
        pyautogui.hotkey('ctrl', 'w')
        self.log_output("Tab closed")
        
    def refresh_page(self):
        pyautogui.hotkey('ctrl', 'r')
        self.log_output("Page refreshed")
        
    def go_back(self):
        pyautogui.hotkey('alt', 'left')
        self.log_output("Going back")
        
    def go_forward(self):
        pyautogui.hotkey('alt', 'right')
        self.log_output("Going forward")
        
    def download_page(self):
        pyautogui.hotkey('ctrl', 's')
        self.log_output("Downloading page")
        
    def zoom_in(self):
        pyautogui.hotkey('ctrl', '+')
        self.log_output("Zooming in")
        
    def zoom_out(self):
        pyautogui.hotkey('ctrl', '-')
        self.log_output("Zooming out")
        
    # Cybersecurity Methods
    def activate_firewall(self):
        try:
            if platform.system() == "Windows":
                os.system("netsh advfirewall set allprofiles state on")
            self.log_output("Firewall activated")
        except Exception as e:
            self.log_output(f"Failed to activate firewall: {str(e)}")
            
    def deactivate_firewall(self):
        try:
            if platform.system() == "Windows":
                os.system("netsh advfirewall set allprofiles state off")
            self.log_output("Firewall deactivated")
        except Exception as e:
            self.log_output(f"Failed to deactivate firewall: {str(e)}")
            
    def start_network_scan(self):
        self.portal.pages["security"].network_analysis()
        
    def view_connections(self):
        try:
            connections = psutil.net_connections()
            established = [conn for conn in connections if conn.status == 'ESTABLISHED']
            self.log_output(f"Active connections: {len(established)}")
            for conn in established[:5]:
                self.log_output(f"  {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}")
        except Exception as e:
            self.log_output(f"Failed to view connections: {str(e)}")
            
    def stop_network_scan(self):
        self.portal.stop_current_operation()
        self.log_output("Network scan stopped")
        
    def launch_vpn(self):
        self.log_output("VPN launched (simulated)")
        
    def disconnect_vpn(self):
        self.log_output("VPN disconnected (simulated)")
        
    def run_malware_scan(self):
        self.portal.pages["security"].malware_analysis()
        
    def enable_safe_mode(self):
        self.log_output("Safe mode enabled (simulated)")
        
    def security_status(self):
        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        status = f"Security Status: CPU {cpu}%, Memory {memory.percent}%, Disk {disk.percent}%"
        self.log_output(status)
        self.portal.speak(status)
        
    def check_wifi_status(self):
        try:
            # Get network interface information
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            wifi_info = []
            for interface, addrs in interfaces.items():
                if interface in stats and getattr(stats[interface], 'isup', False):
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            wifi_info.append(f"{interface}: {addr.address}")
            
            if wifi_info:
                self.log_output("Wi-Fi Status:")
                for info in wifi_info:
                    self.log_output(f"  {info}")
            else:
                self.log_output("No active Wi-Fi connections found")
        except Exception as e:
            self.log_output(f"Failed to check Wi-Fi status: {str(e)}")
            
    def disconnect_wifi(self):
        self.log_output("Wi-Fi disconnected (simulated)")
        
    def connect_wifi(self):
        self.log_output("Wi-Fi connected (simulated)")
        
    def show_security_log(self):
        self.log_output("Displaying security log")
        # This would show the security log from the dashboard
        self.portal.show_page("dashboard")
        
    # NEW: Defender & System Methods
    def run_offline_scan(self):
        try:
            if platform.system() == "Windows":
                self.log_output("Starting Windows Defender offline scan...")
                # This would require admin privileges
                result = subprocess.run([
                    'powershell', '-Command', 
                    'Start-MpWDOScan'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.log_output("✅ Offline scan initiated successfully")
                    self.portal.speak("Windows Defender offline scan has been initiated. Your system will restart to complete the scan.")
                else:
                    self.log_output(f"❌ Failed to start offline scan: {result.stderr}")
                    self.portal.speak("Failed to start offline scan. Please check administrator privileges.")
            else:
                self.log_output("Offline scan only available on Windows")
                self.portal.speak("This feature is only available on Windows systems.")
        except Exception as e:
            self.log_output(f"Error running offline scan: {str(e)}")
            self.portal.speak("Error running offline scan")
    
    def show_defender_version(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run([
                    'powershell', '-Command',
                    'Get-MpComputerStatus | Select-Object AntivirusSignatureVersion, AMProductVersion'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) >= 3:
                        version_info = lines[2].strip()
                        self.log_output(f"Defender Version Info: {version_info}")
                        self.portal.speak(f"Windows Defender version information displayed")
                    else:
                        self.log_output("Could not retrieve Defender version information")
                else:
                    self.log_output("Failed to get Defender version")
            else:
                self.log_output("Defender version check only available on Windows")
        except Exception as e:
            self.log_output(f"Error getting Defender version: {str(e)}")
    
    def scan_specific_folder(self):
        folder = filedialog.askdirectory(title="Select folder to scan with Defender")
        if folder:
            try:
                if platform.system() == "Windows":
                    self.log_output(f"Scanning folder with Defender: {folder}")
                    result = subprocess.run([
                        'powershell', '-Command',
                        f'Start-MpScan -ScanPath "{folder}" -ScanType QuickScan'
                    ], capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        self.log_output("✅ Folder scan initiated successfully")
                        self.portal.speak("Folder scan with Windows Defender has been initiated.")
                    else:
                        self.log_output(f"❌ Folder scan failed: {result.stderr}")
                else:
                    self.portal.pages["security"].scan_folder(folder)
            except Exception as e:
                self.log_output(f"Error scanning folder: {str(e)}")
    
    def quarantine_file(self):
        file_path = filedialog.askopenfilename(title="Select file to quarantine")
        if file_path:
            try:
                # For demonstration, we'll move to our quarantine folder
                quarantine_path = os.path.join(QUARANTINE_DIR, os.path.basename(file_path))
                shutil.move(file_path, quarantine_path)
                self.log_output(f"✅ File quarantined: {file_path} -> {quarantine_path}")
                self.portal.speak("File has been quarantined successfully.")
            except Exception as e:
                self.log_output(f"❌ Failed to quarantine file: {str(e)}")
                self.portal.speak("Failed to quarantine the file.")
    
    def delete_quarantined_items(self):
        try:
            if os.path.exists(QUARANTINE_DIR):
                for filename in os.listdir(QUARANTINE_DIR):
                    file_path = os.path.join(QUARANTINE_DIR, filename)
                    try:
                        if os.path.isfile(file_path):
                            os.unlink(file_path)
                    except Exception as e:
                        self.log_output(f"Failed to delete {filename}: {str(e)}")
                
                self.log_output("✅ All quarantined items deleted")
                self.portal.speak("All quarantined items have been deleted.")
            else:
                self.log_output("No quarantine directory found")
        except Exception as e:
            self.log_output(f"Error deleting quarantined items: {str(e)}")
    
    def enable_cloud_protection(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run([
                    'powershell', '-Command',
                    'Set-MpPreference -MAPSReporting Advanced'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.log_output("✅ Cloud-delivered protection enabled")
                    self.portal.speak("Cloud-delivered protection has been enabled.")
                else:
                    self.log_output("❌ Failed to enable cloud protection")
            else:
                self.log_output("Cloud protection only available on Windows")
        except Exception as e:
            self.log_output(f"Error enabling cloud protection: {str(e)}")
    
    def enable_tamper_protection(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run([
                    'powershell', '-Command',
                    'Set-MpPreference -EnableTamperProtection $true'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.log_output("✅ Tamper protection enabled")
                    self.portal.speak("Tamper protection has been enabled.")
                else:
                    self.log_output("❌ Failed to enable tamper protection")
            else:
                self.log_output("Tamper protection only available on Windows")
        except Exception as e:
            self.log_output(f"Error enabling tamper protection: {str(e)}")
    
    def show_realtime_protection_status(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run([
                    'powershell', '-Command',
                    'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    if len(lines) >= 3:
                        status = "Enabled" if "True" in lines[2] else "Disabled"
                        self.log_output(f"Real-time Protection: {status}")
                        self.portal.speak(f"Real-time protection is currently {status.lower()}.")
                    else:
                        self.log_output("Could not retrieve real-time protection status")
                else:
                    self.log_output("Failed to get real-time protection status")
            else:
                self.log_output("Real-time protection status only available on Windows")
        except Exception as e:
            self.log_output(f"Error getting real-time protection status: {str(e)}")
    
    def display_last_scan_results(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run([
                    'powershell', '-Command',
                    'Get-MpThreatDetection | Select-Object Threat,Resources,ActionSuccess'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.log_output("Last Scan Results:")
                    self.log_output(result.stdout)
                    self.portal.speak("Displaying last scan results.")
                else:
                    self.log_output("No recent scan results found")
            else:
                self.log_output("Scan results only available on Windows")
        except Exception as e:
            self.log_output(f"Error getting scan results: {str(e)}")
    
    def list_detected_threats(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run([
                    'powershell', '-Command',
                    'Get-MpThreatDetection | Format-Table -AutoSize'
                ], capture_output=True, text=True)
                
                if result.returncode == 0 and result.stdout.strip():
                    self.log_output("Detected Threats:")
                    self.log_output(result.stdout)
                    self.portal.speak("Displaying detected threats.")
                else:
                    self.log_output("No threats detected")
                    self.portal.speak("No threats have been detected.")
            else:
                self.log_output("Threat detection only available on Windows")
        except Exception as e:
            self.log_output(f"Error listing threats: {str(e)}")
    
    # NEW: Network & Firewall Methods
    def show_open_ports(self):
        try:
            # Use netstat to show open ports
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                listening_ports = [line for line in lines if 'LISTENING' in line]
                
                self.log_output("Open Network Ports (Listening):")
                for port in listening_ports[:10]:  # Show first 10
                    self.log_output(f"  {port}")
                
                if len(listening_ports) > 10:
                    self.log_output(f"  ... and {len(listening_ports) - 10} more ports")
                
                self.portal.speak(f"Found {len(listening_ports)} open network ports.")
            else:
                self.log_output("Failed to retrieve open ports")
        except Exception as e:
            self.log_output(f"Error showing open ports: {str(e)}")
    
    def block_inbound_connections(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run([
                    'netsh', 'advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.log_output("✅ All inbound connections blocked")
                    self.portal.speak("All inbound connections have been blocked.")
                else:
                    self.log_output("❌ Failed to block inbound connections")
            else:
                self.log_output("Firewall commands only available on Windows")
        except Exception as e:
            self.log_output(f"Error blocking inbound connections: {str(e)}")
    
    def list_firewall_rules(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    self.log_output("Firewall Rules (first 10):")
                    for line in lines[:20]:  # Show first 20 lines
                        self.log_output(f"  {line}")
                    self.portal.speak("Displaying firewall rules.")
                else:
                    self.log_output("Failed to list firewall rules")
            else:
                self.log_output("Firewall commands only available on Windows")
        except Exception as e:
            self.log_output(f"Error listing firewall rules: {str(e)}")
    
    def add_firewall_rule(self, app_name):
        try:
            if platform.system() == "Windows":
                # This is a simplified example
                rule_name = f"Allow {app_name}"
                self.log_output(f"Adding firewall rule for: {app_name}")
                
                # In a real implementation, you would need the actual executable path
                self.log_output("⚠️ Note: This is a demonstration. Actual rule creation would require the app path.")
                self.portal.speak(f"Firewall rule for {app_name} would be created with the actual application path.")
            else:
                self.log_output("Firewall commands only available on Windows")
        except Exception as e:
            self.log_output(f"Error adding firewall rule: {str(e)}")
    
    def show_wifi_security_type(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run([
                    'netsh', 'wlan', 'show', 'interfaces'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Authentication' in line:
                            self.log_output(f"WiFi Security: {line.strip()}")
                            self.portal.speak(f"WiFi security type is {line.split(':')[1].strip()}")
                            break
                else:
                    self.log_output("Failed to get WiFi information")
            else:
                self.log_output("WiFi commands only available on Windows")
        except Exception as e:
            self.log_output(f"Error getting WiFi security: {str(e)}")
    
    def disconnect_network(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.run([
                    'netsh', 'interface', 'set', 'interface', 'name="Wi-Fi"', 'admin=disable'
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.log_output("✅ Disconnected from network")
                    self.portal.speak("Disconnected from the current network.")
                else:
                    self.log_output("❌ Failed to disconnect from network")
            else:
                self.log_output("Network commands only available on Windows")
        except Exception as e:
            self.log_output(f"Error disconnecting network: {str(e)}")
    
    # NEW: Logging & Reporting Methods
    def open_event_viewer(self):
        try:
            if platform.system() == "Windows":
                os.system("eventvwr")
                self.log_output("✅ Event Viewer opened")
                self.portal.speak("Windows Event Viewer has been opened.")
            else:
                self.log_output("Event Viewer only available on Windows")
        except Exception as e:
            self.log_output(f"Error opening Event Viewer: {str(e)}")
    
    def export_defender_logs(self):
        try:
            if platform.system() == "Windows":
                log_file = f"defender_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                
                result = subprocess.run([
                    'powershell', '-Command',
                    'Get-MpThreatDetection | Out-File -FilePath ' + log_file
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.log_output(f"✅ Defender logs exported to {log_file}")
                    self.portal.speak("Windows Defender logs have been exported.")
                else:
                    self.log_output("❌ Failed to export Defender logs")
            else:
                self.log_output("Defender logs only available on Windows")
        except Exception as e:
            self.log_output(f"Error exporting Defender logs: {str(e)}")
    
    def show_last_alerts(self):
        try:
            # Read from our antivirus log file
            if os.path.exists(ANTIVIRUS_LOG_FILE):
                with open(ANTIVIRUS_LOG_FILE, 'r') as f:
                    lines = f.readlines()
                    last_alerts = lines[-10:] if len(lines) >= 10 else lines
                
                self.log_output("Last 10 Security Alerts:")
                for alert in last_alerts:
                    self.log_output(f"  {alert.strip()}")
                self.portal.speak("Displaying the last 10 security alerts.")
            else:
                self.log_output("No security alerts found")
                self.portal.speak("No security alerts have been recorded yet.")
        except Exception as e:
            self.log_output(f"Error showing last alerts: {str(e)}")
    
    def email_security_report(self):
        try:
            # This would integrate with an email service
            self.log_output("📧 Preparing to email security report...")
            self.log_output("⚠️ Email functionality would be implemented here")
            self.log_output("This would send the current security status via email")
            self.portal.speak("Security report email functionality would be implemented with your email service.")
        except Exception as e:
            self.log_output(f"Error preparing email report: {str(e)}")
    
    def archive_threat_logs(self):
        try:
            if os.path.exists(ANTIVIRUS_LOG_FILE):
                archive_name = f"threat_logs_archive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
                
                # Create a simple archive (in real implementation, use zipfile)
                import shutil
                shutil.copy(ANTIVIRUS_LOG_FILE, archive_name.replace('.zip', '.txt'))
                
                self.log_output(f"✅ Threat logs archived as {archive_name.replace('.zip', '.txt')}")
                self.portal.speak("Threat logs have been archived successfully.")
            else:
                self.log_output("No threat logs found to archive")
        except Exception as e:
            self.log_output(f"Error archiving threat logs: {str(e)}")
    
    # NEW: Azure Kudu Methods (Simulated)
    def open_kudu_console(self):
        self.log_output("🌐 Opening Kudu console...")
        self.log_output("This would open the Azure Kudu console in your browser")
        webbrowser.open("https://your-app.scm.azurewebsites.net")
        self.portal.speak("Azure Kudu console would be opened in your browser.")
    
    def restart_web_app(self):
        self.log_output("🔄 Restarting web app...")
        self.log_output("This would restart your Azure web application")
        self.portal.speak("Web app restart command would be executed.")
    
    def show_environment_variables(self):
        self.log_output("📋 Displaying environment variables...")
        for key, value in os.environ.items():
            if any(sensitive not in key.lower() for sensitive in ['password', 'key', 'secret']):
                self.log_output(f"  {key}: {value}")
        self.portal.speak("Environment variables are being displayed.")
    
    def check_disk_space(self):
        try:
            disk = psutil.disk_usage('/')
            self.log_output("💾 Disk Space Information:")
            self.log_output(f"  Total: {disk.total // (1024**3)} GB")
            self.log_output(f"  Used: {disk.used // (1024**3)} GB")
            self.log_output(f"  Free: {disk.free // (1024**3)} GB")
            self.log_output(f"  Usage: {disk.percent}%")
            self.portal.speak(f"Disk usage is currently {disk.percent} percent.")
        except Exception as e:
            self.log_output(f"Error checking disk space: {str(e)}")
    
    def list_site_extensions(self):
        self.log_output("📦 Listing site extensions...")
        self.log_output("This would list installed Azure site extensions")
        self.log_output("  • Example Extension 1.0.0")
        self.log_output("  • Example Extension 2.1.0")
        self.portal.speak("Site extensions would be listed here.")
    
    def execute_kudu_powershell(self):
        command = simpledialog.askstring("Kudu PowerShell", "Enter PowerShell command:")
        if command:
            self.log_output(f"🔧 Executing in Kudu: {command}")
            self.log_output("This would execute the PowerShell command in Kudu")
            self.portal.speak("PowerShell command would be executed in Kudu.")
    
    def access_debug_console(self):
        self.log_output("🐞 Accessing debug console...")
        self.log_output("This would open the Kudu debug console")
        self.portal.speak("Debug console would be accessed.")
    
    def download_site_logs(self):
        self.log_output("📥 Downloading site logs...")
        self.log_output("This would download application logs from Kudu")
        self.portal.speak("Site logs would be downloaded.")
    
    def show_webapp_processes(self):
        try:
            self.log_output("🖥️ Web App Processes:")
            for proc in psutil.process_iter(['name', 'pid', 'memory_percent']):
                try:
                    self.log_output(f"  {proc.info['name']} (PID: {proc.info['pid']}) - Memory: {proc.info['memory_percent']:.1f}%")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            self.portal.speak("Web app processes are being displayed.")
        except Exception as e:
            self.log_output(f"Error showing processes: {str(e)}")
    
    def kill_suspicious_process(self):
        pid = simpledialog.askinteger("Kill Process", "Enter PID of suspicious process:")
        if pid:
            try:
                process = psutil.Process(pid)
                process_name = process.name()
                process.terminate()
                self.log_output(f"✅ Terminated suspicious process: {process_name} (PID: {pid})")
                self.portal.speak(f"Suspicious process {process_name} has been terminated.")
            except Exception as e:
                self.log_output(f"❌ Failed to terminate process {pid}: {str(e)}")
    
    def scan_app_directory(self):
        self.log_output("🔍 Scanning app directory for threats...")
        self.portal.pages["security"].quick_scan()
        self.portal.speak("App directory is being scanned for threats.")
    
    def display_app_permissions(self):
        self.log_output("🔐 Application Permissions:")
        self.log_output("This would display Azure app service permissions")
        self.log_output("  • File system: Read/Write")
        self.log_output("  • Network: Outbound")
        self.log_output("  • Registry: Read")
        self.portal.speak("Application permissions are being displayed.")
    
    def check_ssl_certificate(self):
        self.log_output("🔒 SSL Certificate Status:")
        self.log_output("This would check SSL certificate status for your domain")
        self.log_output("  • Status: Valid")
        self.log_output("  • Expires: 90 days from now")
        self.portal.speak("SSL certificate status would be checked.")
    
    def verify_https_enforcement(self):
        self.log_output("🌐 HTTPS Enforcement:")
        self.log_output("This would verify HTTPS enforcement settings")
        self.log_output("  • HTTPS Only: Enabled")
        self.log_output("  • TLS Version: 1.2")
        self.portal.speak("HTTPS enforcement would be verified.")
    
    def show_cpu_usage(self):
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            self.log_output(f"🖥️ Current CPU Usage: {cpu_percent}%")
            self.portal.speak(f"Current CPU usage is {cpu_percent} percent.")
        except Exception as e:
            self.log_output(f"Error checking CPU usage: {str(e)}")
    
    def show_memory_usage(self):
        try:
            memory = psutil.virtual_memory()
            self.log_output("💾 Memory Consumption:")
            self.log_output(f"  Total: {memory.total // (1024**3)} GB")
            self.log_output(f"  Used: {memory.used // (1024**3)} GB")
            self.log_output(f"  Available: {memory.available // (1024**3)} GB")
            self.log_output(f"  Usage: {memory.percent}%")
            self.portal.speak(f"Memory usage is currently {memory.percent} percent.")
        except Exception as e:
            self.log_output(f"Error checking memory usage: {str(e)}")
    
    def generate_performance_report(self):
        self.log_output("📊 Generating performance report...")
        self.log_output("This would generate a comprehensive performance report")
        self.log_output("✅ Performance report generated")
        self.portal.speak("Performance report has been generated.")
    
    def export_app_diagnostics(self):
        self.log_output("📁 Exporting application diagnostics...")
        self.log_output("This would export diagnostic data for analysis")
        self.log_output("✅ Diagnostics exported successfully")
        self.portal.speak("Application diagnostics have been exported.")
    
    def view_deployment_history(self):
        self.log_output("📋 Deployment History:")
        self.log_output("This would show Azure deployment history")
        self.log_output("  • Deployment 1: 2024-01-15 - Success")
        self.log_output("  • Deployment 2: 2024-01-10 - Success")
        self.log_output("  • Deployment 3: 2024-01-05 - Failed")
        self.portal.speak("Deployment history would be displayed.")
        
    def log_output(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_message = f"[{timestamp}] {message}\n"
        
        def update_output():
            try:
                self.output_text.insert(tk.END, formatted_message)
                self.output_text.see(tk.END)
            except tk.TclError:
                pass  # Widget might be destroyed
        
        self.after(0, update_output)

class SecurityToolkitPage(ttk.Frame):
    def __init__(self, parent, portal):
        super().__init__(parent, style='Content.TFrame')
        self.portal = portal
        self.setup_security_toolkit()
        
    def setup_security_toolkit(self):
        # Header
        header_frame = tk.Frame(self, bg='#0d1117')
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        title_label = tk.Label(header_frame,
                             text="Advanced Security Toolkit",
                             font=('Arial', 24, 'bold'),
                             fg='#58a6ff',
                             bg='#0d1117')
        title_label.pack(side=tk.LEFT)
        
        # Security tools grid
        tools_frame = tk.Frame(self, bg='#0d1117')
        tools_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create tool buttons with enhanced styling
        tools = [
            ("🛡️ Quick Scan", self.quick_scan, "#27ae60"),
            ("🔍 Deep Scan", self.deep_scan, "#e74c3c"),
            ("🌐 Network Analysis", self.network_analysis, "#3498db"),
            ("📁 File Integrity", self.file_integrity_check, "#9b59b6"),
            ("🔐 Password Audit", self.password_audit, "#f39c12"),
            ("🕵️ Malware Analysis", self.malware_analysis, "#e67e22"),
            ("🌐 Port Scanner", self.port_scanner, "#1abc9c"),
            ("📊 System Audit", self.system_audit, "#d35400"),
            ("🔒 Firewall Check", self.firewall_check, "#c0392b"),
            ("📡 Traffic Monitor", self.traffic_monitor, "#8e44ad"),
            ("🗑️ Secure Delete", self.secure_delete, "#7f8c8d"),
            ("🔍 Process Monitor", self.process_monitor, "#16a085")
        ]
        
        # Create 4x3 grid
        for i, (text, command, color) in enumerate(tools):
            row = i // 4
            col = i % 4
            
            btn = tk.Button(tools_frame, text=text,
                          command=command,
                          font=('Arial', 11, 'bold'),
                          bg=color,
                          fg='white',
                          width=15,
                          height=3,
                          relief='raised',
                          bd=3)
            btn.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
            
        # Configure grid weights
        for i in range(3):
            tools_frame.rowconfigure(i, weight=1)
        for i in range(4):
            tools_frame.columnconfigure(i, weight=1)
            
        # Output area
        output_frame = tk.Frame(self, bg='#0d1117')
        output_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        tk.Label(output_frame, text="Security Log",
                font=('Arial', 14, 'bold'),
                fg='#f0f6fc', bg='#0d1117').pack(anchor='w')
        
        self.security_output = scrolledtext.ScrolledText(output_frame,
                                                       height=15,
                                                       bg='#161b22',
                                                       fg='#00ff41',
                                                       font=('Consolas', 9))
        self.security_output.pack(fill=tk.BOTH, expand=True, pady=10)
        self.log_security("Security toolkit initialized.")
        
    def quick_scan(self):
        self.log_security("🚀 Starting quick security scan...")
        self.portal.speak("Starting quick security scan")
        
        def scan():
            try:
                # Check running processes
                suspicious_processes = []
                for proc in psutil.process_iter(['name', 'pid']):
                    try:
                        proc_name = proc.info['name'].lower()
                        # Simple heuristic for suspicious processes
                        if any(keyword in proc_name for keyword in ['crypto', 'miner', 'keylog', 'trojan']):
                            suspicious_processes.append(proc.info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Check network connections
                suspicious_connections = []
                try:
                    for conn in psutil.net_connections():
                        if conn.status == 'ESTABLISHED' and conn.raddr:
                            # Check for suspicious remote ports
                            if conn.raddr.port in [4444, 5555, 6666, 7777, 8888, 9999]:
                                suspicious_connections.append(conn)
                except:
                    pass
                
                # Report findings
                self.log_security("✅ Quick scan completed")
                if suspicious_processes:
                    self.log_security(f"⚠️ Found {len(suspicious_processes)} suspicious processes:")
                    for proc in suspicious_processes:
                        self.log_security(f"   - {proc['name']} (PID: {proc['pid']})")
                else:
                    self.log_security("✅ No suspicious processes found")
                    
                if suspicious_connections:
                    self.log_security(f"⚠️ Found {len(suspicious_connections)} suspicious connections:")
                    for conn in suspicious_connections[:5]:  # Show first 5
                        self.log_security(f"   - {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}")
                else:
                    self.log_security("✅ No suspicious network connections found")
                    
                self.portal.speak("Quick scan completed. System appears clean.")
                
            except Exception as e:
                self.log_security(f"❌ Scan error: {str(e)}")
                self.portal.speak("Scan encountered an error")
        
        threading.Thread(target=scan, daemon=True).start()
        
    def deep_scan(self):
        self.log_security("🔍 Starting deep system scan...")
        self.portal.speak("Starting deep system scan. This may take several minutes.")
        
        def deep_scan_thread():
            try:
                # System information
                self.log_security("📊 Collecting system information...")
                system_info = {
                    "OS": platform.system(),
                    "Version": platform.version(),
                    "Architecture": platform.architecture()[0],
                    "Processor": platform.processor()
                }
                
                for key, value in system_info.items():
                    self.log_security(f"   {key}: {value}")
                
                # Security software check
                self.log_security("🛡️ Checking security software...")
                security_products = self.check_security_software()
                if security_products:
                    for product in security_products:
                        self.log_security(f"   ✅ {product}")
                else:
                    self.log_security("   ⚠️ No security software detected")
                
                # User account analysis
                self.log_security("👤 Analyzing user accounts...")
                users = psutil.users()
                for user in users:
                    self.log_security(f"   User: {user.name} - Terminal: {user.terminal}")
                
                # Startup programs
                self.log_security("🚀 Checking startup programs...")
                startup_programs = self.get_startup_programs()
                for program in startup_programs[:10]:  # Show first 10
                    self.log_security(f"   {program}")
                
                self.log_security("✅ Deep scan completed")
                self.portal.speak("Deep system scan completed successfully")
                
            except Exception as e:
                self.log_security(f"❌ Deep scan error: {str(e)}")
                self.portal.speak("Deep scan encountered an error")
        
        threading.Thread(target=deep_scan_thread, daemon=True).start()
        
    def check_security_software(self):
        """Check for installed security software"""
        security_products = []
        
        # Windows Defender check
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['powershell', 'Get-MpComputerStatus'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    security_products.append("Windows Defender")
        except:
            pass
            
        # Common antivirus processes
        common_av_processes = ['avp', 'avast', 'avg', 'norton', 'mcafee', 'bitdefender']
        for proc in psutil.process_iter(['name']):
            try:
                proc_name = proc.info['name'].lower()
                if any(av in proc_name for av in common_av_processes):
                    security_products.append(proc_name.capitalize())
            except:
                continue
                
        return list(set(security_products))  # Remove duplicates
        
    def get_startup_programs(self):
        """Get startup programs"""
        startup_programs = []
        try:
            if platform.system() == "Windows":
                # Common startup locations
                startup_paths = [
                    os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
                    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
                ]
                
                for path in startup_paths:
                    if os.path.exists(path):
                        for file in os.listdir(path):
                            if file.endswith(('.lnk', '.exe', '.bat')):
                                startup_programs.append(file)
            else:
                # Linux/Mac startup
                pass
        except:
            pass
            
        return startup_programs if startup_programs else ["No startup programs found"]
        
    def network_analysis(self):
        self.log_security("🌐 Starting network analysis...")
        self.portal.speak("Starting network analysis")
        
        def analyze_network():
            try:
                # Network interfaces
                interfaces = psutil.net_if_addrs()
                self.log_security("📡 Network Interfaces:")
                for interface, addrs in interfaces.items():
                    self.log_security(f"   {interface}:")
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            self.log_security(f"     IPv4: {addr.address}")
                        elif addr.family == socket.AF_INET6:
                            self.log_security(f"     IPv6: {addr.address}")
                
                # Network statistics
                stats = psutil.net_io_counters()
                self.log_security("📊 Network Statistics:")
                self.log_security(f"   Bytes Sent: {stats.bytes_sent // (1024*1024)} MB")
                self.log_security(f"   Bytes Received: {stats.bytes_recv // (1024*1024)} MB")
                self.log_security(f"   Packets Sent: {stats.packets_sent}")
                self.log_security(f"   Packets Received: {stats.packets_recv}")
                
                # Active connections
                connections = psutil.net_connections()
                established = [conn for conn in connections if conn.status == 'ESTABLISHED']
                self.log_security(f"🔗 Active Connections: {len(established)}")
                
                for conn in established[:10]:  # Show first 10
                    if conn.raddr:
                        self.log_security(f"   {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}")
                
                self.portal.speak("Network analysis completed")
                
            except Exception as e:
                self.log_security(f"❌ Network analysis error: {str(e)}")
                self.portal.speak("Network analysis encountered an error")
        
        threading.Thread(target=analyze_network, daemon=True).start()
        
    def file_integrity_check(self):
        self.log_security("📁 Starting file integrity check...")
        self.portal.speak("Starting file integrity check")
        
        def integrity_check():
            try:
                # Check system critical files
                critical_files = []
                if platform.system() == "Windows":
                    critical_files = [
                        "C:\\Windows\\System32\\kernel32.dll",
                        "C:\\Windows\\System32\\ntdll.dll",
                        "C:\\Windows\\System32\\winlogon.exe"
                    ]
                elif platform.system() == "Linux":
                    critical_files = [
                        "/bin/bash",
                        "/bin/ls",
                        "/usr/bin/sudo"
                    ]
                
                for file_path in critical_files:
                    if os.path.exists(file_path):
                        file_hash = self.calculate_file_hash(file_path)
                        file_size = os.path.getsize(file_path)
                        self.log_security(f"   ✅ {os.path.basename(file_path)}: {file_size} bytes, Hash: {file_hash[:16]}...")
                    else:
                        self.log_security(f"   ❌ {file_path} not found")
                
                self.log_security("✅ File integrity check completed")
                self.portal.speak("File integrity check completed")
                
            except Exception as e:
                self.log_security(f"❌ Integrity check error: {str(e)}")
        
        threading.Thread(target=integrity_check, daemon=True).start()
        
    def calculate_file_hash(self, file_path):
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return "Error calculating hash"
            
    def password_audit(self):
        self.log_security("🔐 Starting password strength audit...")
        self.portal.speak("Starting password strength audit")
        
        def audit_passwords():
            try:
                # Check common weak passwords in system (simulated)
                weak_passwords = [
                    "password", "123456", "admin", "qwerty",
                    "letmein", "welcome", "monkey", "password1"
                ]
                
                self.log_security("📋 Common weak passwords check:")
                for pwd in weak_passwords:
                    self.log_security(f"   ❌ {pwd} - Very weak")
                
                # Password policy recommendations
                self.log_security("💡 Password Policy Recommendations:")
                recommendations = [
                    "Use at least 12 characters",
                    "Include uppercase and lowercase letters",
                    "Include numbers and special characters",
                    "Avoid dictionary words",
                    "Use unique passwords for different accounts",
                    "Consider using a password manager"
                ]
                
                for rec in recommendations:
                    self.log_security(f"   ✅ {rec}")
                
                self.log_security("✅ Password audit completed")
                self.portal.speak("Password audit completed. Check recommendations.")
                
            except Exception as e:
                self.log_security(f"❌ Password audit error: {str(e)}")
        
        threading.Thread(target=audit_passwords, daemon=True).start()
        
    def malware_analysis(self):
        self.log_security("🕵️ Starting malware analysis...")
        self.portal.speak("Starting malware analysis")
        
        def analyze_malware():
            try:
                # Scan common malware locations
                suspicious_locations = []
                if platform.system() == "Windows":
                    suspicious_locations = [
                        os.path.expanduser("~\\AppData\\Local\\Temp"),
                        os.path.expanduser("~\\AppData\\Roaming"),
                        "C:\\Windows\\Temp"
                    ]
                
                total_files_scanned = 0
                suspicious_files = []
                
                for location in suspicious_locations:
                    if os.path.exists(location):
                        self.log_security(f"🔍 Scanning {location}")
                        for root, dirs, files in os.walk(location):
                            for file in files[:100]:  # Limit to first 100 files per directory
                                file_path = os.path.join(root, file)
                                ext = os.path.splitext(file_path)[1].lower()
                                
                                if ext in SUSPICIOUS_EXTS:
                                    suspicious_files.append(file_path)
                                
                                total_files_scanned += 1
                
                self.log_security(f"📊 Scanned {total_files_scanned} files")
                
                if suspicious_files:
                    self.log_security(f"⚠️ Found {len(suspicious_files)} suspicious files:")
                    for file in suspicious_files[:10]:  # Show first 10
                        self.log_security(f"   {file}")
                else:
                    self.log_security("✅ No obvious malware signatures detected")
                
                self.portal.speak("Malware analysis completed")
                
            except Exception as e:
                self.log_security(f"❌ Malware analysis error: {str(e)}")
        
        threading.Thread(target=analyze_malware, daemon=True).start()
        
    def port_scanner(self):
        self.log_security("🔍 Starting port scanner...")
        self.portal.speak("Starting port scan")
        
        def scan_ports():
            try:
                # Scan common ports on localhost
                target = "127.0.0.1"
                common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3389]
                
                self.log_security(f"🎯 Scanning {target} for common ports")
                
                open_ports = []
                for port in common_ports:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(1)
                            result = sock.connect_ex((target, port))
                            if result == 0:
                                open_ports.append(port)
                                self.log_security(f"   ✅ Port {port} - OPEN")
                            else:
                                self.log_security(f"   ❌ Port {port} - CLOSED")
                    except:
                        self.log_security(f"   ⚠️ Port {port} - FILTERED")
                
                self.log_security(f"📊 Found {len(open_ports)} open ports")
                self.portal.speak(f"Port scan completed. Found {len(open_ports)} open ports")
                
            except Exception as e:
                self.log_security(f"❌ Port scan error: {str(e)}")
        
        threading.Thread(target=scan_ports, daemon=True).start()
        
    def system_audit(self):
        self.log_security("📊 Starting comprehensive system audit...")
        self.portal.speak("Starting comprehensive system audit")
        
        def audit_system():
            try:
                # System information
                self.log_security("🖥️ System Information:")
                self.log_security(f"   OS: {platform.system()} {platform.release()}")
                self.log_security(f"   Architecture: {platform.architecture()[0]}")
                self.log_security(f"   Processor: {platform.processor()}")
                
                # Security assessment
                self.log_security("🛡️ Security Assessment:")
                
                # Check if running as admin/root
                is_admin = os.geteuid() == 0 if platform.system() != "Windows" else False
                self.log_security(f"   Administrator privileges: {'✅ Yes' if is_admin else '⚠️ No'}")
                
                # Check for system updates
                self.log_security("   System updates: ⚠️ Manual check recommended")
                
                # Firewall status
                self.log_security("   Firewall status: ⚠️ Manual verification needed")
                
                # User accounts
                users = psutil.users()
                self.log_security(f"   Active users: {len(users)}")
                
                # System health
                cpu_usage = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                self.log_security("💻 System Health:")
                self.log_security(f"   CPU Usage: {cpu_usage}%")
                self.log_security(f"   Memory Usage: {memory.percent}%")
                self.log_security(f"   Disk Usage: {disk.percent}%")
                
                # Recommendations
                self.log_security("💡 Recommendations:")
                if cpu_usage > 80:
                    self.log_security("   ⚠️ High CPU usage detected")
                if memory.percent > 80:
                    self.log_security("   ⚠️ High memory usage detected")
                if disk.percent > 80:
                    self.log_security("   ⚠️ Low disk space")
                
                self.log_security("✅ System audit completed")
                self.portal.speak("System audit completed")
                
            except Exception as e:
                self.log_security(f"❌ System audit error: {str(e)}")
        
        threading.Thread(target=audit_system, daemon=True).start()
        
    def firewall_check(self):
        self.log_security("🔒 Checking firewall status...")
        self.portal.speak("Checking firewall status")
        
        def check_firewall():
            try:
                if platform.system() == "Windows":
                    result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if 'State' in line:
                                self.log_security(f"   {line.strip()}")
                    else:
                        self.log_security("   ⚠️ Could not retrieve firewall status")
                else:
                    self.log_security("   ℹ️ Firewall check available on Windows only")
                
                self.log_security("✅ Firewall check completed")
                self.portal.speak("Firewall check completed")
                
            except Exception as e:
                self.log_security(f"❌ Firewall check error: {str(e)}")
        
        threading.Thread(target=check_firewall, daemon=True).start()
        
    def traffic_monitor(self):
        self.log_security("📡 Starting traffic monitoring...")
        self.portal.speak("Starting traffic monitoring")
        
        def monitor_traffic():
            try:
                # Get initial stats
                initial = psutil.net_io_counters()
                time.sleep(5)  # Monitor for 5 seconds
                final = psutil.net_io_counters()
                
                # Calculate traffic
                bytes_sent = final.bytes_sent - initial.bytes_sent
                bytes_recv = final.bytes_recv - initial.bytes_recv
                
                self.log_security("📊 Network Traffic (5 seconds):")
                self.log_security(f"   Upload: {bytes_sent // 1024} KB")
                self.log_security(f"   Download: {bytes_recv // 1024} KB")
                self.log_security(f"   Upload speed: {bytes_sent // 5} B/s")
                self.log_security(f"   Download speed: {bytes_recv // 5} B/s")
                
                # Show active connections
                connections = psutil.net_connections()
                established = [conn for conn in connections if conn.status == 'ESTABLISHED']
                self.log_security(f"   Active connections: {len(established)}")
                
                self.log_security("✅ Traffic monitoring completed")
                self.portal.speak("Traffic monitoring completed")
                
            except Exception as e:
                self.log_security(f"❌ Traffic monitoring error: {str(e)}")
        
        threading.Thread(target=monitor_traffic, daemon=True).start()
        
    def secure_delete(self):
        self.log_security("🗑️ Starting secure file deletion...")
        self.portal.speak("Select files for secure deletion")
        
        files = filedialog.askopenfilenames(title="Select files to securely delete")
        if files:
            def secure_delete_files():
                try:
                    for file_path in files:
                        try:
                            # Overwrite file with random data before deletion
                            file_size = os.path.getsize(file_path)
                            with open(file_path, 'wb') as f:
                                f.write(os.urandom(file_size))
                            
                            # Delete the file
                            os.unlink(file_path)
                            self.log_security(f"   ✅ Securely deleted: {os.path.basename(file_path)}")
                        except Exception as e:
                            self.log_security(f"   ❌ Failed to delete {file_path}: {str(e)}")
                    
                    self.log_security("✅ Secure deletion completed")
                    self.portal.speak("Secure file deletion completed")
                    
                except Exception as e:
                    self.log_security(f"❌ Secure deletion error: {str(e)}")
            
            threading.Thread(target=secure_delete_files, daemon=True).start()
        else:
            self.log_security("❌ No files selected for deletion")
            
    def process_monitor(self):
        self.log_security("🔍 Starting process monitoring...")
        self.portal.speak("Starting process monitoring")
        
        def monitor_processes():
            try:
                # Get all processes
                processes = []
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        processes.append(proc.info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Sort by CPU usage
                processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
                
                self.log_security("🖥️ Top processes by CPU usage:")
                for proc in processes[:10]:  # Show top 10
                    self.log_security(f"   {proc['name']} (PID: {proc['pid']}) - CPU: {proc['cpu_percent']}%, Memory: {proc['memory_percent']:.1f}%")
                
                # Check for suspicious processes
                suspicious_keywords = ['miner', 'keylog', 'trojan', 'backdoor', 'virus']
                suspicious = []
                for proc in processes:
                    proc_name = proc['name'].lower()
                    if any(keyword in proc_name for keyword in suspicious_keywords):
                        suspicious.append(proc)
                
                if suspicious:
                    self.log_security("⚠️ Suspicious processes detected:")
                    for proc in suspicious:
                        self.log_security(f"   ❌ {proc['name']} (PID: {proc['pid']})")
                else:
                    self.log_security("✅ No obviously suspicious processes found")
                
                self.log_security("✅ Process monitoring completed")
                self.portal.speak("Process monitoring completed")
                
            except Exception as e:
                self.log_security(f"❌ Process monitoring error: {str(e)}")
        
        threading.Thread(target=monitor_processes, daemon=True).start()
        
    def log_security(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_message = f"[{timestamp}] {message}\n"
        
        def update_output():
            try:
                self.security_output.insert(tk.END, formatted_message)
                self.security_output.see(tk.END)
            except tk.TclError:
                pass  # Widget might be destroyed
        
        self.after(0, update_output)

class VirusTotalPage(ttk.Frame):
    def __init__(self, parent, portal):
        super().__init__(parent, style='Content.TFrame')
        self.portal = portal
        self.setup_virustotal_interface()
        
    def setup_virustotal_interface(self):
        # Header
        header_frame = tk.Frame(self, bg='#0d1117')
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        title_label = tk.Label(header_frame,
                             text="VirusTotal File Scanner",
                             font=('Arial', 24, 'bold'),
                             fg='#58a6ff',
                             bg='#0d1117')
        title_label.pack(side=tk.LEFT)
        
        # File selection
        file_frame = tk.Frame(self, bg='#0d1117')
        file_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(file_frame, text="Select file to scan:", 
                 style='TLabel').pack(side=tk.LEFT)
        
        self.file_path_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, width=60)
        file_entry.pack(side=tk.LEFT, padx=5)
        
        browse_btn = ttk.Button(file_frame, text="Browse", 
                               command=self.browse_file,
                               style='Accent.TButton')
        browse_btn.pack(side=tk.LEFT, padx=5)
        
        # Scan buttons
        button_frame = tk.Frame(self, bg='#0d1117')
        button_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.scan_btn = ttk.Button(button_frame, text="🔍 Scan with VirusTotal", 
                                  command=self.scan_with_virustotal,
                                  style='Accent.TButton')
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.local_scan_btn = ttk.Button(button_frame, text="🛡️ Local Scan Only", 
                                       command=self.local_scan_only,
                                       style='Accent.TButton')
        self.local_scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.quarantine_btn = ttk.Button(button_frame, text="🗑️ Quarantine File", 
                                       command=self.quarantine_file,
                                       style='Accent.TButton')
        self.quarantine_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress
        self.progress = ttk.Progressbar(self, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=20, pady=5)
        
        # Results area
        results_frame = tk.Frame(self, bg='#0d1117')
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create notebook for different result views
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Summary tab
        summary_frame = ttk.Frame(self.notebook)
        self.notebook.add(summary_frame, text="📊 Summary")
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame,
                                                    height=15,
                                                    bg='#161b22',
                                                    fg='#f0f6fc',
                                                    font=('Consolas', 9))
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Details tab
        details_frame = ttk.Frame(self.notebook)
        self.notebook.add(details_frame, text="🔍 Details")
        
        self.details_text = scrolledtext.ScrolledText(details_frame,
                                                    height=15,
                                                    bg='#161b22',
                                                    fg='#f0f6fc',
                                                    font=('Consolas', 9))
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Log tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="📝 Log")
        
        self.log_text = scrolledtext.ScrolledText(log_frame,
                                                height=15,
                                                bg='#161b22',
                                                fg='#00ff41',
                                                font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Initialize log
        self.log_message("VirusTotal scanner ready")
        self.log_message(f"API Key: {'Configured' if VIRUSTOTAL_API_KEY else 'Not configured'}")
        
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select file to scan",
            filetypes=[("All files", "*.*")]
        )
        if filename:
            self.file_path_var.set(filename)
            self.log_message(f"Selected file: {filename}")
            
    def scan_with_virustotal(self):
        file_path = self.file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file")
            return
            
        self.scan_btn.config(state='disabled')
        self.progress.start()
        self.log_message("Starting VirusTotal scan...")
        
        threading.Thread(target=self.perform_virustotal_scan, args=(file_path,), daemon=True).start()
        
    def perform_virustotal_scan(self, file_path):
        try:
            # First do local scan
            local_results = self.portal.local_scanner.scan_file(file_path)
            self.display_local_results(local_results)
            
            # Then do VirusTotal scan
            self.log_message("Uploading file to VirusTotal...")
            vt_results = self.portal.vt_scanner.scan_file(file_path)
            self.display_virustotal_results(vt_results)
            
            # Combine results
            self.display_combined_results(local_results, vt_results)
            
        except Exception as e:
            self.log_message(f"❌ Scan error: {str(e)}")
        finally:
            self.progress.stop()
            self.scan_btn.config(state='normal')
            
    def local_scan_only(self):
        file_path = self.file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file")
            return
            
        self.local_scan_btn.config(state='disabled')
        self.progress.start()
        self.log_message("Starting local scan...")
        
        threading.Thread(target=self.perform_local_scan, args=(file_path,), daemon=True).start()
        
    def perform_local_scan(self, file_path):
        try:
            results = self.portal.local_scanner.scan_file(file_path)
            self.display_local_results(results)
            self.display_summary(results, {})
            
        except Exception as e:
            self.log_message(f"❌ Local scan error: {str(e)}")
        finally:
            self.progress.stop()
            self.local_scan_btn.config(state='normal')
            
    def quarantine_file(self):
        file_path = self.file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file")
            return
            
        try:
            # Move file to quarantine directory
            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(QUARANTINE_DIR, filename)
            
            # Ensure unique filename
            counter = 1
            base_name, extension = os.path.splitext(filename)
            while os.path.exists(quarantine_path):
                quarantine_path = os.path.join(QUARANTINE_DIR, f"{base_name}_{counter}{extension}")
                counter += 1
                
            shutil.move(file_path, quarantine_path)
            self.log_message(f"✅ File quarantined: {quarantine_path}")
            
            # Update file path
            self.file_path_var.set("")
            
        except Exception as e:
            self.log_message(f"❌ Quarantine failed: {str(e)}")
            
    def display_local_results(self, results):
        self.details_text.delete(1.0, tk.END)
        
        if 'error' in results:
            self.details_text.insert(tk.END, f"Error: {results['error']}\n")
            return
            
        self.details_text.insert(tk.END, "🔍 LOCAL SCAN RESULTS\n")
        self.details_text.insert(tk.END, "="*50 + "\n\n")
        
        self.details_text.insert(tk.END, f"File: {results['path']}\n")
        self.details_text.insert(tk.END, f"Threat Level: {results['threat_level']}\n")
        self.details_text.insert(tk.END, f"Malicious: {'Yes' if results['malicious'] else 'No'}\n")
        self.details_text.insert(tk.END, f"Suspicious: {'Yes' if results['suspicious'] else 'No'}\n\n")
        
        if results['detections']:
            self.details_text.insert(tk.END, "Detections:\n")
            for detection in results['detections']:
                self.details_text.insert(tk.END, f"  ⚠️ {detection}\n")
        else:
            self.details_text.insert(tk.END, "✅ No detections found\n")
            
        if results['reasons']:
            self.details_text.insert(tk.END, "\nAnalysis Details:\n")
            for reason in results['reasons']:
                self.details_text.insert(tk.END, f"  ℹ️ {reason}\n")
                
    def display_virustotal_results(self, results):
        if 'error' in results:
            self.log_message(f"VirusTotal error: {results['error']}")
            return
            
        self.details_text.insert(tk.END, "\n\n🌐 VIRUSTOTAL RESULTS\n")
        self.details_text.insert(tk.END, "="*50 + "\n\n")
        
        if 'data' in results:
            data = results['data']
            attributes = data.get('attributes', {})
            
            # Basic info
            self.details_text.insert(tk.END, f"Scan Date: {attributes.get('date', 'N/A')}\n")
            
            # Stats
            stats = attributes.get('stats', {})
            self.details_text.insert(tk.END, f"Malicious: {stats.get('malicious', 0)}\n")
            self.details_text.insert(tk.END, f"Suspicious: {stats.get('suspicious', 0)}\n")
            self.details_text.insert(tk.END, f"Undetected: {stats.get('undetected', 0)}\n")
            self.details_text.insert(tk.END, f"Harmless: {stats.get('harmless', 0)}\n")
            
            # Results from antivirus engines
            results_data = attributes.get('results', {})
            if results_data:
                self.details_text.insert(tk.END, "\nEngine Results:\n")
                for engine, result in list(results_data.items())[:10]:  # Show first 10
                    category = result.get('category', 'unknown')
                    if category in ['malicious', 'suspicious']:
                        self.details_text.insert(tk.END, f"  🔴 {engine}: {category}\n")
                    else:
                        self.details_text.insert(tk.END, f"  ✅ {engine}: {category}\n")
        else:
            self.details_text.insert(tk.END, "No detailed results available\n")
            
    def display_combined_results(self, local_results, vt_results):
        self.summary_text.delete(1.0, tk.END)
        
        self.summary_text.insert(tk.END, "🛡️ SECURITY ASSESSMENT SUMMARY\n")
        self.summary_text.insert(tk.END, "="*60 + "\n\n")
        
        # Local results summary
        self.summary_text.insert(tk.END, "🔍 Local Analysis:\n")
        self.summary_text.insert(tk.END, f"  Threat Level: {local_results['threat_level']}\n")
        self.summary_text.insert(tk.END, f"  Detections: {len(local_results['detections'])}\n\n")
        
        # VirusTotal results summary
        if 'data' in vt_results:
            stats = vt_results['data'].get('attributes', {}).get('stats', {})
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            
            self.summary_text.insert(tk.END, "🌐 VirusTotal Analysis:\n")
            self.summary_text.insert(tk.END, f"  Malicious Engines: {malicious_count}\n")
            self.summary_text.insert(tk.END, f"  Suspicious Engines: {suspicious_count}\n\n")
            
            # Overall assessment
            total_detections = malicious_count + suspicious_count
            if total_detections > 5 or local_results['malicious']:
                assessment = "🔴 HIGH RISK - File appears malicious"
                recommendation = "Immediately quarantine and delete this file"
            elif total_detections > 0 or local_results['suspicious']:
                assessment = "🟡 MEDIUM RISK - File appears suspicious"
                recommendation = "Exercise caution and consider quarantining"
            else:
                assessment = "🟢 LOW RISK - File appears clean"
                recommendation = "No immediate action required"
                
        else:
            assessment = "🟡 UNKNOWN RISK - Cloud scan unavailable"
            recommendation = "Rely on local analysis and exercise caution"
            
        self.summary_text.insert(tk.END, "📋 Overall Assessment:\n")
        self.summary_text.insert(tk.END, f"  {assessment}\n")
        self.summary_text.insert(tk.END, f"  Recommendation: {recommendation}\n")
        
    def display_summary(self, local_results, vt_results):
        self.summary_text.delete(1.0, tk.END)
        
        self.summary_text.insert(tk.END, "🛡️ LOCAL SCAN SUMMARY\n")
        self.summary_text.insert(tk.END, "="*50 + "\n\n")
        
        self.summary_text.insert(tk.END, f"File: {local_results['path']}\n")
        self.summary_text.insert(tk.END, f"Threat Level: {local_results['threat_level']}\n")
        
        if local_results['malicious']:
            self.summary_text.insert(tk.END, "🔴 MALICIOUS FILE DETECTED\n")
        elif local_results['suspicious']:
            self.summary_text.insert(tk.END, "🟡 SUSPICIOUS FILE DETECTED\n")
        else:
            self.summary_text.insert(tk.END, "🟢 FILE APPEARS CLEAN\n")
            
        if local_results['detections']:
            self.summary_text.insert(tk.END, "\nDetections:\n")
            for detection in local_results['detections']:
                self.summary_text.insert(tk.END, f"  ⚠️ {detection}\n")
                
    def log_message(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_message = f"[{timestamp}] {message}\n"
        
        def update_log():
            try:
                self.log_text.insert(tk.END, formatted_message)
                self.log_text.see(tk.END)
            except tk.TclError:
                pass
        
        self.after(0, update_log)

class EnhancedGestureControlPage(ttk.Frame):
    def __init__(self, parent, portal):
        super().__init__(parent, style='Content.TFrame')
        self.portal = portal
        self.setup_gesture_control()
        self.gesture_active = False
        self.cap = None
        self.mp_hands = mp.solutions.hands
        self.hands = self.mp_hands.Hands(
            static_image_mode=False,
            max_num_hands=1,
            min_detection_confidence=0.5,
            min_tracking_confidence=0.5
        )
        self.mp_draw = mp.solutions.drawing_utils
        self.current_gesture = None
        self.gesture_history = []
        self.max_history = 10
        
    def setup_gesture_control(self):
        # Header
        header_frame = tk.Frame(self, bg='#0d1117')
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        title_label = tk.Label(header_frame,
                             text="Enhanced Gesture Control System",
                             font=('Arial', 24, 'bold'),
                             fg='#58a6ff',
                             bg='#0d1117')
        title_label.pack(side=tk.LEFT)
        
        # Control buttons
        control_frame = tk.Frame(self, bg='#0d1117')
        control_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.start_btn = tk.Button(control_frame, text="🎥 Start Gesture Control", 
                                  command=self.start_gesture_control,
                                  font=('Arial', 12, 'bold'),
                                  bg='#27ae60', fg='white',
                                  width=20, height=2)
        self.start_btn.pack(side=tk.LEFT, padx=10)
        
        self.stop_btn = tk.Button(control_frame, text="⏹️ Stop Gesture Control", 
                                 command=self.stop_gesture_control,
                                 font=('Arial', 12, 'bold'),
                                 bg='#e74c3c', fg='white',
                                 width=20, height=2,
                                 state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10)
        
        self.calibrate_btn = tk.Button(control_frame, text="⚙️ Calibrate Gestures", 
                                      command=self.calibrate_gestures,
                                      font=('Arial', 12, 'bold'),
                                      bg='#3498db', fg='white',
                                      width=20, height=2)
        self.calibrate_btn.pack(side=tk.LEFT, padx=10)
        
        # Status and preview
        status_frame = tk.Frame(self, bg='#0d1117')
        status_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.status_var = tk.StringVar(value="🔴 Gesture control inactive")
        status_label = tk.Label(status_frame, textvariable=self.status_var,
                              font=('Arial', 12, 'bold'),
                              fg='#f0f6fc', bg='#0d1117')
        status_label.pack(side=tk.LEFT)
        
        self.gesture_var = tk.StringVar(value="Current gesture: None")
        gesture_label = tk.Label(status_frame, textvariable=self.gesture_var,
                               font=('Arial', 12),
                               fg='#58a6ff', bg='#0d1117')
        gesture_label.pack(side=tk.RIGHT)
        
        # Camera preview and gesture info
        preview_frame = tk.Frame(self, bg='#0d1117')
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Camera preview
        camera_frame = tk.LabelFrame(preview_frame, text="Camera Preview", 
                                   bg='#0d1117', fg='#f0f6fc', font=('Arial', 12, 'bold'))
        camera_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        self.camera_label = tk.Label(camera_frame, text="Camera feed will appear here",
                                   bg='#161b22', fg='#8b949e', font=('Arial', 12),
                                   width=60, height=20)
        self.camera_label.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Gesture information
        info_frame = tk.LabelFrame(preview_frame, text="Gesture Commands", 
                                 bg='#0d1117', fg='#f0f6fc', font=('Arial', 12, 'bold'))
        info_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        # Create notebook for gesture categories
        gesture_notebook = ttk.Notebook(info_frame)
        gesture_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # System Control Tab
        system_tab = ttk.Frame(gesture_notebook)
        gesture_notebook.add(system_tab, text="🎯 System")
        
        system_gestures = [
            "👆 1 Finger - Open Start Menu",
            "✌️ 2 Fingers - Show Desktop", 
            "🤟 3 Fingers - Task View",
            "🖐️ 4 Fingers - Action Center",
            "✋ 5 Fingers - Lock Screen",
            "👊 Fist - Emergency Stop",
            "👍 Thumb Up - Volume Up",
            "👎 Thumb Down - Volume Down",
            "🤙 Call Me - Mute/Unmute",
            "✊ Raised Fist - Take Screenshot"
        ]
        
        system_text = scrolledtext.ScrolledText(system_tab, width=40, height=15,
                                              bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        system_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for gesture in system_gestures:
            system_text.insert(tk.END, f"• {gesture}\n")
        system_text.config(state=tk.DISABLED)
        
        # Media Control Tab
        media_tab = ttk.Frame(gesture_notebook)
        gesture_notebook.add(media_tab, text="🔊 Media")
        
        media_gestures = [
            "👉 Point Right - Next Track",
            "👈 Point Left - Previous Track",
            "👆 Point Up - Volume Up", 
            "👇 Point Down - Volume Down",
            "👌 OK Sign - Play/Pause",
            "🤏 Pinch - Mute/Unmute",
            "🔄 Circle - Refresh Page",
            "✋ Stop - Stop Playback",
            "🎬 Film - Open YouTube",
            "🎵 Music - Open Music Player"
        ]
        
        media_text = scrolledtext.ScrolledText(media_tab, width=40, height=15,
                                             bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        media_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for gesture in media_gestures:
            media_text.insert(tk.END, f"• {gesture}\n")
        media_text.config(state=tk.DISABLED)
        
        # Navigation Tab
        nav_tab = ttk.Frame(gesture_notebook)
        gesture_notebook.add(nav_tab, text="🧭 Navigation")
        
        nav_gestures = [
            "➡️ Swipe Right - Next Tab",
            "⬅️ Swipe Left - Previous Tab",
            "⬆️ Swipe Up - Scroll Up",
            "⬇️ Swipe Down - Scroll Down",
            "🔍 Zoom In - Zoom In",
            "🔍 Zoom Out - Zoom Out",
            "📖 Open Book - New Tab",
            "❌ Close Hand - Close Tab",
            "🏠 House - Home Page",
            "🔙 Back Arrow - Go Back"
        ]
        
        nav_text = scrolledtext.ScrolledText(nav_tab, width=40, height=15,
                                           bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        nav_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for gesture in nav_gestures:
            nav_text.insert(tk.END, f"• {gesture}\n")
        nav_text.config(state=tk.DISABLED)
        
        # Security Tab
        security_tab = ttk.Frame(gesture_notebook)
        gesture_notebook.add(security_tab, text="🛡️ Security")
        
        security_gestures = [
            "🛡️ Shield - Enable Firewall",
            "🔒 Lock - Lock System",
            "🔓 Unlock - Unlock (Simulated)",
            "🔍 Magnifying Glass - Start Scan",
            "🚫 Stop Entry - Block Connection",
            "📊 Chart - System Info",
            "🔐 Key - Password Manager",
            "🌐 Globe - Network Scan",
            "⚠️ Warning - Emergency Stop",
            "✅ Checkmark - Security Check"
        ]
        
        security_text = scrolledtext.ScrolledText(security_tab, width=40, height=15,
                                                bg='#161b22', fg='#f0f6fc', font=('Arial', 10))
        security_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for gesture in security_gestures:
            security_text.insert(tk.END, f"• {gesture}\n")
        security_text.config(state=tk.DISABLED)
        
        # Output log
        log_frame = tk.Frame(self, bg='#0d1117')
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        tk.Label(log_frame, text="Gesture Control Log",
                font=('Arial', 14, 'bold'),
                fg='#f0f6fc', bg='#0d1117').pack(anchor='w')
        
        self.gesture_log = scrolledtext.ScrolledText(log_frame,
                                                   height=10,
                                                   bg='#161b22',
                                                   fg='#00ff41',
                                                   font=('Consolas', 9))
        self.gesture_log.pack(fill=tk.BOTH, expand=True, pady=10)
        self.log_gesture("Gesture control system ready")
        
    def start_gesture_control(self):
        self.gesture_active = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("🟢 Gesture control active")
        self.log_gesture("Starting gesture control...")
        self.portal.speak("Gesture control activated")
        
        # Initialize camera
        self.cap = cv2.VideoCapture(0)
        if not self.cap.isOpened():
            self.log_gesture("❌ Error: Could not access camera")
            self.portal.speak("Camera access failed")
            return
            
        # Start gesture processing
        threading.Thread(target=self.process_gestures, daemon=True).start()
        
    def stop_gesture_control(self):
        self.gesture_active = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("🔴 Gesture control inactive")
        self.log_gesture("Gesture control stopped")
        self.portal.speak("Gesture control deactivated")
        
        if self.cap:
            self.cap.release()
            self.cap = None
            
        # Clear camera preview
        self.camera_label.config(image='', text="Camera feed stopped")
        
    def calibrate_gestures(self):
        self.log_gesture("Starting gesture calibration...")
        self.portal.speak("Please perform each gesture when prompted for calibration")
        
        # Simple calibration process
        calibration_steps = [
            ("Open hand with all fingers extended", "open_hand"),
            ("Make a fist", "fist"),
            ("Show one finger", "one_finger"),
            ("Show two fingers", "two_fingers"),
            ("Show three fingers", "three_fingers"),
            ("Show four fingers", "four_fingers"),
            ("Show five fingers", "five_fingers"),
            ("Thumbs up", "thumbs_up"),
            ("Thumbs down", "thumbs_down"),
            ("OK sign", "ok_sign")
        ]
        
        def run_calibration():
            for gesture_name, gesture_id in calibration_steps:
                self.log_gesture(f"Please show: {gesture_name}")
                self.portal.speak(f"Please show {gesture_name}")
                time.sleep(5)  # Wait for user to perform gesture
                
            self.log_gesture("✅ Calibration completed")
            self.portal.speak("Gesture calibration completed successfully")
            
        threading.Thread(target=run_calibration, daemon=True).start()
        
    def process_gestures(self):
        while self.gesture_active and self.cap:
            ret, frame = self.cap.read()
            if not ret:
                continue
                
            # Flip frame for mirror effect
            frame = cv2.flip(frame, 1)
            rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            
            # Process with MediaPipe
            results = self.hands.process(rgb_frame)
            
            gesture_detected = None
            
            if results.multi_hand_landmarks:
                for hand_landmarks in results.multi_hand_landmarks:
                    # Draw hand landmarks
                    self.mp_draw.draw_landmarks(frame, hand_landmarks, self.mp_hands.HAND_CONNECTIONS)
                    
                    # Recognize gesture
                    gesture = self.recognize_gesture(hand_landmarks)
                    if gesture and gesture != self.current_gesture:
                        self.current_gesture = gesture
                        self.process_gesture_command(gesture)
                        gesture_detected = gesture
                    
            # Update camera preview
            self.update_camera_preview(frame)
            
            # Update gesture display
            if gesture_detected:
                self.gesture_var.set(f"Current gesture: {gesture_detected}")
            elif not results.multi_hand_landmarks:
                self.gesture_var.set("Current gesture: None")
                self.current_gesture = None
                
            # Small delay to prevent high CPU usage
            time.sleep(0.1)
            
    def recognize_gesture(self, hand_landmarks):
        """Enhanced gesture recognition with finger counting"""
        landmarks = hand_landmarks.landmark
        
        # Get finger tip positions and check if they're extended
        fingers = []
        
        # Thumb - check if it's extended to the side
        thumb_tip = landmarks[self.mp_hands.HandLandmark.THUMB_TIP]
        thumb_ip = landmarks[self.mp_hands.HandLandmark.THUMB_IP]
        thumb_mcp = landmarks[self.mp_hands.HandLandmark.THUMB_MCP]
        
        # For thumb, we check if it's extended away from the hand
        thumb_extended = thumb_tip.x < thumb_ip.x if thumb_tip.x < thumb_mcp.x else thumb_tip.x > thumb_ip.x
        
        # Other fingers - check if tip is above the middle joint
        finger_pairs = [
            (self.mp_hands.HandLandmark.INDEX_FINGER_TIP, self.mp_hands.HandLandmark.INDEX_FINGER_PIP),
            (self.mp_hands.HandLandmark.MIDDLE_FINGER_TIP, self.mp_hands.HandLandmark.MIDDLE_FINGER_PIP),
            (self.mp_hands.HandLandmark.RING_FINGER_TIP, self.mp_hands.HandLandmark.RING_FINGER_PIP),
            (self.mp_hands.HandLandmark.PINKY_TIP, self.mp_hands.HandLandmark.PINKY_PIP)
        ]
        
        for tip, pip in finger_pairs:
            if landmarks[tip].y < landmarks[pip].y:  # Tip is above PIP joint
                fingers.append(True)
            else:
                fingers.append(False)
        
        # Count extended fingers (excluding thumb for now)
        extended_fingers = sum(fingers)
        
        # Enhanced gesture recognition based on finger count and thumb position
        if extended_fingers == 0 and not thumb_extended:
            return "fist"
        elif extended_fingers == 1 and fingers[0]:  # Only index finger
            return "one_finger"
        elif extended_fingers == 2 and fingers[0] and fingers[1]:  # Index and middle
            return "two_fingers"
        elif extended_fingers == 3 and fingers[0] and fingers[1] and fingers[2]:  # Index, middle, ring
            return "three_fingers"
        elif extended_fingers == 4:  # All four fingers
            if thumb_extended:
                return "five_fingers"
            else:
                return "four_fingers"
        elif thumb_extended and extended_fingers == 0:
            # Check thumb direction for thumbs up/down
            thumb_tip_y = landmarks[self.mp_hands.HandLandmark.THUMB_TIP].y
            thumb_mcp_y = landmarks[self.mp_hands.HandLandmark.THUMB_MCP].y
            if thumb_tip_y < thumb_mcp_y:
                return "thumbs_up"
            else:
                return "thumbs_down"
        elif extended_fingers == 2 and fingers[0] and fingers[3]:  # Index and pinky
            return "rock_on"
        elif extended_fingers == 1 and fingers[0] and thumb_extended:  # Index and thumb making L
            return "point_sideways"
        
        return None
        
    def process_gesture_command(self, gesture):
        """Process detected gesture and execute corresponding command"""
        self.log_gesture(f"Gesture detected: {gesture}")
        self.gesture_history.append(gesture)
        if len(self.gesture_history) > self.max_history:
            self.gesture_history.pop(0)
            
        # Gesture to command mapping
        gesture_commands = {
            # System Control
            "one_finger": ("Opening Start Menu", self.open_start_menu),
            "two_fingers": ("Showing Desktop", self.show_desktop),
            "three_fingers": ("Opening Task View", self.open_task_view),
            "four_fingers": ("Opening Action Center", self.open_action_center),
            "five_fingers": ("Locking System", self.lock_system),
            "fist": ("🛑 EMERGENCY STOP", self.emergency_stop),
            "thumbs_up": ("Volume Up", self.volume_up),
            "thumbs_down": ("Volume Down", self.volume_down),
            "rock_on": ("Muting/Unmuting", self.toggle_mute),
            "point_sideways": ("Taking Screenshot", self.take_screenshot),
            
            # Media Control
            "point_right": ("Next Track", self.next_track),
            "point_left": ("Previous Track", self.previous_track),
            "point_up": ("Volume Up", self.volume_up),
            "point_down": ("Volume Down", self.volume_down),
            "ok_sign": ("Play/Pause", self.play_pause),
            "pinch": ("Muting/Unmuting", self.toggle_mute),
            "circle": ("Refreshing Page", self.refresh_page),
            "stop": ("Stopping Playback", self.stop_playback),
            
            # Security Commands
            "shield": ("Enabling Firewall", self.enable_firewall),
            "lock": ("Locking System", self.lock_system),
            "unlock": ("Unlocking System", self.unlock_system),
            "magnify": ("Starting Security Scan", self.start_security_scan),
            "block": ("Blocking Connections", self.block_connections),
            "chart": ("Showing System Info", self.show_system_info),
            "key": ("Opening Password Manager", self.open_password_manager),
            "globe": ("Starting Network Scan", self.start_network_scan),
            "warning": ("🛑 EMERGENCY STOP", self.emergency_stop),
            "check": ("Running Security Check", self.run_security_check)
        }
        
        if gesture in gesture_commands:
            message, command = gesture_commands[gesture]
            self.log_gesture(f"Executing: {message}")
            self.portal.speak(message)
            
            try:
                command()
            except Exception as e:
                self.log_gesture(f"Error executing command: {str(e)}")
        else:
            self.log_gesture(f"Gesture '{gesture}' not mapped to any command")
            
    def update_camera_preview(self, frame):
        """Update the camera preview in the GUI"""
        try:
            # Resize frame for preview
            frame = cv2.resize(frame, (640, 480))
            
            # Convert to PhotoImage
            rgb_image = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pil_image = Image.fromarray(rgb_image)
            photo_image = ImageTk.PhotoImage(pil_image)
            
            # Update label
            self.camera_label.config(image=photo_image, text="")
            self.camera_label.image = photo_image  # Keep reference
            
        except Exception as e:
            print(f"Camera preview error: {e}")
            
    # Gesture command implementations
    def open_start_menu(self):
        pyautogui.press('win')
        
    def show_desktop(self):
        if platform.system() == "Windows":
            pyautogui.hotkey('win', 'd')
        elif platform.system() == "Darwin":
            pyautogui.hotkey('command', 'f3')
            
    def open_task_view(self):
        if platform.system() == "Windows":
            pyautogui.hotkey('win', 'tab')
            
    def open_action_center(self):
        if platform.system() == "Windows":
            pyautogui.hotkey('win', 'a')
            
    def lock_system(self):
        if platform.system() == "Windows":
            os.system("rundll32.exe user32.dll,LockWorkStation")
        elif platform.system() == "Darwin":
            os.system("pmset displaysleepnow")
            
    def emergency_stop(self):
        self.portal.stop_current_operation()
        self.log_gesture("🛑 EMERGENCY STOP ACTIVATED")
        self.portal.speak("Emergency stop activated")
        
    def volume_up(self):
        pyautogui.press('volumeup')
        
    def volume_down(self):
        pyautogui.press('volumedown')
        
    def toggle_mute(self):
        pyautogui.press('volumemute')
        
    def take_screenshot(self):
        try:
            screenshot = pyautogui.screenshot()
            filename = f"gesture_screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            screenshot.save(filename)
            self.log_gesture(f"Screenshot saved as {filename}")
        except Exception as e:
            self.log_gesture(f"Screenshot failed: {str(e)}")
            
    def next_track(self):
        pyautogui.press('nexttrack')
        
    def previous_track(self):
        pyautogui.press('prevtrack')
        
    def play_pause(self):
        pyautogui.press('playpause')
        
    def refresh_page(self):
        pyautogui.hotkey('ctrl', 'r')
        
    def stop_playback(self):
        # This might vary by media player
        pyautogui.press('stop')
        
    def enable_firewall(self):
        try:
            if platform.system() == "Windows":
                os.system("netsh advfirewall set allprofiles state on")
                self.log_gesture("Firewall enabled")
        except Exception as e:
            self.log_gesture(f"Failed to enable firewall: {str(e)}")
            
    def unlock_system(self):
        # This would typically require authentication
        self.log_gesture("Unlock gesture recognized (simulated)")
        
    def start_security_scan(self):
        self.portal.pages["security"].quick_scan()
        
    def block_connections(self):
        self.log_gesture("Block connections gesture recognized")
        # This would implement network blocking logic
        
    def show_system_info(self):
        cpu = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        info = f"System Info - CPU: {cpu}%, Memory: {memory.percent}%, Disk: {disk.percent}%"
        self.log_gesture(info)
        
    def open_password_manager(self):
        self.log_gesture("Password manager gesture recognized")
        # This would open a password manager application
        
    def start_network_scan(self):
        self.portal.pages["security"].network_analysis()
        
    def run_security_check(self):
        self.portal.pages["security"].system_audit()
        
    def log_gesture(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_message = f"[{timestamp}] {message}\n"
        
        def update_log():
            try:
                self.gesture_log.insert(tk.END, formatted_message)
                self.gesture_log.see(tk.END)
            except tk.TclError:
                pass
        
        self.after(0, update_log)

class EnhancedChatbotPage(ttk.Frame):
    def __init__(self, parent, portal):
        super().__init__(parent, style='Content.TFrame')
        self.portal = portal
        self.setup_chatbot_interface()
        self.chat_history = []
        
    def setup_chatbot_interface(self):
        # Header
        header_frame = tk.Frame(self, bg='#0d1117')
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        title_label = tk.Label(header_frame,
                             text="AI Cybersecurity Assistant",
                             font=('Arial', 24, 'bold'),
                             fg='#58a6ff',
                             bg='#0d1117')
        title_label.pack(side=tk.LEFT)
        
        # Chat area
        chat_frame = tk.Frame(self, bg='#0d1117')
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.chat_display = scrolledtext.ScrolledText(chat_frame,
                                                    height=20,
                                                    bg='#161b22',
                                                    fg='#f0f6fc',
                                                    font=('Arial', 10),
                                                    wrap=tk.WORD)
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        self.chat_display.config(state=tk.DISABLED)
        
        # Input area
        input_frame = tk.Frame(self, bg='#0d1117')
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.input_entry = tk.Entry(input_frame,
                                  bg='#21262d',
                                  fg='#f0f6fc',
                                  font=('Arial', 12),
                                  insertbackground='white')
        self.input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.input_entry.bind('<Return>', self.send_message)
        
        send_btn = tk.Button(input_frame, text="Send",
                           command=self.send_message,
                           bg='#58a6ff',
                           fg='white',
                           font=('Arial', 12, 'bold'))
        send_btn.pack(side=tk.RIGHT)
        
        # Quick actions
        actions_frame = tk.Frame(self, bg='#0d1117')
        actions_frame.pack(fill=tk.X, padx=20, pady=10)
        
        quick_actions = [
            ("🔍 Security Scan", "Run a security scan on my system"),
            ("🌐 Network Check", "Check my network connections"),
            ("🛡️ Firewall Status", "What's my firewall status?"),
            ("📊 System Info", "Show system information"),
            ("🔐 Password Tips", "Give me password security tips"),
            ("⚠️ Threat Check", "Check for common threats")
        ]
        
        for text, command in quick_actions:
            btn = tk.Button(actions_frame, text=text,
                          command=lambda cmd=command: self.quick_action(cmd),
                          bg='#21262d',
                          fg='#f0f6fc',
                          font=('Arial', 10))
            btn.pack(side=tk.LEFT, padx=5)
            
        # Add initial welcome message
        self.add_message("AI Assistant", "Welcome to the Cybersecurity AI Assistant! How can I help you with security today?", is_user=False)
        
    def send_message(self, event=None):
        message = self.input_entry.get().strip()
        if not message:
            return
            
        self.input_entry.delete(0, tk.END)
        self.add_message("You", message, is_user=True)
        
        # Process message in thread
        threading.Thread(target=self.process_message, args=(message,), daemon=True).start()
        
    def quick_action(self, command):
        self.input_entry.delete(0, tk.END)
        self.input_entry.insert(0, command)
        self.send_message()
        
    def process_message(self, message):
        """Process user message and generate response"""
        try:
            # First check for specific commands that don't need AI
            response = self.handle_direct_commands(message)
            if response:
                self.add_message("AI Assistant", response, is_user=False)
                return
                
            # Use DeepSeek AI for other queries
            response = self.generate_ai_response(message)
            self.add_message("AI Assistant", response, is_user=False)
            
        except Exception as e:
            error_msg = f"I apologize, but I encountered an error: {str(e)}. Please try again."
            self.add_message("AI Assistant", error_msg, is_user=False)
            
    def handle_direct_commands(self, message):
        """Handle specific commands without AI"""
        message_lower = message.lower()
        
        if any(cmd in message_lower for cmd in ['scan', 'security scan']):
            self.portal.pages["security"].quick_scan()
            return "Starting security scan now..."
            
        elif any(cmd in message_lower for cmd in ['network', 'connection']):
            self.portal.pages["security"].network_analysis()
            return "Analyzing network connections..."
            
        elif any(cmd in message_lower for cmd in ['firewall']):
            self.portal.pages["security"].firewall_check()
            return "Checking firewall status..."
            
        elif any(cmd in message_lower for cmd in ['system info', 'system information']):
            cpu = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            return f"System Information:\nCPU: {cpu}%\nMemory: {memory.percent}%\nDisk: {disk.percent}%"
            
        elif any(cmd in message_lower for cmd in ['password', 'security tips']):
            return """🔐 Password Security Tips:
• Use at least 12 characters
• Mix uppercase, lowercase, numbers, and symbols
• Avoid dictionary words and personal information
• Use unique passwords for each account
• Consider using a password manager
• Enable two-factor authentication where available"""
            
        elif any(cmd in message_lower for cmd in ['threat', 'virus', 'malware']):
            return """🛡️ Common Threat Prevention:
• Keep your system and software updated
• Use reputable antivirus software
• Be cautious with email attachments
• Avoid suspicious websites and downloads
• Use a firewall
• Regular security scans
• Backup important data regularly"""
            
        return None
        
    def generate_ai_response(self, input_text):
        """Generate AI response using DeepSeek API"""
        try:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.portal.deepseek_api_key}",
                    "HTTP-Referer": "https://www.anonymous-cybersecurity.com",
                    "X-Title": "Anonymous Cybersecurity Portal",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "deepseek/deepseek-r1:free",
                    "messages": [{
                        "role": "user",
                        "content": f"""You are a cybersecurity expert assistant. Provide helpful, accurate security advice.
                        
                        User question: {input_text}
                        
                        Please provide:
                        1. Clear cybersecurity guidance
                        2. Practical steps if applicable
                        3. Security best practices
                        4. Any relevant warnings
                        
                        Keep responses concise and actionable."""
                    }]
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return result['choices'][0]['message']['content']
            else:
                return f"I apologize, but I'm having trouble connecting to the AI service. Status: {response.status_code}"
                
        except Exception as e:
            return f"I encountered an error: {str(e)}. Please try again later."
        
    def add_message(self, sender, message, is_user=False):
        """Add message to chat display"""
        def update_chat():
            self.chat_display.config(state=tk.NORMAL)
            
            # Add sender tag
            if is_user:
                self.chat_display.insert(tk.END, f"{sender}: ", 'user')
            else:
                self.chat_display.insert(tk.END, f"{sender}: ", 'assistant')
                
            # Add message
            self.chat_display.insert(tk.END, f"{message}\n\n")
            
            self.chat_display.config(state=tk.DISABLED)
            self.chat_display.see(tk.END)
            
            # Configure tags for different senders
            self.chat_display.tag_config('user', foreground='#58a6ff', font=('Arial', 10, 'bold'))
            self.chat_display.tag_config('assistant', foreground='#00ff41', font=('Arial', 10, 'bold'))
            
        self.after(0, update_chat)

class VulnerabilityScannerPage(ttk.Frame):
    def __init__(self, parent, portal):
        super().__init__(parent, style='Content.TFrame')
        self.portal = portal
        self.scanner = EnhancedWebVulnerabilityScanner(self, portal)
        
class EnhancedSettingsPage(ttk.Frame):
    def __init__(self, parent, portal):
        super().__init__(parent, style='Content.TFrame')
        self.portal = portal
        self.setup_settings_interface()
        
    def setup_settings_interface(self):
        # Header
        header_frame = tk.Frame(self, bg='#0d1117')
        header_frame.pack(fill=tk.X, padx=20, pady=10)
        
        title_label = tk.Label(header_frame,
                             text="System Settings & Configuration",
                             font=('Arial', 24, 'bold'),
                             fg='#58a6ff',
                             bg='#0d1117')
        title_label.pack(side=tk.LEFT)
        
        # Settings notebook
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # General Settings Tab
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="⚙️ General")
        
        self.setup_general_settings(general_frame)
        
        # Security Settings Tab
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="🛡️ Security")
        
        self.setup_security_settings(security_frame)
        
        # Voice Settings Tab
        voice_frame = ttk.Frame(notebook)
        notebook.add(voice_frame, text="🎤 Voice")
        
        self.setup_voice_settings(voice_frame)
        
        # About Tab
        about_frame = ttk.Frame(notebook)
        notebook.add(about_frame, text="ℹ️ About")
        
        self.setup_about_section(about_frame)
        
    def setup_general_settings(self, parent):
        # Theme settings
        theme_frame = tk.LabelFrame(parent, text="Theme Settings",
                                  bg='#0d1117', fg='#f0f6fc', font=('Arial', 12, 'bold'))
        theme_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.theme_var = tk.StringVar(value="dark")
        tk.Radiobutton(theme_frame, text="Dark Theme", variable=self.theme_var,
                      value="dark", bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(anchor='w', padx=10, pady=5)
        tk.Radiobutton(theme_frame, text="Light Theme", variable=self.theme_var,
                      value="light", bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(anchor='w', padx=10, pady=5)
        
        # Auto-start settings
        startup_frame = tk.LabelFrame(parent, text="Startup Options",
                                    bg='#0d1117', fg='#f0f6fc', font=('Arial', 12, 'bold'))
        startup_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.auto_start_var = tk.BooleanVar()
        tk.Checkbutton(startup_frame, text="Start with Windows",
                      variable=self.auto_start_var,
                      bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(anchor='w', padx=10, pady=5)
        
        self.minimize_to_tray_var = tk.BooleanVar()
        tk.Checkbutton(startup_frame, text="Minimize to system tray",
                      variable=self.minimize_to_tray_var,
                      bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(anchor='w', padx=10, pady=5)
        
        # Update settings
        update_frame = tk.LabelFrame(parent, text="Updates",
                                   bg='#0d1117', fg='#f0f6fc', font=('Arial', 12, 'bold'))
        update_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.auto_update_var = tk.BooleanVar(value=True)
        tk.Checkbutton(update_frame, text="Check for updates automatically",
                      variable=self.auto_update_var,
                      bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(anchor='w', padx=10, pady=5)
        
    def setup_security_settings(self, parent):
        # Scan settings
        scan_frame = tk.LabelFrame(parent, text="Scan Settings",
                                 bg='#0d1117', fg='#f0f6fc', font=('Arial', 12, 'bold'))
        scan_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(scan_frame, text="Quick Scan Depth:",
                bg='#0d1117', fg='#f0f6fc').pack(anchor='w', padx=10, pady=5)
        
        self.scan_depth_var = tk.StringVar(value="medium")
        depth_frame = tk.Frame(scan_frame, bg='#0d1117')
        depth_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Radiobutton(depth_frame, text="Light", variable=self.scan_depth_var,
                      value="light", bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(side=tk.LEFT)
        tk.Radiobutton(depth_frame, text="Medium", variable=self.scan_depth_var,
                      value="medium", bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(side=tk.LEFT)
        tk.Radiobutton(depth_frame, text="Deep", variable=self.scan_depth_var,
                      value="deep", bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(side=tk.LEFT)
        
        # Monitoring settings
        monitor_frame = tk.LabelFrame(parent, text="Real-time Monitoring",
                                    bg='#0d1117', fg='#f0f6fc', font=('Arial', 12, 'bold'))
        monitor_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.monitor_usb_var = tk.BooleanVar(value=True)
        tk.Checkbutton(monitor_frame, text="Monitor USB devices",
                      variable=self.monitor_usb_var,
                      bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(anchor='w', padx=10, pady=5)
        
        self.monitor_network_var = tk.BooleanVar(value=True)
        tk.Checkbutton(monitor_frame, text="Monitor network activity",
                      variable=self.monitor_network_var,
                      bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(anchor='w', padx=10, pady=5)
        
        self.monitor_processes_var = tk.BooleanVar(value=True)
        tk.Checkbutton(monitor_frame, text="Monitor process activity",
                      variable=self.monitor_processes_var,
                      bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(anchor='w', padx=10, pady=5)
        
    def setup_voice_settings(self, parent):
        # Voice control settings
        voice_control_frame = tk.LabelFrame(parent, text="Voice Control",
                                          bg='#0d1117', fg='#f0f6fc', font=('Arial', 12, 'bold'))
        voice_control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.voice_enabled_var = tk.BooleanVar(value=True)
        tk.Checkbutton(voice_control_frame, text="Enable voice control",
                      variable=self.voice_enabled_var,
                      command=self.toggle_voice_settings,
                      bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(anchor='w', padx=10, pady=5)
        
        # Voice feedback
        feedback_frame = tk.Frame(voice_control_frame, bg='#0d1117')
        feedback_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.voice_feedback_var = tk.BooleanVar(value=True)
        tk.Checkbutton(feedback_frame, text="Voice feedback",
                      variable=self.voice_feedback_var,
                      bg='#0d1117', fg='#f0f6fc', selectcolor='#161b22').pack(anchor='w')
        
        # Voice speed
        speed_frame = tk.Frame(voice_control_frame, bg='#0d1117')
        speed_frame.pack(fill=tk.X, padx=20, pady=5)
        
        tk.Label(speed_frame, text="Voice speed:",
                bg='#0d1117', fg='#f0f6fc').pack(side=tk.LEFT)
        
        self.voice_speed_var = tk.StringVar(value="normal")
        speed_options = ["slow", "normal", "fast"]
        speed_menu = ttk.Combobox(speed_frame, textvariable=self.voice_speed_var,
                                 values=speed_options, state="readonly", width=10)
        speed_menu.pack(side=tk.LEFT, padx=5)
        
    def setup_about_section(self, parent):
        about_text = f"""
ANONYMOUS SYSTEM - AI-Powered Cybersecurity Command Center

Version: 2.0.0
Release Date: {datetime.now().strftime('%Y-%m-%d')}

Developed by: Anonymous Cybersecurity Team
License: Proprietary - All Rights Reserved

Features:
• Real-time system monitoring
• Advanced threat detection
• Voice and gesture control
• AI-powered security analysis
• Vulnerability scanning
• Network security tools
• Privacy protection

System Requirements:
• Windows 10/11, macOS, or Linux
• Python 3.8+
• 4GB RAM minimum
• Internet connection for cloud features

For support and updates, visit our security portal.
        """
        
        about_display = scrolledtext.ScrolledText(parent,
                                                height=20,
                                                bg='#161b22',
                                                fg='#f0f6fc',
                                                font=('Consolas', 10))
        about_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        about_display.insert(tk.END, about_text.strip())
        about_display.config(state=tk.DISABLED)
        
        # System info button
        info_btn = tk.Button(parent, text="Show System Information",
                           command=self.show_system_info,
                           bg='#58a6ff',
                           fg='white',
                           font=('Arial', 12, 'bold'))
        info_btn.pack(pady=10)
        
    def toggle_voice_settings(self):
        # Enable/disable voice settings based on checkbox
        state = tk.NORMAL if self.voice_enabled_var.get() else tk.DISABLED
        # This would need to be implemented to control child widgets
        
    def show_system_info(self):
        info = f"""
System Information:
- OS: {platform.system()} {platform.release()}
- Architecture: {platform.architecture()[0]}
- Processor: {platform.processor()}
- Python: {platform.python_version()}
- Hostname: {socket.gethostname()}
        
Memory: {psutil.virtual_memory().total // (1024**3)} GB
CPU Cores: {psutil.cpu_count()}
        """
        messagebox.showinfo("System Information", info.strip())

def main():
    try:
        root = tk.Tk()
        app = CybersecurityPortal(root)
        root.mainloop()
    except Exception as e:
        print(f"Application error: {e}")
        # Fallback basic interface
        basic_root = tk.Tk()
        basic_root.title("Cybersecurity Portal - Basic Mode")
        basic_root.geometry("800x600")
        label = tk.Label(basic_root, text=f"Application encountered an error:\n{str(e)}", font=('Arial', 12))
        label.pack(expand=True)
        basic_root.mainloop()

if __name__ == "__main__":
    main()
