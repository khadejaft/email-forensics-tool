import re
import requests
import time
import hashlib
import os
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup

class ThreatDetector:
    def __init__(self, virustotal_api_key=None, google_api_key=None):
        self.virustotal_api_key = virustotal_api_key
        self.google_api_key = google_api_key
        self.use_online_check = False
        
        # Cache for performance
        self.url_cache = {}  # Cache for URL redirects
        self.domain_cache = {}  # Cache for WHOIS results
        self.whois_timeout = 2  # 2 second timeout max
        
        # Suspicious file extensions
        self.suspicious_extensions = [
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js', 
            '.jar', '.wsf', '.ps1', '.msi', '.reg', '.iso', '.img',
            '.docm', '.xlsm', '.pptm', '.dotm'
        ]
        
        self.double_extensions = ['.pdf.exe', '.doc.exe', '.jpg.exe', '.txt.exe', '.pdf.scr']
        
        # Lookalike domain patterns
        self.lookalike_patterns = {
            'paypal': ['paypa1', 'paypai', 'paypal-', 'paypall', 'paypaI'],
            'amazon': ['amaz0n', 'amazom', 'amzon', 'amazn', 'amaz0n'],
            'apple': ['appie', 'appIe', 'app1e', 'appIe'],
            'microsoft': ['micr0soft', 'micros0ft', 'mlcrosoft', 'mlcrosoft'],
            'google': ['go0gle', 'g00gle', 'googIe', 'googie', 'g00gle'],
            'facebook': ['faceb00k', 'facebo0k', 'faceb00k', 'faceb0ok'],
            'netflix': ['netfl1x', 'netflx', 'nctflix', 'netflx']
        }
        
        # Urgency words
        self.urgency_words = [
            'immediately', 'urgent', 'within 24 hours', 'as soon as possible',
            'expires today', 'limited time', 'act now', 'don\'t wait',
            'immediate action', 'deadline', 'expiring soon', 'right away',
            'your account will be closed', 'suspended permanently', 'verify now'
        ]
        
        # Financial keywords
        self.financial_keywords = [
            'credit card', 'bank account', 'payment', 'invoice', 'bill',
            'refund', 'transaction', 'purchase', 'order confirmation',
            'subscription', 'billing', 'paypal', 'wire transfer', 'ssn',
            'social security', 'password', 'login', 'verify your account'
        ]
        
        # Disposable email domains
        self.disposable_domains = [
            'tempmail.com', 'guerrillamail.com', 'mailinator.com',
            '10minutemail.com', 'throwaway.com', 'temp-mail.org',
            'spamgourmet.com', 'trashmail.com', 'fakeinbox.com'
        ]
        
        # Legitimate domains (WHITELIST) - Expanded
        self.legitimate_domains = [
            # Email providers
            'gmail.com', 'outlook.com', 'yahoo.com', 'icloud.com', 'aol.com', 'protonmail.com',
            'hotmail.com', 'mail.com', 'yandex.com', 'zoho.com',
            
            # Tech companies
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'meta.com', 'facebook.com',
            'twitter.com', 'linkedin.com', 'instagram.com', 'github.com', 'stackoverflow.com',
            'netflix.com', 'spotify.com', 'hulu.com', 'disneyplus.com', 'zoom.us', 'slack.com',
            
            # Google domains
            'googleusercontent.com', 'googleapis.com', 'fonts.googleapis.com', 'gstatic.com',
            'ggpht.com', 'youtube.com', 'ytimg.com', 'c.gle', 'goo.gl', 'g.co',
            'blogger.com', 'blogspot.com', 'android.com', 'chrome.com', 'nest.com',
            
            # Banks
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
            'capitalone.com', 'usbank.com', 'td.com', 'amex.com', 'paypal.com',
            'discover.com', 'suntrust.com', 'pnc.com', 'ally.com', 'sofi.com',
            
            # Shopping
            'walmart.com', 'target.com', 'bestbuy.com', 'homedepot.com', 'lowes.com',
            'costco.com', 'ebay.com', 'etsy.com', 'shopify.com', 'aliexpress.com',
            'wish.com', 'newegg.com', 'gamestop.com', 'nordstrom.com', 'macys.com',
            
            # Social media
            'tiktok.com', 'snapchat.com', 'pinterest.com', 'reddit.com', 'tumblr.com',
            'whatsapp.com', 'telegram.org', 'signal.org', 'discord.com', 'twitch.tv',
            
            # CDN and tracking (common in emails)
            'cloudfront.net', 'akamai.net', 'fastly.net', 'cloudflare.com',
            'doubleclick.net', 'googleadservices.com', 'googlesyndication.com',
            
            # Delivery services
            'fedex.com', 'ups.com', 'dhl.com', 'usps.com', 'amazon.com',
            
            # Pakistani domains (for your region)
            'foodpanda.pk', 'foodpanda.com', 'deliveryhero.io', 'deliveryhero.com',
            'abmail.info.foodpanda.pk', 'ablink.info.foodpanda.pk',
            'emailinboundprocessing.com', '01.emailinboundprocessing.com',
            'images.deliveryhero.io', 'sadiq.ai', 'sadiq.com', 'sadiq.pk',
            'daraz.pk', 'daraz.com', 'olx.com.pk', 'pakwheels.com'
        ]
        
        # Brands commonly impersonated
        self.brand_names = [
            'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix', 
            'bank of america', 'chase', 'wells fargo', 'citibank', 
            'facebook', 'instagram', 'linkedin', 'twitter', 'fedex', 'ups', 'dhl'
        ]
        
        self.brand_domains = {
            'paypal': 'paypal.com',
            'amazon': 'amazon.com',
            'apple': 'apple.com',
            'microsoft': 'microsoft.com',
            'google': 'google.com',
            'netflix': 'netflix.com',
            'facebook': 'facebook.com',
            'linkedin': 'linkedin.com',
            'instagram': 'instagram.com',
            'twitter': 'twitter.com',
            'fedex': 'fedex.com',
            'ups': 'ups.com',
            'dhl': 'dhl.com',
            'chase': 'chase.com',
            'bank of america': 'bankofamerica.com'
        }
        
        # Domains to skip WHOIS checks (CDNs, tracking, etc.)
        self.skip_whois_domains = [
            'googleusercontent.com', 'googleapis.com', 'gstatic.com', 'ggpht.com',
            'cloudfront.net', 'akamai.net', 'fastly.net', 'cloudflare.com',
            'doubleclick.net', 'googlesyndication.com', 'facebook.com',
            'cdninstagram.com', 'twimg.com', 'github.io', 'blogspot.com'
        ]
    
    def is_legitimate_domain(self, domain):
        """Check if domain is in whitelist - FAST CHECK"""
        domain_lower = domain.lower()
        
        # Direct match
        if domain_lower in self.legitimate_domains:
            return True
        
        # Check if domain ends with any legitimate domain
        for legit in self.legitimate_domains:
            if domain_lower.endswith(legit) or legit in domain_lower:
                return True
        return False
    
    def should_skip_whois(self, domain):
        """Determine if we should skip WHOIS for this domain (performance)"""
        domain_lower = domain.lower()
        
        # Skip if legitimate
        if self.is_legitimate_domain(domain_lower):
            return True
        
        # Skip known CDNs and tracking domains
        for skip in self.skip_whois_domains:
            if skip in domain_lower:
                return True
        
        # Only check common TLDs
        common_tlds = ['.com', '.net', '.org', '.io', '.co', '.us', '.uk']
        if not any(domain_lower.endswith(tld) for tld in common_tlds):
            return True
        
        # Skip very short domains (likely internal/redirects)
        if len(domain_lower.split('.')[0]) < 4:
            return True
        
        return False
    
    def unshorten_url(self, url):
        """Follow redirects with caching - FAST"""
        if url in self.url_cache:
            return self.url_cache[url]
        
        # Skip if legitimate domain
        if self.is_legitimate_domain(url):
            self.url_cache[url] = url
            return url
        
        try:
            # Quick HEAD request with timeout
            response = requests.head(url, allow_redirects=True, timeout=3)
            final_url = response.url
            self.url_cache[url] = final_url
            return final_url
        except:
            self.url_cache[url] = url
            return url
    
    def check_link_mismatch(self, html_content):
        """Detect mismatched display URLs vs actual links - FAST"""
        threats = []
        if not html_content:
            return threats
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            count = 0
            for link in soup.find_all('a', href=True):
                if count > 20:  # Limit checking to first 20 links for performance
                    break
                    
                display_text = link.get_text(strip=True)
                actual_url = link['href']
                
                if not display_text or not actual_url or len(display_text) < 5:
                    continue
                
                # Extract domains
                try:
                    actual_domain = urlparse(actual_url).netloc.lower()
                    if actual_domain.startswith('www.'):
                        actual_domain = actual_domain[4:]
                except:
                    continue
                
                # Check if display text contains a domain
                domain_in_text = re.search(r'(?:https?://)?(?:www\.)?([a-z0-9][a-z0-9.-]+\.[a-z]{2,})', display_text.lower())
                
                if domain_in_text:
                    text_domain = domain_in_text.group(1)
                    if text_domain != actual_domain and text_domain not in actual_domain:
                        if not self.is_legitimate_domain(actual_url):
                            threats.append(f"⚠️ LINK MISMATCH: '{text_domain}' links to '{actual_domain}'")
                            count += 1
                count += 1
        except:
            pass
        
        return threats
    
    def check_domain_age(self, url):
        """Check domain age with smart caching and timeout - OPTIMIZED"""
        threats = []
        
        # Parse domain
        try:
            domain = urlparse(url).netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            if not domain:
                return threats
        except:
            return threats
        
        # Check cache
        if domain in self.domain_cache:
            return self.domain_cache[domain]
        
        # Skip WHOIS for certain domains (performance)
        if self.should_skip_whois(domain):
            self.domain_cache[domain] = []
            return []
        
        # Quick WHOIS check with timeout
        try:
            import whois
            import socket
            socket.setdefaulttimeout(self.whois_timeout)
            
            w = whois.whois(domain)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                age_days = (datetime.now() - creation_date).days
                if age_days < 7 and age_days > 0:
                    threats.append(f"⚠️ BRAND NEW domain ({age_days} days old): {domain}")
                elif age_days < 30 and age_days > 0:
                    threats.append(f"⚠️ New domain ({age_days} days old): {domain}")
        except ImportError:
            # whois not installed - skip silently
            pass
        except:
            # Timeout or error - assume nothing
            pass
        
        self.domain_cache[domain] = threats
        return threats
    
    def check_spf_dkim_dmarc(self, headers):
        """Check SPF, DKIM, DMARC authentication results"""
        threats = []
        auth_results = headers.get("Authentication-Results", "")
        if auth_results:
            if "spf=fail" in auth_results.lower() or "spf=neutral" in auth_results.lower():
                threats.append("⚠️ SPF authentication FAILED - email likely spoofed")
            if "dkim=fail" in auth_results.lower():
                threats.append("⚠️ DKIM authentication FAILED - email may be tampered")
            if "dmarc=fail" in auth_results.lower():
                threats.append("⚠️ DMARC authentication FAILED - domain policy violation")
        else:
            threats.append("⚠️ No authentication results found - email not validated")
        
        return threats
    
    def extract_ip_addresses(self, headers):
        """Extract IP addresses from Received headers"""
        ips = []
        received_headers = headers.get("Received", "")
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        found_ips = re.findall(ip_pattern, received_headers)
        
        for ip in found_ips:
            if not ip.startswith('10.') and not ip.startswith('192.168.') and not ip.startswith('127.'):
                if ip not in ips:
                    ips.append(ip)
        return ips[:3]  # Limit to first 3 IPs
    
    def check_reply_to_mismatch(self, headers):
        """Check for Reply-To mismatch"""
        from_addr = headers.get("From", "")
        reply_to = headers.get("Reply-To", "")
        
        if reply_to and from_addr:
            from_domain = re.search(r'@([^\s>]+)', from_addr)
            reply_domain = re.search(r'@([^\s>]+)', reply_to)
            
            if from_domain and reply_domain and from_domain.group(1) != reply_domain.group(1):
                if not self.is_legitimate_domain(reply_domain.group(1)):
                    return f"⚠️ Reply-To mismatch: replies go to {reply_domain.group(1)} not {from_domain.group(1)}"
        return None
    
    def check_sender_reputation(self, headers):
        """Check sender domain reputation"""
        threats = []
        from_addr = headers.get("From", "")
        
        domain_match = re.search(r'@([^\s>]+)', from_addr)
        if domain_match:
            domain = domain_match.group(1)
            
            if domain in self.disposable_domains:
                threats.append(f"⚠️ Disposable email domain used: {domain}")
            
            for brand, legit_domain in self.brand_domains.items():
                if brand in domain.lower() and legit_domain != domain:
                    if not domain.endswith(legit_domain):
                        threats.append(f"⚠️ Domain spoofing: {domain} pretending to be {legit_domain}")
        
        return threats
    
    def check_lookalike_domain(self, url):
        """Detect lookalike/typosquatting domains - FAST"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            if self.is_legitimate_domain(domain):
                return None
            
            # Check lookalike patterns
            for brand, variations in self.lookalike_patterns.items():
                for variant in variations:
                    if variant in domain:
                        return f"⚠️ Lookalike domain: '{domain}' resembles '{brand}'"
            
            # Quick check for suspicious characters
            suspicious_chars = ['0', '1', 'l', 'I', 'O', 'rn', 'rr']
            for char in suspicious_chars:
                if char in domain:
                    # Skip if it's a known tracking domain
                    tracking_patterns = ['inbound', 'tracking', 'email', 'mailer', 'newsletter']
                    if not any(pattern in domain for pattern in tracking_patterns):
                        return f"⚠️ Suspicious characters in domain: '{domain}'"
        except:
            pass
        return None
    
    # ============================================================
    # FIXED: calculate_risk_score - IMPROVED WEIGHTS
    # ============================================================
    def calculate_risk_score(self, threats, headers, urls, attachments):
        """Calculate weighted risk score - FIXED VERSION"""
        risk_score = 0
        
        # ============================================================
        # AUTHENTICATION ISSUES (High weight - very suspicious)
        # ============================================================
        if any("No authentication results" in t for t in threats):
            risk_score += 25  # ← ADDED THIS!
        if any("SPF" in t or "DKIM" in t or "DMARC" in t for t in threats):
            risk_score += 25
        if any("authentication FAILED" in t for t in threats):
            risk_score += 30
        
        # ============================================================
        # SPOOFING & IMPERSONATION (High weight)
        # ============================================================
        if any("Fake sender" in t for t in threats):
            risk_score += 25  # ← INCREASED from 20
        if any("impersonating" in t.lower() for t in threats):
            risk_score += 30  # ← ADDED THIS!
        if any("Domain spoofing" in t for t in threats):
            risk_score += 25  # ← ADDED THIS!
        if any("Lookalike" in t for t in threats):
            risk_score += 20
        if any("Reply-To mismatch" in t for t in threats):
            risk_score += 25  # ← INCREASED from 20
        
        # ============================================================
        # URL & LINK ISSUES (High weight)
        # ============================================================
        if any("LINK MISMATCH" in t for t in threats):
            risk_score += 30
        if any("Login page on suspicious domain" in t for t in threats):
            risk_score += 25  # ← INCREASED from 15
        if any("URL shortener" in t for t in threats):
            risk_score += 15
        
        # ============================================================
        # DOMAIN AGE ISSUES (Medium weight)
        # ============================================================
        if any("BRAND NEW domain" in t for t in threats):
            risk_score += 35
        if any("New domain" in t for t in threats):
            risk_score += 25
        
        # ============================================================
        # CONTENT ISSUES (Medium weight)
        # ============================================================
        if any("Phishing keyword" in t for t in threats):
            risk_score += 20  # ← INCREASED from 15
        if any("Urgency tactics" in t for t in threats):
            risk_score += 20  # ← ADDED THIS!
        if any("Financial information requested" in t for t in threats):
            risk_score += 20  # ← ADDED THIS!
        if any("suspicious attachment" in t.lower() for t in threats):
            risk_score += 30
        if any("Disposable email" in t for t in threats):
            risk_score += 15
        
        # ============================================================
        # BONUS: Multiple threat types = higher score
        # ============================================================
        threat_count = len(threats)
        if threat_count >= 5:
            risk_score += 15  # Many threats = very suspicious
        elif threat_count >= 3:
            risk_score += 10  # Multiple threats = suspicious
        
        # Cap at 100
        risk_score = min(risk_score, 100)
        confidence = 100 - risk_score
        
        # Determine risk level
        if risk_score > 60:
            risk_level = "HIGH"
        elif risk_score > 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            'risk_score': risk_score,
            'confidence': confidence,
            'risk_level': risk_level
        }
    
    # ============================================================
    # FIXED: detect_all_threats - Added missing detections
    # ============================================================
    def detect_all_threats(self, email_content, headers, urls, raw_email=None):
        threats = []
        informational = []
        
        if not email_content:
            return threats, informational
        
        body = email_content.get("body", "").lower()
        html_body = email_content.get("raw_body", "")
        
        # ========== HEADER ANALYSIS ==========
        threats.extend(self.check_spf_dkim_dmarc(headers))
        threats.extend(self.check_sender_reputation(headers))
        
        ips = self.extract_ip_addresses(headers)
        if ips:
            informational.append(f"ℹ️ Sender IPs: {', '.join(ips)}")
        
        reply_to_threat = self.check_reply_to_mismatch(headers)
        if reply_to_threat:
            threats.append(reply_to_threat)
        
        # ========== BRAND IMPERSONATION IN SUBJECT (NEW) ==========
        subject = headers.get("Subject", "").lower()
        from_header = headers.get("From", "")
        
        if from_header:
            display_match = re.search(r'^(.+?)\s*<(.+?)>', from_header)
            if display_match:
                display_name = display_match.group(1).lower()
                email_addr = display_match.group(2).lower()
                
                for brand in self.brand_names:
                    if brand in display_name:
                        expected_domain = self.brand_domains.get(brand, '')
                        if expected_domain and expected_domain not in email_addr:
                            if not self.is_legitimate_domain(email_addr):
                                threats.append(f"⚠️ IMPERSONATION: '{display_name}' pretending to be {brand}")
                                break
        
        # Check brand names in subject
        for brand in self.brand_names:
            if brand in subject:
                # Check if email actually came from that brand
                from_domain_match = re.search(r'@([^\s>]+)', headers.get("From", ""))
                if from_domain_match:
                    domain = from_domain_match.group(1).lower()
                    expected_domain = self.brand_domains.get(brand, '')
                    if expected_domain and expected_domain not in domain:
                        if not self.is_legitimate_domain(domain):
                            threats.append(f"⚠️ Brand name '{brand}' in subject but domain is {domain}")
                            break
        
        # ========== URL ANALYSIS ==========
        all_urls = list(urls) if urls else []
        
        # Check link mismatches (limit to first 30 URLs)
        threats.extend(self.check_link_mismatch(html_body))
        
        # Analyze each URL
        urls_analyzed = 0
        for url in all_urls:
            if urls_analyzed > 30:
                informational.append(f"ℹ️ Skipped {len(all_urls) - 30} additional URLs for performance")
                break
            
            # Check domain age (cached, fast)
            threats.extend(self.check_domain_age(url))
            
            # Check lookalike domains (fast)
            lookalike = self.check_lookalike_domain(url)
            if lookalike:
                threats.append(lookalike)
            
            # Check URL shorteners
            if not self.is_legitimate_domain(url):
                short_domains = ['bit.ly', 'tinyurl.com', 'short.url', 'rb.gy', 'ow.ly', 'buff.ly']
                if any(domain in url.lower() for domain in short_domains):
                    threats.append(f"⚠️ Suspicious URL shortener: {url}")
                
                # Check for login/verify pages
                if ('login' in url.lower() or 'verify' in url.lower() or 'secure' in url.lower()):
                    threats.append(f"⚠️ Login page on suspicious domain")
            
            urls_analyzed += 1
        
        # ========== PHISHING KEYWORDS (EXPANDED) ==========
        phishing_keywords = [
            # Account-related
            "verify your account", "confirm your identity", "account suspended",
            "account locked", "account limited", "account compromised",
            "unusual activity", "suspicious activity", "unauthorized access",
            "fraud alert", "security alert", "security breach",
            
            # Urgency
            "urgent action required", "immediate action", "within 24 hours",
            "immediately", "as soon as possible", "act now", "don't wait",
            "limited time", "expires today", "expiring soon", "deadline",
            "your account will be closed", "suspended permanently",
            
            # Action
            "click here", "click the link", "update your payment",
            "verify immediately", "update your information", "confirm your account",
            "restore your account", "reactivate your account",
            
            # Financial
            "credit card", "bank account", "payment method", "billing information",
            "refund", "transaction", "purchase", "invoice", "bill",
            "order confirmation", "subscription", "wire transfer",
            
            # Personal
            "ssn", "social security", "password", "login credentials",
            "personal information", "identity verification"
        ]
        
        # Check for each phishing keyword
        keyword_found = False
        for keyword in phishing_keywords:
            if keyword in body:
                threats.append(f"⚠️ Phishing keyword: '{keyword}'")
                keyword_found = True
                break  # Only add one phishing keyword threat
        
        # ========== FAKE SENDER DETECTION (IMPROVED) ==========
        if from_header:
            display_match = re.search(r'^(.+?)\s*<(.+?)>', from_header)
            if display_match:
                display_name = display_match.group(1).lower()
                email_addr = display_match.group(2).lower()
                
                for brand in self.brand_names:
                    if brand.lower() in display_name:
                        expected_domain = self.brand_domains.get(brand.lower(), '')
                        if expected_domain and expected_domain not in email_addr:
                            if not self.is_legitimate_domain(email_addr):
                                threats.append(f"⚠️ Fake sender: '{display_name}' impersonating {brand}")
                                break
        
        # ========== URGENCY TACTICS ==========
        urgency_found = [w for w in self.urgency_words if w in body]
        if len(urgency_found) >= 2:
            threats.append(f"⚠️ Urgency tactics detected")
            informational.append(f"ℹ️ Urgency words found: {', '.join(urgency_found[:5])}")
        
        # ========== FINANCIAL REQUESTS ==========
        financial_found = [k for k in self.financial_keywords if k in body]
        if len(financial_found) >= 2:
            threats.append(f"⚠️ Financial information requested")
            informational.append(f"ℹ️ Financial keywords found: {', '.join(financial_found[:5])}")
        
        # ========== ATTACHMENT ANALYSIS ==========
        if hasattr(self, 'attachments') and self.attachments:
            for att in self.attachments[:5]:
                att_name = att.get('name', '') if isinstance(att, dict) else str(att)
                att_lower = att_name.lower()
                
                for ext in self.suspicious_extensions:
                    if att_lower.endswith(ext):
                        threats.append(f"⚠️ Suspicious attachment: {att_name}")
                        break
                
                if isinstance(att, dict):
                    for pattern in self.double_extensions:
                        if att_lower.endswith(pattern):
                            threats.append(f"⚠️ Double extension: {att_name}")
                            break
        
        # Remove duplicates
        threats = list(dict.fromkeys(threats))
        informational = list(dict.fromkeys(informational))
        
        # ========== CALCULATE RISK SCORE ==========
        risk = self.calculate_risk_score(threats, headers, all_urls, 
                                         getattr(self, 'attachments', []))
        
        # Add risk score to informational
        informational.append(f"ℹ️ Risk Score: {risk['risk_score']}/100 ({risk['risk_level']} risk)")
        
        # Add summary
        if len(threats) == 0:
            informational.append("✅ No threats detected - email appears legitimate")
        else:
            informational.append(f"⚠️ {len(threats)} threats detected")
        
        return threats, informational
    
    def scan_urls(self, urls):
        """Standalone URL scanner - FAST VERSION"""
        results = []
        
        for i, url in enumerate(urls[:30]):  # Max 30 URLs
            # Check if legitimate
            if self.is_legitimate_domain(url):
                results.append(f"✅ Safe: {url}")
                continue
            
            # Check lookalike
            lookalike = self.check_lookalike_domain(url)
            if lookalike:
                results.append(lookalike)
                continue
            
            # Check domain age
            age_threats = self.check_domain_age(url)
            if age_threats:
                results.append(age_threats[0])
                continue
            
            # Check for login pages
            if 'login' in url.lower() or 'verify' in url.lower():
                results.append(f"⚠️ CAUTION: {url} (Login page)")
            else:
                results.append(f"⚠️ Suspicious: {url}")
            
            if i < len(urls) - 1 and i % 5 == 0:  # Rate limit
                time.sleep(0.3)
        
        if len(urls) > 30:
            results.append(f"ℹ️ Skipped {len(urls) - 30} additional URLs (limit for performance)")
        
        return results