import re
from datetime import datetime
from email.utils import parsedate_to_datetime
import customtkinter as ctk

class HeaderAnalyzer:
    """Advanced header analysis for email forensics"""
    
    def __init__(self):
        # Suspicious header patterns
        self.suspicious_from_patterns = [
            r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\s*<[^>]+@[^>]+>',  # Mismatched From
            r'=\?[^?]+\?[BQ]\?[^?]+\?=',  # Encoded headers (could hide spoofing)
        ]
        
        # Known legitimate sending services (not necessarily the domain owner)
        self.bulk_email_services = [
            'sendgrid.net', 'mailgun.org', 'sparkpostmail.com', 'ses.amazonaws.com',
            'mailjet.com', 'postmarkapp.com', 'sendinblue.com', 'constantcontact.com',
            'mailchimp.app', 'emailsrvr.com', 'emailmailer.net'
        ]
        
        # Return-Path vs From mismatch patterns (common in legitimate marketing emails)
        self.common_marketing_domains = [
            'bounce', 'mailer', 'newsletter', 'marketing', 'notification',
            'noreply', 'donotreply', 'no-reply'
        ]
    
    def analyze_headers(self, headers):
        """
        Comprehensive header analysis
        Returns: (threats, warnings, info, header_structure)
        """
        threats = []
        warnings = []
        info = []
        
        # 1. Extract all important headers
        from_header = headers.get('From', '')
        to_header = headers.get('To', '')
        reply_to = headers.get('Reply-To', '')
        return_path = headers.get('Return-Path', '')
        subject = headers.get('Subject', '')
        date = headers.get('Date', '')
        message_id = headers.get('Message-ID', '')
        received_spf = headers.get('Received-SPF', '')
        authentication_results = headers.get('Authentication-Results', '')
        dkim_signature = headers.get('DKIM-Signature', '')
        
        # 2. Parse From header
        from_info = self._parse_from_header(from_header)
        info.append(f"ℹ️ Sender: {from_info['display_name']} <{from_info['email']}>")
        
        # 3. Check for missing critical headers
        missing = []
        if not from_header:
            missing.append("From")
        if not date:
            missing.append("Date")
        if not message_id:
            missing.append("Message-ID")
        
        if missing:
            warnings.append(f"⚠️ Missing critical headers: {', '.join(missing)}")
        
        # 4. SPF Analysis (improved)
        spf_threats, spf_info = self._analyze_spf(authentication_results, received_spf)
        threats.extend(spf_threats)
        info.extend(spf_info)
        
        # 5. DKIM Analysis (improved)
        dkim_threats, dkim_info = self._analyze_dkim(authentication_results, dkim_signature)
        threats.extend(dkim_threats)
        info.extend(dkim_info)
        
        # 6. DMARC Analysis
        dmarc_threats, dmarc_info = self._analyze_dmarc(authentication_results)
        threats.extend(dmarc_threats)
        info.extend(dmarc_info)
        
        # 7. Reply-To vs From mismatch (with better detection)
        reply_to_threat = self._analyze_reply_to(from_info, reply_to, return_path)
        if reply_to_threat:
            threats.append(reply_to_threat)
        
        # 8. Return-Path analysis
        return_path_threat = self._analyze_return_path(from_info, return_path)
        if return_path_threat:
            warnings.append(return_path_threat)
        
        # 9. Received headers chain analysis
        received_headers = self._extract_received_headers(headers)
        received_threats, received_info = self._analyze_received_chain(received_headers)
        threats.extend(received_threats)
        info.extend(received_info)
        
        # 10. Date analysis
        date_threat, date_info = self._analyze_date(date)
        if date_threat:
            threats.append(date_threat)
        if date_info:
            info.append(date_info)
        
        # 11. SPOOFING DETECTION (Enhanced)
        spoofing_threats = self._detect_spoofing(headers, from_info)
        threats.extend(spoofing_threats)
        
        # 12. Calculate header trust score
        trust_score = self._calculate_header_trust_score(threats, warnings, headers)
        info.append(f"ℹ️ Header Trust Score: {trust_score}/100")
        
        # 13. Header structure for UI
        header_structure = self._build_header_structure(headers)
        
        return threats, warnings, info, header_structure
    
    def _parse_from_header(self, from_header):
        """Parse From header into display name and email"""
        result = {'display_name': 'Unknown', 'email': 'Unknown', 'domain': ''}
        
        if not from_header:
            return result
        
        # Pattern 1: "Name" <email@domain.com>
        pattern1 = re.search(r'"?([^"<]+)"?\s*<([^>]+)>', from_header)
        if pattern1:
            result['display_name'] = pattern1.group(1).strip()
            result['email'] = pattern1.group(2).strip()
        else:
            # Pattern 2: Just email@domain.com
            pattern2 = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', from_header)
            if pattern2:
                result['email'] = pattern2.group(1)
                result['display_name'] = result['email'].split('@')[0]
        
        # Extract domain
        if '@' in result['email']:
            result['domain'] = result['email'].split('@')[1].lower()
        
        return result
    
    def _analyze_spf(self, auth_results, received_spf):
        """Enhanced SPF analysis"""
        threats = []
        info = []
        
        combined = f"{auth_results} {received_spf}".lower()
        
        # Check SPF results
        if 'spf=fail' in combined or 'spf=fail' in received_spf.lower():
            threats.append("⚠️ SPF FAILED - Sender not authorized by domain owner (high confidence)")
        elif 'spf=softfail' in combined:
            threats.append("⚠️ SPF SOFTFAIL - Domain not sure if sender is authorized")
        elif 'spf=neutral' in combined:
            warnings = "⚠️ SPF NEUTRAL - Domain owner hasn't published SPF policy"
            threats.append(warnings)
        elif 'spf=pass' in combined or 'spf=pass' in received_spf.lower():
            info.append("✅ SPF PASS - Server authorized by domain owner")
        elif 'spf=none' in combined:
            info.append("ℹ️ SPF NONE - No SPF record found (not necessarily malicious)")
        elif not combined or ('spf' not in combined):
            info.append("ℹ️ No SPF authentication data available")
        
        return threats, info
    
    def _analyze_dkim(self, auth_results, dkim_signature):
        """Enhanced DKIM analysis"""
        threats = []
        info = []
        
        combined = auth_results.lower()
        
        if 'dkim=fail' in combined:
            threats.append("⚠️ DKIM FAILED - Email signature invalid (may be tampered)")
        elif 'dkim=neutral' in combined:
            threats.append("⚠️ DKIM NEUTRAL - Domain owner hasn't published DKIM policy")
        elif 'dkim=pass' in combined:
            info.append("✅ DKIM PASS - Email signature verified")
        elif 'dkim=none' in combined:
            info.append("ℹ️ No DKIM signature found")
        elif dkim_signature:
            info.append("ℹ️ DKIM signature present but not validated")
        else:
            info.append("ℹ️ No DKIM signature in email")
        
        return threats, info
    
    def _analyze_dmarc(self, auth_results):
        """Enhanced DMARC analysis"""
        threats = []
        info = []
        
        combined = auth_results.lower()
        
        if 'dmarc=fail' in combined:
            threats.append("⚠️ DMARC FAILED - Domain policy violation (high confidence spoofing)")
        elif 'dmarc=pass' in combined:
            info.append("✅ DMARC PASS - Domain policy satisfied")
        elif 'dmarc=none' in combined:
            info.append("ℹ️ No DMARC policy published")
        elif not combined:
            info.append("ℹ️ No DMARC authentication data available")
        
        return threats, info
    
    def _analyze_reply_to(self, from_info, reply_to, return_path):
        """Analyze Reply-To header for mismatches"""
        if not reply_to or reply_to == 'None' or not from_info['email']:
            return None
        
        # Extract domain from reply-to
        reply_match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', reply_to)
        if not reply_match:
            return None
        
        reply_domain = reply_match.group(1).lower()
        from_domain = from_info['domain'].lower()
        
        # Check if domains match
        if reply_domain != from_domain:
            # Check if it's a legitimate marketing/notification domain
            is_marketing = any(service in reply_domain for service in self.bulk_email_services)
            is_common = any(word in reply_domain for word in self.common_marketing_domains)
            
            if is_marketing or is_common:
                return f"⚠️ Reply-To mismatch: {reply_domain} (likely legitimate marketing service)"
            else:
                return f"⚠️⚠️ CRITICAL: Reply-To goes to {reply_domain} not {from_domain} - Potential spoofing!"
        
        return None
    
    def _analyze_return_path(self, from_info, return_path):
        """Analyze Return-Path header"""
        if not return_path or return_path == 'None' or not from_info['email']:
            return None
        
        return_match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', return_path)
        if not return_match:
            return None
        
        return_domain = return_match.group(1).lower()
        from_domain = from_info['domain'].lower()
        
        if return_domain != from_domain:
            # Check for common bounce handling services
            is_bounce_service = any(service in return_domain for service in self.bulk_email_services)
            if is_bounce_service:
                return f"ℹ️ Return-Path uses {return_domain} (bounce handling service) - Normal for bulk email"
            else:
                return f"⚠️ Return-Path mismatch: {return_domain} vs {from_domain}"
        
        return None
    
    def _extract_received_headers(self, headers):
        """Extract and parse all Received headers"""
        received_list = []
        
        # Received headers can appear multiple times
        for key, value in headers.items():
            if key.lower() == 'received':
                received_list.append(value)
        
        return received_list
    
    def _analyze_received_chain(self, received_headers):
        """Analyze the chain of Received headers"""
        threats = []
        info = []
        
        if not received_headers:
            info.append("ℹ️ No Received headers found")
            return threats, info
        
        info.append(f"ℹ️ Found {len(received_headers)} Received headers")
        
        # Track IPs and servers in the chain
        ips_found = []
        servers = []
        
        for i, received in enumerate(received_headers[:5]):  # Limit to first 5
            # Extract IP addresses
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, received)
            
            # Extract servers/hostnames
            from_pattern = r'from\s+([a-zA-Z0-9.-]+)'
            servers_in_header = re.findall(from_pattern, received, re.IGNORECASE)
            
            for ip in ips:
                if ip not in ips_found and not ip.startswith('127.'):
                    ips_found.append(ip)
            
            for server in servers_in_header:
                if server not in servers:
                    servers.append(server)
        
        # Report findings
        if ips_found:
            info.append(f"ℹ️ Sender IPs in chain: {', '.join(ips_found[:3])}")
        
        # Check for suspicious patterns in received chain
        for received in received_headers:
            if 'with HTTP' in received and 'with SMTP' not in received:
                threats.append("⚠️ Web-based email detected - More likely to be spoofed")
                break
        
        return threats, info
    
    def _analyze_date(self, date_header):
        """Analyze date header for anomalies"""
        threats = []
        info = []
        
        if not date_header:
            return "⚠️ No Date header in email (unusual for legitimate emails)", None
        
        try:
            email_date = parsedate_to_datetime(date_header)
            now = datetime.now(email_date.tzinfo)
            
            # Check if date is in the future
            if email_date > now:
                threats.append(f"⚠️ Future date detected: {email_date.strftime('%Y-%m-%d %H:%M')}")
            
            # Check if date is very old (over 30 days)
            days_old = (now - email_date).days
            if days_old > 30:
                info.append(f"ℹ️ Email is {days_old} days old")
            elif days_old < 0:
                pass  # Already handled future date
                
        except Exception:
            info.append("ℹ️ Unable to parse date format")
        
        return threats[0] if threats else None, info[0] if info else None
    
    def _detect_spoofing(self, headers, from_info):
        """Enhanced spoofing detection"""
        threats = []
        
        # Get display name from From header
        from_header = headers.get('From', '')
        
        # Check for display name spoofing (e.g., "PayPal Support" <random@domain.com>)
        if from_info['display_name'] != 'Unknown':
            display_lower = from_info['display_name'].lower()
            
            # Known brands being spoofed
            brands = {
                'paypal': ['paypal', 'pay pal'],
                'amazon': ['amazon', 'amz'],
                'apple': ['apple', 'app store'],
                'microsoft': ['microsoft', 'ms', 'outlook', 'hotmail'],
                'google': ['google', 'gmail', 'drive', 'youtube'],
                'netflix': ['netflix'],
                'facebook': ['facebook', 'fb', 'meta'],
                'linkedin': ['linkedin'],
                'bank': ['chase', 'bank of america', 'wells fargo', 'citibank', 'capital one'],
                'fedex': ['fedex'],
                'ups': ['ups'],
                'dhl': ['dhl'],
                'spotify': ['spotify'],
                'disney': ['disney', 'disney+']
            }
            
            # Extract domain from email
            email_domain = from_info['domain']
            
            # Check each brand
            for brand, keywords in brands.items():
                for keyword in keywords:
                    if keyword in display_lower:
                        # Verify if domain actually belongs to brand
                        is_legitimate = self._is_legitimate_brand_domain(email_domain, brand)
                        
                        if not is_legitimate:
                            threats.append(f"⚠️⚠️ SPOOFING DETECTED: '{from_info['display_name']}' impersonating {brand.title()} but email is from {email_domain}")
                            break
                        else:
                            # Legitimate brand email
                            pass
                        break
        
        # Check for suspicious characters in email address
        email_addr = from_info['email']
        if email_addr != 'Unknown':
            # Look for lookalike characters
            suspicious_chars = {
                'rn': 'm',  # rn looks like m
                'vv': 'w',  # vv looks like w
                '0': 'o',   # zero instead of o
                '1': 'l',   # one instead of l
                '5': 's',   # five instead of s
                '8': 'b',   # eight instead of b
            }
            
            for suspicious, legitimate in suspicious_chars.items():
                if suspicious in email_addr.lower():
                    threats.append(f"⚠️ Suspicious character '{suspicious}' in email address (could be '{legitimate}' spoofing)")
                    break
        
        return threats
    
    def _is_legitimate_brand_domain(self, domain, brand):
        """Check if domain belongs to the brand"""
        brand_domains = {
            'paypal': ['paypal.com', 'paypal.cn', 'paypal.co.uk', 'paypal.fr', 'paypal.de', 'paypal.es'],
            'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.in'],
            'apple': ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
            'microsoft': ['microsoft.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com'],
            'google': ['google.com', 'gmail.com', 'youtube.com', 'googlemail.com'],
            'netflix': ['netflix.com', 'netflix.net'],
            'facebook': ['facebook.com', 'fb.com', 'messenger.com', 'instagram.com'],
            'linkedin': ['linkedin.com'],
            'fedex': ['fedex.com'],
            'ups': ['ups.com'],
            'dhl': ['dhl.com', 'dhl.de'],
            'spotify': ['spotify.com'],
            'disney': ['disney.com', 'disneyplus.com']
        }
        
        if brand in brand_domains:
            for legit_domain in brand_domains[brand]:
                if domain.endswith(legit_domain) or legit_domain.endswith(domain):
                    return True
        
        return False
    
    def _calculate_header_trust_score(self, threats, warnings, headers):
        """Calculate trust score based on header analysis"""
        score = 100
        
        # Deduct for each type of issue
        for threat in threats:
            if 'SPF FAILED' in threat:
                score -= 25
            elif 'DKIM FAILED' in threat:
                score -= 20
            elif 'DMARC FAILED' in threat:
                score -= 30
            elif 'SPOOFING DETECTED' in threat:
                score -= 40
            elif 'CRITICAL' in threat:
                score -= 35
            elif 'mismatch' in threat.lower():
                score -= 15
        
        for warning in warnings:
            if 'Missing critical headers' in warning:
                score -= 15
        
        # Ensure score is within bounds
        return max(0, min(100, score))
    
    def _build_header_structure(self, headers):
        """Build organized header structure for display"""
        structure = {
            'authentication': {},
            'envelope': {},
            'content': {},
            'other': {}
        }
        
        for key, value in headers.items():
            key_lower = key.lower()
            
            if key_lower in ['authentication-results', 'received-spf', 'dkim-signature', 'dmarc']:
                structure['authentication'][key] = value
            elif key_lower in ['from', 'to', 'cc', 'bcc', 'reply-to', 'return-path', 'sender']:
                structure['envelope'][key] = value
            elif key_lower in ['subject', 'date', 'message-id', 'content-type', 'mime-version']:
                structure['content'][key] = value
            else:
                structure['other'][key] = value
        
        return structure


class HeaderDisplayUI:
    """Enhanced UI for displaying analyzed headers"""
    
    @staticmethod
    def create_analyzed_header_display(parent, colors, headers, analyzer_results):
        """Create a detailed header display with analysis"""
        
        threats, warnings, info, header_structure = analyzer_results
        
        # Main container
        container = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        
        # Summary Card
        summary_card = ctk.CTkFrame(container, fg_color=colors["card"], corner_radius=12)
        summary_card.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(summary_card, text="Header Analysis Summary", 
                    font=("Arial", 20, "bold"), text_color=colors["accent"]).pack(anchor="w", padx=20, pady=(15, 10))
        
        # Trust Score
        trust_score = 100 - (len(threats) * 10)
        trust_score = max(0, min(100, trust_score))
        score_color = colors["success"] if trust_score >= 80 else colors["warning"] if trust_score >= 50 else colors["danger"]
        
        score_frame = ctk.CTkFrame(summary_card, fg_color="transparent")
        score_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(score_frame, text="Header Trust Score:", font=("Arial", 16, "bold")).pack(side="left")
        ctk.CTkLabel(score_frame, text=f"{trust_score}%", font=("Arial", 24, "bold"), 
                    text_color=score_color).pack(side="left", padx=10)
        
        # Threats
        if threats:
            threat_card = ctk.CTkFrame(container, fg_color=colors["card"], corner_radius=12)
            threat_card.pack(fill="x", pady=(0, 15))
            
            ctk.CTkLabel(threat_card, text="⚠️ Threats Detected", 
                        font=("Arial", 18, "bold"), text_color=colors["danger"]).pack(anchor="w", padx=20, pady=(15, 10))
            
            for threat in threats:
                ctk.CTkLabel(threat_card, text=threat, font=("Arial", 13), 
                            text_color=colors["danger"], wraplength=800, justify="left").pack(anchor="w", padx=20, pady=5)
        
        # Info messages
        if info:
            info_card = ctk.CTkFrame(container, fg_color=colors["card"], corner_radius=12)
            info_card.pack(fill="x", pady=(0, 15))
            
            ctk.CTkLabel(info_card, text="ℹ️ Information", 
                        font=("Arial", 18, "bold"), text_color=colors["accent"]).pack(anchor="w", padx=20, pady=(15, 10))
            
            for msg in info[:10]:
                ctk.CTkLabel(info_card, text=msg, font=("Arial", 12), 
                            text_color=colors["muted"], wraplength=800, justify="left").pack(anchor="w", padx=20, pady=3)
        
        # Organized Headers
        headers_card = ctk.CTkFrame(container, fg_color=colors["card"], corner_radius=12)
        headers_card.pack(fill="both", expand=True)
        
        tabview = ctk.CTkTabview(headers_card, fg_color=colors["bg"])
        tabview.pack(fill="both", expand=True, padx=20, pady=20)
        
        tabs = ["Authentication", "Envelope", "Content", "All Headers"]
        for tab in tabs:
            tabview.add(tab)
        
        # Authentication Headers
        auth_frame = ctk.CTkScrollableFrame(tabview.tab("Authentication"), fg_color="transparent")
        auth_frame.pack(fill="both", expand=True)
        
        if header_structure['authentication']:
            for key, value in header_structure['authentication'].items():
                row = ctk.CTkFrame(auth_frame, fg_color="transparent")
                row.pack(fill="x", pady=5)
                ctk.CTkLabel(row, text=f"{key}:", font=("Arial", 12, "bold"), 
                            width=200, anchor="w").pack(side="left")
                ctk.CTkLabel(row, text=value, font=("Arial", 11), 
                            text_color=colors["muted"], wraplength=600, justify="left").pack(side="left", padx=10)
        else:
            ctk.CTkLabel(auth_frame, text="No authentication headers found", 
                        text_color=colors["warning"]).pack(pady=20)
        
        # Envelope Headers
        envelope_frame = ctk.CTkScrollableFrame(tabview.tab("Envelope"), fg_color="transparent")
        envelope_frame.pack(fill="both", expand=True)
        
        for key, value in header_structure['envelope'].items():
            row = ctk.CTkFrame(envelope_frame, fg_color="transparent")
            row.pack(fill="x", pady=5)
            ctk.CTkLabel(row, text=f"{key}:", font=("Arial", 12, "bold"), 
                        width=200, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value, font=("Arial", 11), 
                        text_color=colors["muted"], wraplength=600, justify="left").pack(side="left", padx=10)
        
        # Content Headers
        content_frame = ctk.CTkScrollableFrame(tabview.tab("Content"), fg_color="transparent")
        content_frame.pack(fill="both", expand=True)
        
        for key, value in header_structure['content'].items():
            row = ctk.CTkFrame(content_frame, fg_color="transparent")
            row.pack(fill="x", pady=5)
            ctk.CTkLabel(row, text=f"{key}:", font=("Arial", 12, "bold"), 
                        width=200, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value, font=("Arial", 11), 
                        text_color=colors["muted"], wraplength=600, justify="left").pack(side="left", padx=10)
        
        # All Headers
        all_frame = ctk.CTkScrollableFrame(tabview.tab("All Headers"), fg_color="transparent")
        all_frame.pack(fill="both", expand=True)
        
        for key, value in headers.items():
            row = ctk.CTkFrame(all_frame, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=f"{key}:", font=("Arial", 11, "bold"), 
                        width=200, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value[:200] + "..." if len(value) > 200 else value, 
                        font=("Arial", 10), text_color=colors["muted"], wraplength=600, justify="left").pack(side="left", padx=10)
        
        return container