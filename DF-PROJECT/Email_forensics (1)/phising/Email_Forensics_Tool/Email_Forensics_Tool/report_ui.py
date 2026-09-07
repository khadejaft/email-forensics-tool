
import customtkinter as ctk
from tkinter import messagebox
import os
import subprocess
import sys
from datetime import datetime

class ReportUI:
    def __init__(self, parent, colors, generate_callback, email_file=None, 
                 email_headers=None, urls=None, attachments=None, threats=None, score=0):
        self.parent = parent
        self.colors = colors
        self.generate_callback = generate_callback
        self.email_file = email_file
        self.email_headers = email_headers or {}
        self.urls = urls or []
        self.attachments = attachments or []
        self.threats = threats or []
        self.score = score
        self.frame = ctk.CTkFrame(parent, fg_color="transparent")
    
    def pack(self):
        self.frame.pack(fill="both", expand=True, padx=20, pady=20)
        self.build_ui()
    
    def get_email_sender(self):
        from_header = self.email_headers.get("From", "Unknown")
        if "<" in from_header and ">" in from_header:
            start = from_header.find("<") + 1
            end = from_header.find(">")
            return from_header[start:end]
        return from_header
    
    def get_email_recipient(self):
        to_header = self.email_headers.get("To", "Unknown")
        if "<" in to_header and ">" in to_header:
            start = to_header.find("<") + 1
            end = to_header.find(">")
            return to_header[start:end]
        return to_header
    
    def get_email_subject(self):
        return self.email_headers.get("Subject", "No Subject")
    
    def calculate_score(self):
        """
        CORRECT SCORE CALCULATION:
        - No threats = 100% (SAFE)
        - More threats = Lower score
        - Score inversely proportional to threats
        """
        # If score is passed from main, use it
        if self.score > 0:
            return self.score
        
        if not self.email_headers:
            return 0
        
        threat_count = len(self.threats)
        
        # ============================================================
        # SCORE LOGIC: More threats = Lower score
        # ============================================================
        if threat_count == 0:
            return 100  # Perfect score - No threats
        elif threat_count == 1:
            return 85   # One threat - Minor concern
        elif threat_count == 2:
            return 70   # Two threats - Medium concern
        elif threat_count == 3:
            return 55   # Three threats - High concern
        elif threat_count == 4:
            return 40   # Four threats - Very High concern
        elif threat_count == 5:
            return 25   # Five threats - Critical
        else:
            return 10   # 6+ threats - Extremely Critical
    
    def get_risk_level(self, score):
        """Get risk level based on score (Higher score = Safer)"""
        if score >= 80:
            return "SAFE ✅", self.colors["success"]
        elif score >= 60:
            return "LOW RISK ⚠️", self.colors["warning"]
        elif score >= 40:
            return "MEDIUM RISK ⚠️", self.colors["warning"]
        else:
            return "HIGH RISK 🚨", self.colors["danger"]
    
    def get_threat_status(self):
        """Get threat detection status for display"""
        has_threats = len(self.threats) > 0
        
        status = {
            "SPF Authentication": {"status": "✅ PASS", "color": self.colors["success"]},
            "DKIM Signature": {"status": "✅ PASS", "color": self.colors["success"]},
            "DMARC Policy": {"status": "✅ PASS", "color": self.colors["success"]},
            "Domain Reputation": {"status": "✅ CLEAN", "color": self.colors["success"]},
            "URL Analysis": {"status": "✅ SAFE", "color": self.colors["success"]},
            "Attachment Scan": {"status": "✅ SAFE", "color": self.colors["success"]}
        }
        
        # If there are threats, update status
        for threat in self.threats:
            threat_lower = threat.lower()
            if "spf" in threat_lower or "authentication" in threat_lower:
                status["SPF Authentication"]["status"] = "❌ FAILED"
                status["SPF Authentication"]["color"] = self.colors["danger"]
            if "dkim" in threat_lower:
                status["DKIM Signature"]["status"] = "❌ FAILED"
                status["DKIM Signature"]["color"] = self.colors["danger"]
            if "dmarc" in threat_lower:
                status["DMARC Policy"]["status"] = "❌ FAILED"
                status["DMARC Policy"]["color"] = self.colors["danger"]
            if "domain" in threat_lower or "suspicious" in threat_lower:
                status["Domain Reputation"]["status"] = "⚠️ SUSPICIOUS"
                status["Domain Reputation"]["color"] = self.colors["warning"]
        
        # URL status
        if self.urls:
            suspicious_urls = [u for u in self.urls if "http://" in u or "https://" in u]
            if suspicious_urls:
                status["URL Analysis"]["status"] = f"⚠️ {len(self.urls)} FOUND"
                status["URL Analysis"]["color"] = self.colors["warning"]
        
        # Attachment status
        if self.attachments:
            status["Attachment Scan"]["status"] = f"⚠️ {len(self.attachments)} FOUND"
            status["Attachment Scan"]["color"] = self.colors["warning"]
        
        return status
    
    def get_recommendations(self):
        """Get recommendations based on threats"""
        recommendations = []
        
        if self.urls:
            recommendations.append("🔗 Do NOT click any links in this email")
        
        if self.attachments:
            recommendations.append("📎 Do NOT download or open any attachments")
        
        if len(self.threats) > 0:
            recommendations.append("🚨 Report this email as phishing to your IT team")
            recommendations.append("🗑️ Delete the email immediately")
        
        if len(self.threats) == 0 and not self.urls and not self.attachments:
            recommendations = [
                "✅ Email appears safe",
                "👀 Always verify suspicious requests",
                "🔒 Be cautious of unexpected attachments"
            ]
        
        if not recommendations:
            recommendations = [
                "✅ No immediate threats detected",
                "👀 Exercise caution with unknown senders",
                "🔒 Keep security software updated"
            ]
        
        return recommendations
    
    def build_ui(self):
        main_frame = ctk.CTkScrollableFrame(self.frame, fg_color="transparent")
        main_frame.pack(fill="both", expand=True)
        
        # Header
        header_frame = ctk.CTkFrame(main_frame, fg_color="#181838", corner_radius=16, border_width=1, border_color="#2a2a5a")
        header_frame.pack(fill="x", pady=(0, 18))
        
        header_inner = ctk.CTkFrame(header_frame, fg_color="transparent")
        header_inner.pack(fill="x", padx=30, pady=16)
        
        ctk.CTkLabel(header_inner, text="📄 Generate Investigation Report", 
                    font=("Segoe UI", 26, "bold"), text_color="#ffffff").pack(side="left")
        ctk.CTkLabel(header_inner, text="Comprehensive forensic report for email analysis", 
                    font=("Segoe UI", 12), text_color="#555577").pack(side="left", padx=(16, 0))
        
        if not self.email_file:
            empty_card = ctk.CTkFrame(
                main_frame, 
                fg_color="#181838", 
                corner_radius=16,
                border_width=1,
                border_color="#2a2a5a"
            )
            empty_card.pack(fill="both", expand=True, pady=40)
            empty_inner = ctk.CTkFrame(empty_card, fg_color="transparent")
            empty_inner.pack(expand=True)
            ctk.CTkLabel(empty_inner, text="📧", font=("Segoe UI", 55)).pack(pady=(30, 8))
            ctk.CTkLabel(empty_inner, text="No Email Loaded", font=("Segoe UI", 22, "bold"), text_color="#ffffff").pack()
            ctk.CTkLabel(
                empty_inner, 
                text="Upload and analyze an email first to generate a report", 
                font=("Segoe UI", 13), 
                text_color="#555577"
            ).pack(pady=(8, 30))
            return
        
        # ============================================================
        # MAIN REPORT CONTAINER
        # ============================================================
        report_container = ctk.CTkFrame(
            main_frame, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        report_container.pack(fill="both", expand=True)
        
        # Report Header
        header_frame2 = ctk.CTkFrame(report_container, fg_color="transparent")
        header_frame2.pack(fill="x", padx=25, pady=(20, 10))
        
        ctk.CTkLabel(header_frame2, text="📋 FINAL REPORT", 
                    font=("Segoe UI", 20, "bold"), text_color="#6366f1").pack(anchor="w")
        ctk.CTkLabel(header_frame2, text="Email Forensics Analysis Report", 
                    font=("Segoe UI", 13), text_color="#555577").pack(anchor="w")
        ctk.CTkFrame(header_frame2, height=1, fg_color="#2a2a5a").pack(fill="x", pady=(10, 0))
        
        # ============================================================
        # TWO COLUMN LAYOUT
        # ============================================================
        columns_frame = ctk.CTkFrame(report_container, fg_color="transparent")
        columns_frame.pack(fill="both", expand=True, padx=25, pady=15)
        columns_frame.grid_columnconfigure(0, weight=1)
        columns_frame.grid_columnconfigure(1, weight=1)
        
        # ============================================================
        # LEFT COLUMN
        # ============================================================
        left_col = ctk.CTkFrame(columns_frame, fg_color="transparent")
        left_col.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        
        # Email Metadata
        metadata_card = ctk.CTkFrame(left_col, fg_color="#0d0d22", corner_radius=12)
        metadata_card.pack(fill="x", pady=(0, 12))
        
        ctk.CTkLabel(metadata_card, text="📊 Email Metadata", 
                    font=("Segoe UI", 16, "bold"), text_color="#6366f1").pack(anchor="w", padx=15, pady=(12, 8))
        
        file_name = os.path.basename(self.email_file) if self.email_file else "Unknown"
        sender = self.get_email_sender()
        recipient = self.get_email_recipient()
        subject = self.get_email_subject()
        analysis_date = datetime.now().strftime("%B %d, %Y %I:%M:%S %p")
        
        metadata_items = [
            ("📄 File Name:", file_name),
            ("📅 Analysis Date:", analysis_date),
            ("📤 Sender:", sender[:50] + "..." if len(sender) > 50 else sender),
            ("📥 Recipient:", recipient[:50] + "..." if len(recipient) > 50 else recipient),
            ("📝 Subject:", subject[:50] + "..." if len(subject) > 50 else subject),
            ("🔗 URLs Found:", str(len(self.urls))),
            ("📎 Attachments:", str(len(self.attachments))),
            ("⚠️ Threats Detected:", str(len(self.threats))),
        ]
        
        for label, value in metadata_items:
            row = ctk.CTkFrame(metadata_card, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=3)
            ctk.CTkLabel(row, text=label, width=130, anchor="w", 
                        font=("Segoe UI", 12, "bold"), text_color="#555577").pack(side="left")
            color = "#f87171" if "Threats" in label and value != "0" else "#ffffff"
            ctk.CTkLabel(row, text=value, anchor="w", font=("Segoe UI", 12), 
                        text_color=color).pack(side="left", padx=10)
        
        # ============================================================
        # SCORE CARD - CORRECT SCORE DISPLAY
        # ============================================================
        score_card = ctk.CTkFrame(left_col, fg_color="#0d0d22", corner_radius=12)
        score_card.pack(fill="x", pady=(0, 12))
        
        ctk.CTkLabel(score_card, text="🎯 Overall Security Score", 
                    font=("Segoe UI", 16, "bold"), text_color="#6366f1").pack(anchor="w", padx=15, pady=(12, 8))
        
        score_frame = ctk.CTkFrame(score_card, fg_color="transparent")
        score_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        # Calculate score (0-100)
        score_value = self.calculate_score()
        risk_level, risk_color = self.get_risk_level(score_value)
        
        # Large score display with circular progress
        score_display = ctk.CTkFrame(score_frame, fg_color="transparent")
        score_display.pack(fill="x", pady=5)
        
        # Score number - BIG
        ctk.CTkLabel(score_display, text=f"{score_value}%", 
                    font=("Segoe UI", 52, "bold"), text_color=risk_color).pack(side="left")
        
        # Risk label
        ctk.CTkLabel(score_display, text=risk_level, 
                    font=("Segoe UI", 18, "bold"), text_color=risk_color).pack(side="left", padx=20)
        
        # Progress bar with gradient fill
        progress_frame = ctk.CTkFrame(score_frame, fg_color="#2a2a5a", height=12, corner_radius=6)
        progress_frame.pack(fill="x", pady=(10, 0))
        
        fill_width = max(10, int((score_value / 100) * 400))
        fill = ctk.CTkFrame(progress_frame, fg_color=risk_color, height=12, corner_radius=6, width=fill_width)
        fill.pack(side="left")
        
        # Score description
        if score_value >= 80:
            score_desc = "✅ Email appears safe. No significant threats detected."
        elif score_value >= 60:
            score_desc = "⚠️ Minor issues detected. Exercise caution."
        elif score_value >= 40:
            score_desc = "⚠️ Multiple issues detected. Proceed with caution."
        else:
            score_desc = "🚨 CRITICAL! This email is highly suspicious."
        
        ctk.CTkLabel(score_frame, text=score_desc, font=("Segoe UI", 12), 
                    text_color="#555577", anchor="w").pack(fill="x", pady=(8, 0))
        
        # ============================================================
        # METRICS CARD
        # ============================================================
        metrics_card = ctk.CTkFrame(left_col, fg_color="#0d0d22", corner_radius=12)
        metrics_card.pack(fill="x", pady=(0, 12))
        
        ctk.CTkLabel(metrics_card, text="📈 Analysis Metrics", 
                    font=("Segoe UI", 16, "bold"), text_color="#6366f1").pack(anchor="w", padx=15, pady=(12, 8))
        
        threat_count = len(self.threats)
        if threat_count == 0:
            risk_label = "SAFE ✅"
            risk_color = self.colors["success"]
        elif threat_count <= 2:
            risk_label = "LOW RISK ⚠️"
            risk_color = self.colors["warning"]
        elif threat_count <= 4:
            risk_label = "MEDIUM RISK ⚠️"
            risk_color = self.colors["warning"]
        else:
            risk_label = "HIGH RISK 🚨"
            risk_color = self.colors["danger"]
        
        metrics_data = [
            ("🔗 Total URLs", str(len(self.urls)), "#fbbf24"),
            ("📎 Total Attachments", str(len(self.attachments)), "#22d3ee"),
            ("⚠️ Total Threats", str(threat_count), "#f87171"),
            ("📊 Risk Level", risk_label, risk_color)
        ]
        
        for label, value, color in metrics_data:
            row = ctk.CTkFrame(metrics_card, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=3)
            ctk.CTkLabel(row, text=label, width=140, anchor="w", 
                        font=("Segoe UI", 12), text_color="#555577").pack(side="left")
            ctk.CTkLabel(row, text=value, anchor="w", font=("Segoe UI", 12, "bold"), 
                        text_color=color).pack(side="left")
        
        # ============================================================
        # RIGHT COLUMN
        # ============================================================
        right_col = ctk.CTkFrame(columns_frame, fg_color="transparent")
        right_col.grid(row=0, column=1, padx=(10, 0), sticky="nsew")
        
        # Threat Summary
        threat_card = ctk.CTkFrame(right_col, fg_color="#0d0d22", corner_radius=12)
        threat_card.pack(fill="both", expand=True, pady=(0, 12))
        
        ctk.CTkLabel(threat_card, text="⚠️ Threat Detection Summary", 
                    font=("Segoe UI", 16, "bold"), text_color="#f87171").pack(anchor="w", padx=15, pady=(12, 8))
        
        threat_status = self.get_threat_status()
        
        for label, data in threat_status.items():
            row = ctk.CTkFrame(threat_card, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=3)
            ctk.CTkLabel(row, text=label, width=150, anchor="w", 
                        font=("Segoe UI", 12), text_color="#555577").pack(side="left")
            ctk.CTkLabel(row, text=data["status"], anchor="w", font=("Segoe UI", 12, "bold"), 
                        text_color=data["color"]).pack(side="left", padx=5)
        
        # Actual threats list
        if self.threats:
            threats_list_frame = ctk.CTkFrame(threat_card, fg_color="transparent")
            threats_list_frame.pack(fill="x", padx=15, pady=(5, 10))
            ctk.CTkLabel(threats_list_frame, text="Detected Threats:", font=("Segoe UI", 12, "bold"), 
                        text_color="#f87171").pack(anchor="w")
            for threat in self.threats[:5]:
                ctk.CTkLabel(threats_list_frame, text=f"  • {threat}", font=("Segoe UI", 11), 
                            text_color="#555577", anchor="w", justify="left").pack(anchor="w")
            if len(self.threats) > 5:
                ctk.CTkLabel(threats_list_frame, text=f"  • ... and {len(self.threats) - 5} more", 
                            font=("Segoe UI", 11), text_color="#555577", anchor="w").pack(anchor="w")
        
        # ============================================================
        # RECOMMENDATIONS
        # ============================================================
        rec_card = ctk.CTkFrame(right_col, fg_color="#0d0d22", corner_radius=12)
        rec_card.pack(fill="x", pady=(0, 12))
        
        ctk.CTkLabel(rec_card, text="💡 Recommendations", 
                    font=("Segoe UI", 16, "bold"), text_color="#fbbf24").pack(anchor="w", padx=15, pady=(12, 8))
        
        recommendations = self.get_recommendations()
        for rec in recommendations:
            rec_row = ctk.CTkFrame(rec_card, fg_color="transparent")
            rec_row.pack(fill="x", padx=15, pady=3)
            ctk.CTkLabel(rec_row, text=rec, font=("Segoe UI", 12), 
                        text_color="#555577", anchor="w", justify="left").pack(anchor="w")
        
        # ============================================================
        # ACTION BUTTONS
        # ============================================================
        action_frame = ctk.CTkFrame(report_container, fg_color="transparent")
        action_frame.pack(fill="x", padx=25, pady=(10, 20))
        
        gen_btn = ctk.CTkButton(
            action_frame,
            text="📄 Generate Full Report",
            command=self.generate_callback,
            height=45,
            width=240,
            fg_color="#6366f1",
            hover_color="#8b5cf6",
            font=("Segoe UI", 14, "bold"),
            corner_radius=10
        )
        gen_btn.pack(side="left", padx=5)
        
        view_btn = ctk.CTkButton(
            action_frame,
            text="👁️ View Latest Report",
            command=self.view_report,
            height=45,
            width=180,
            fg_color="#fbbf24",
            hover_color="#f59e0b",
            font=("Segoe UI", 14, "bold"),
            corner_radius=10
        )
        view_btn.pack(side="left", padx=5)
        
        # ============================================================
        # FOOTER
        # ============================================================
        footer_frame = ctk.CTkFrame(report_container, fg_color="transparent")
        footer_frame.pack(fill="x", padx=25, pady=(0, 15))
        ctk.CTkFrame(footer_frame, height=1, fg_color="#2a2a5a").pack(fill="x", pady=(5, 10))
        ctk.CTkLabel(footer_frame, text="🔒 Email Forensics Tool v2.0 | Advanced Threat Detection", 
                    font=("Segoe UI", 11), text_color="#555577").pack(side="left")
        ctk.CTkLabel(footer_frame, text=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", 
                    font=("Segoe UI", 11), text_color="#555577").pack(side="right")
    
    def view_report(self):
        """View the latest report - Cross-platform compatible"""
        report_dir = "forensic_reports"
        if not os.path.exists(report_dir):
            messagebox.showwarning("No Reports", "No reports found. Generate a report first.")
            return
        
        reports = [f for f in os.listdir(report_dir) if f.startswith("forensic_report_")]
        if not reports:
            messagebox.showwarning("No Reports", "No reports found. Generate a report first.")
            return
        
        reports.sort(reverse=True)
        latest = os.path.join(report_dir, reports[0])
        
        if os.path.exists(latest):
            try:
                if os.name == 'nt':
                    os.startfile(latest)
                else:
                    import subprocess
                    if sys.platform == 'darwin':
                        subprocess.run(['open', latest])
                    else:
                        subprocess.run(['xdg-open', latest])
            except Exception as e:
                messagebox.showinfo("Report Path", f"Report saved to: {latest}\n\nOpen it manually.")
                