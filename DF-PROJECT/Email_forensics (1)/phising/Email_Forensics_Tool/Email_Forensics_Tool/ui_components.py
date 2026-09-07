import customtkinter as ctk
from datetime import datetime
import os
import re
from html import unescape
import json
from tkinter import messagebox

# ============================================================
# PREMIUM COLOR PALETTE
# ============================================================
PREMIUM_COLORS = {
    "bg_primary": "#0a0a1a",
    "bg_secondary": "#111128",
    "bg_card": "#181838",
    "bg_card_hover": "#222248",
    "bg_sidebar": "#0d0d22",
    "border": "#2a2a5a",
    "border_glow": "#4a4a8a",
    "text_primary": "#ffffff",
    "text_secondary": "#8888bb",
    "text_muted": "#555577",
    "accent_primary": "#6366f1",
    "accent_secondary": "#8b5cf6",
    "accent_tertiary": "#a78bfa",
    "gradient_start": "#6366f1",
    "gradient_end": "#8b5cf6",
    "success": "#22d3ee",
    "warning": "#fbbf24",
    "danger": "#f87171",
}

class DashboardUI:
    def __init__(self, parent, colors, upload_callback, analyze_callback, 
                 scan_callback, report_callback, reset_callback,
                 email_headers, urls, attachments, threats, history_callback=None):
        self.parent = parent
        self.colors = colors
        self.upload_callback = upload_callback
        self.analyze_callback = analyze_callback
        self.scan_callback = scan_callback
        self.report_callback = report_callback
        self.reset_callback = reset_callback
        self.history_callback = history_callback
        self.email_headers = email_headers
        self.urls = urls
        self.attachments = attachments
        self.threats = threats
        self.email_file = None
        self.email_content = None
        self.activity_history = []
        self.email_count = 0
        self._last_email_file = None
        
        self.frame = ctk.CTkFrame(parent, fg_color="transparent")
        self.build_ui()
    
    def pack(self):
        self.frame.pack(fill="both", expand=True, padx=20, pady=20)
    
    def log_activity(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.activity_history.append(log_entry)
        if hasattr(self, 'activity_text'):
            self.activity_text.insert("end", log_entry)
            self.activity_text.see("end")
    
    def update_stats(self, email_headers, urls, attachments, threats, email_file):
        self.email_headers = email_headers
        self.urls = urls
        self.attachments = attachments
        self.threats = threats
        self.email_file = email_file
        
        if email_file and email_file != self._last_email_file:
            self.email_count += 1
            self._last_email_file = email_file
        
        emails_count = str(self.email_count)
        threats_count = str(len(self.threats))
        urls_count = str(len(self.urls))
        attachments_count = str(len(self.attachments))
        
        if hasattr(self, 'email_label'):
            self.email_label.configure(text=emails_count)
        if hasattr(self, 'threat_label'):
            self.threat_label.configure(text=threats_count)
        if hasattr(self, 'url_label'):
            self.url_label.configure(text=urls_count)
        if hasattr(self, 'attach_label'):
            self.attach_label.configure(text=attachments_count)
        
        if self.email_file and hasattr(self, 'file_label'):
            file_name = os.path.basename(self.email_file)
            self.file_label.configure(text=f"✓ Loaded: {file_name}")
    
    def refresh_display(self):
        if hasattr(self, 'email_label'):
            self.email_label.configure(text=str(self.email_count))
        if hasattr(self, 'threat_label'):
            self.threat_label.configure(text=str(len(self.threats)))
        if hasattr(self, 'url_label'):
            self.url_label.configure(text=str(len(self.urls)))
        if hasattr(self, 'attach_label'):
            self.attach_label.configure(text=str(len(self.attachments)))
        if self.email_file and hasattr(self, 'file_label'):
            file_name = os.path.basename(self.email_file)
            self.file_label.configure(text=f"✓ Loaded: {file_name}")
    
    def reset_stats(self):
        self.email_count = 0
        self.email_headers = {}
        self.urls = []
        self.attachments = []
        self.threats = []
        self.email_file = None
        self._last_email_file = None
        self.activity_history = []
        
        if hasattr(self, 'email_label'):
            self.email_label.configure(text="0")
        if hasattr(self, 'threat_label'):
            self.threat_label.configure(text="0")
        if hasattr(self, 'url_label'):
            self.url_label.configure(text="0")
        if hasattr(self, 'attach_label'):
            self.attach_label.configure(text="0")
        if hasattr(self, 'file_label'):
            self.file_label.configure(text="")
        if hasattr(self, 'activity_text'):
            self.activity_text.delete("1.0", "end")
            self.log_activity("System ready. Upload an email to begin analysis.")
    
    def build_ui(self):
        main_frame = ctk.CTkScrollableFrame(self.frame, fg_color="transparent")
        main_frame.pack(fill="both", expand=True)
        
        # ============================================================
        # GRADIENT BACKGROUND - Using frames with different colors
        # ============================================================
        gradient_bg = ctk.CTkFrame(main_frame, fg_color="#0a0a1a", corner_radius=0)
        gradient_bg.pack(fill="both", expand=True)
        
        # ============================================================
        # GLASSMORPHISM STATS CARDS
        # ============================================================
        stats_row = ctk.CTkFrame(gradient_bg, fg_color="transparent")
        stats_row.pack(fill="x", pady=(0, 25))
        
        for i in range(4):
            stats_row.grid_columnconfigure(i, weight=1)
        
        card_configs = [
            {"label": "Emails", "icon": "📧", "color": "#6366f1", "attr": "email_label"},
            {"label": "Threats", "icon": "⚠️", "color": "#f87171", "attr": "threat_label"},
            {"label": "URLs", "icon": "🔗", "color": "#fbbf24", "attr": "url_label"},
            {"label": "Attachments", "icon": "📎", "color": "#22d3ee", "attr": "attach_label"}
        ]
        
        for i, config in enumerate(card_configs):
            # Glassmorphism card
            card = ctk.CTkFrame(
                stats_row, 
                corner_radius=16,
                fg_color="#181838",
                border_width=1,
                border_color="#2a2a5a"
            )
            card.grid(row=0, column=i, padx=8, sticky="nsew", ipady=8)
            
            # Neumorphism inner shadow effect
            inner_shadow = ctk.CTkFrame(
                card, 
                fg_color="#0d0d22",
                corner_radius=14
            )
            inner_shadow.pack(fill="both", expand=True, padx=3, pady=3)
            
            content = ctk.CTkFrame(inner_shadow, fg_color="transparent")
            content.pack(fill="both", expand=True, padx=20, pady=(14, 16))
            
            top_row = ctk.CTkFrame(content, fg_color="transparent")
            top_row.pack(fill="x")
            
            # Glass icon circle
            icon_bg = ctk.CTkFrame(
                top_row, 
                fg_color="#2a2a5a", 
                corner_radius=20, 
                width=36, 
                height=36
            )
            icon_bg.pack(side="left", padx=(0, 10))
            icon_bg.pack_propagate(False)
            ctk.CTkLabel(icon_bg, text=config["icon"], font=("Segoe UI", 16)).pack(expand=True)
            
            ctk.CTkLabel(
                top_row, 
                text=config["label"], 
                font=("Segoe UI", 12, "bold"), 
                text_color="#8888bb"
            ).pack(side="left")
            
            # Animated counter
            value_label = ctk.CTkLabel(
                content, 
                text="0", 
                font=("Segoe UI", 32, "bold"),
                text_color=config["color"]
            )
            value_label.pack(anchor="w", pady=(6, 0))
            setattr(self, config["attr"], value_label)
        
        # ============================================================
        # GLASSMORPHISM - Two Column Layout
        # ============================================================
        content_row = ctk.CTkFrame(gradient_bg, fg_color="transparent")
        content_row.pack(fill="both", expand=True)
        content_row.grid_columnconfigure(0, weight=1)
        content_row.grid_columnconfigure(1, weight=1)
        
        # ============================================================
        # LEFT COLUMN - Upload with Glass Effect
        # ============================================================
        left_column = ctk.CTkFrame(content_row, fg_color="transparent")
        left_column.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        
        upload_card = ctk.CTkFrame(
            left_column, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        upload_card.pack(fill="both", expand=True)
        
        # Gradient header bar
        header_accent = ctk.CTkFrame(upload_card, height=4, fg_color="#6366f1", corner_radius=2)
        header_accent.pack(fill="x", padx=0, pady=0)
        
        header_frame = ctk.CTkFrame(upload_card, fg_color="transparent")
        header_frame.pack(fill="x", padx=25, pady=(20, 10))
        
        ctk.CTkLabel(
            header_frame, 
            text="📤 Upload Email", 
            font=("Segoe UI", 20, "bold"),
            text_color="#ffffff"
        ).pack(side="left")
        
        ctk.CTkLabel(
            header_frame,
            text="Drag & drop or browse",
            font=("Segoe UI", 12),
            text_color="#555577"
        ).pack(side="right")
        
        # Glass drop zone with neumorphism
        drop_zone = ctk.CTkFrame(
            upload_card, 
            fg_color="#0d0d22", 
            corner_radius=14,
            border_width=2,
            border_color="#2a2a5a"
        )
        drop_zone.pack(fill="both", expand=True, padx=25, pady=(0, 20))
        
        # Glass icon frame
        icon_frame = ctk.CTkFrame(
            drop_zone, 
            fg_color="#2a2a5a", 
            corner_radius=50,
            width=90,
            height=90
        )
        icon_frame.pack(pady=(30, 10))
        icon_frame.pack_propagate(False)
        ctk.CTkLabel(icon_frame, text="📧", font=("Segoe UI", 44)).pack(expand=True)
        
        ctk.CTkLabel(
            drop_zone, 
            text="Drop your .eml file here", 
            font=("Segoe UI", 16, "bold"),
            text_color="#ffffff"
        ).pack()
        
        ctk.CTkLabel(
            drop_zone, 
            text="or click the button below to browse", 
            font=("Segoe UI", 12),
            text_color="#555577"
        ).pack(pady=(4, 14))
        
        # Neumorphism button
        browse_btn = ctk.CTkButton(
            drop_zone, 
            text="📁 Browse Files", 
            command=self.upload_callback,
            height=48, 
            width=240, 
            fg_color="#6366f1", 
            hover_color="#8b5cf6",
            font=("Segoe UI", 14, "bold"),
            corner_radius=12
        )
        browse_btn.pack(pady=8)
        
        self.file_label = ctk.CTkLabel(
            drop_zone, 
            text="", 
            font=("Segoe UI", 12, "bold"), 
            text_color="#22d3ee"
        )
        self.file_label.pack(pady=(0, 15))
        
        if self.email_file:
            file_name = os.path.basename(self.email_file)
            self.file_label.configure(text=f"✓ Loaded: {file_name}")
        
        # ============================================================
        # RIGHT COLUMN - Activity Log with Glass Effect
        # ============================================================
        right_column = ctk.CTkFrame(content_row, fg_color="transparent")
        right_column.grid(row=0, column=1, padx=(10, 0), sticky="nsew")
        
        activity_card = ctk.CTkFrame(
            right_column, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        activity_card.pack(fill="both", expand=True, pady=(0, 10))
        
        activity_header = ctk.CTkFrame(activity_card, fg_color="transparent")
        activity_header.pack(fill="x", padx=25, pady=(18, 10))
        
        ctk.CTkLabel(
            activity_header, 
            text="📋 Activity Log", 
            font=("Segoe UI", 18, "bold"),
            text_color="#ffffff"
        ).pack(side="left")
        
        # Animated pulse indicator
        status_frame = ctk.CTkFrame(activity_header, fg_color="transparent")
        status_frame.pack(side="right")
        
        status_dot = ctk.CTkFrame(
            status_frame,
            width=8,
            height=8,
            fg_color="#22d3ee",
            corner_radius=4
        )
        status_dot.pack(side="left", padx=(0, 6))
        ctk.CTkLabel(
            status_frame,
            text="Live",
            font=("Segoe UI", 11),
            text_color="#22d3ee"
        ).pack(side="left")
        
        # Activity text with glass effect
        self.activity_text = ctk.CTkTextbox(
            activity_card, 
            font=("Segoe UI", 12),
            fg_color="#0d0d22",
            corner_radius=12
        )
        self.activity_text.pack(fill="both", expand=True, padx=20, pady=(0, 15))
        
        for entry in self.activity_history:
            self.activity_text.insert("end", entry)
        self.activity_text.see("end")
        
        # ============================================================
        # QUICK ACTIONS - Glass Card
        # ============================================================
        actions_card = ctk.CTkFrame(
            right_column, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        actions_card.pack(fill="x")
        
        actions_header = ctk.CTkFrame(actions_card, fg_color="transparent")
        actions_header.pack(fill="x", padx=25, pady=(15, 8))
        
        ctk.CTkLabel(
            actions_header, 
            text="⚡ Quick Actions", 
            font=("Segoe UI", 16, "bold"),
            text_color="#ffffff"
        ).pack(side="left")
        
        btn_frame = ctk.CTkFrame(actions_card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=18, pady=(0, 12))
        
        actions = [
            {"text": "🔍 Analyze Email", "callback": self.analyze_callback, "color": "#6366f1"},
            {"text": "🌐 Scan URLs", "callback": self.scan_callback, "color": "#fbbf24"},
            {"text": "📄 Generate Report", "callback": self.report_callback, "color": "#22d3ee"},
            {"text": "🗑️ Clear Data", "callback": self.reset_callback, "color": "#f87171"}
        ]
        
        for i, action in enumerate(actions):
            row = i // 2
            col = i % 2
            # Neumorphism buttons
            btn = ctk.CTkButton(
                btn_frame, 
                text=action["text"], 
                command=action["callback"], 
                height=40, 
                fg_color="#0d0d22", 
                hover_color="#2a2a5a",
                font=("Segoe UI", 12),
                anchor="w",
                corner_radius=10,
                border_width=1,
                border_color="#2a2a5a"
            )
            btn.grid(row=row, column=col, padx=4, pady=3, sticky="ew")
            btn_frame.grid_columnconfigure(col, weight=1)
    
    def update_activity_log(self, message):
        self.log_activity(message)


# ============================================================
# HISTORY UI - With Glass and Neumorphism
# ============================================================
class HistoryUI:
    def __init__(self, parent, colors, history_data, on_select_callback, reset_callback=None):
        self.parent = parent
        self.colors = colors
        self.history_data = history_data
        self.on_select_callback = on_select_callback
        self.reset_callback = reset_callback
        self.frame = ctk.CTkFrame(parent, fg_color="transparent")
        self.build_ui()
    
    def pack(self):
        self.frame.pack(fill="both", expand=True, padx=20, pady=20)
    
    def build_ui(self):
        main_frame = ctk.CTkScrollableFrame(self.frame, fg_color="transparent")
        main_frame.pack(fill="both", expand=True)
        
        # Glass header
        header_card = ctk.CTkFrame(
            main_frame, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        header_card.pack(fill="x", pady=(0, 18))
        
        header_inner = ctk.CTkFrame(header_card, fg_color="transparent")
        header_inner.pack(fill="x", padx=30, pady=20)
        
        ctk.CTkLabel(
            header_inner, 
            text="📊 Scan History", 
            font=("Segoe UI", 26, "bold"),
            text_color="#ffffff"
        ).pack(side="left")
        
        total_scans = len(self.history_data)
        total_threats = sum(r.get('threats', 0) for r in self.history_data)
        
        stats_container = ctk.CTkFrame(header_inner, fg_color="transparent")
        stats_container.pack(side="right")
        
        # Glass pills
        pill1 = ctk.CTkFrame(stats_container, fg_color="#2a2a5a", corner_radius=20)
        pill1.pack(side="left", padx=4)
        ctk.CTkLabel(pill1, text=f"📌 {total_scans} Scans", font=("Segoe UI", 11), text_color="#6366f1").pack(padx=14, pady=4)
        
        pill2 = ctk.CTkFrame(stats_container, fg_color="#2a2a5a", corner_radius=20)
        pill2.pack(side="left", padx=4)
        ctk.CTkLabel(pill2, text=f"⚠️ {total_threats} Threats", font=("Segoe UI", 11), text_color="#f87171").pack(padx=14, pady=4)
        
        # Reset button with neumorphism
        if self.reset_callback:
            reset_btn = ctk.CTkButton(
                header_inner, 
                text="🗑️ Reset All Data", 
                command=self.reset_callback,
                height=38,
                width=150,
                fg_color="#f87171",
                hover_color="#ef4444",
                font=("Segoe UI", 12, "bold"),
                corner_radius=10
            )
            reset_btn.pack(side="right", padx=(15, 0))
        
        if not self.history_data:
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
            ctk.CTkLabel(empty_inner, text="📭", font=("Segoe UI", 55)).pack(pady=(30, 8))
            ctk.CTkLabel(
                empty_inner, 
                text="No Scan History", 
                font=("Segoe UI", 22, "bold"), 
                text_color="#ffffff"
            ).pack()
            ctk.CTkLabel(
                empty_inner, 
                text="Upload and analyze emails to see history here", 
                font=("Segoe UI", 13), 
                text_color="#555577"
            ).pack(pady=(8, 30))
            return
        
        # History items with glass effect
        for record in self.history_data:
            threat_count = record.get('threats', 0)
            border_color = "#22d3ee" if threat_count == 0 else "#fbbf24" if threat_count <= 2 else "#f87171"
            
            card = ctk.CTkFrame(
                main_frame, 
                fg_color="#181838", 
                corner_radius=14,
                border_width=1,
                border_color="#2a2a5a"
            )
            card.pack(fill="x", pady=6)
            
            # Neumorphism left accent
            border = ctk.CTkFrame(card, width=5, fg_color=border_color, corner_radius=2)
            border.pack(side="left", fill="y", padx=(0, 12), pady=10)
            
            content = ctk.CTkFrame(card, fg_color="transparent")
            content.pack(fill="x", padx=18, pady=12)
            
            header_row = ctk.CTkFrame(content, fg_color="transparent")
            header_row.pack(fill="x")
            ctk.CTkLabel(
                header_row, 
                text=f"{record.get('subject', 'No Subject')[:45]}", 
                font=("Segoe UI", 15, "bold"),
                text_color="#ffffff"
            ).pack(side="left")
            ctk.CTkLabel(
                header_row, 
                text=record.get('timestamp', ''), 
                font=("Segoe UI", 11),
                text_color="#555577"
            ).pack(side="right")
            
            details_row = ctk.CTkFrame(content, fg_color="transparent")
            details_row.pack(fill="x", pady=(6, 4))
            
            from_frame = ctk.CTkFrame(details_row, fg_color="transparent")
            from_frame.pack(side="left", padx=(0, 15))
            ctk.CTkLabel(
                from_frame, 
                text="From:", 
                font=("Segoe UI", 11, "bold"), 
                text_color="#555577"
            ).pack(side="left")
            ctk.CTkLabel(
                from_frame, 
                text=record.get('from', 'Unknown')[:40], 
                font=("Segoe UI", 11), 
                text_color="#8888bb"
            ).pack(side="left", padx=(6, 0))
            
            stats_row = ctk.CTkFrame(details_row, fg_color="transparent")
            stats_row.pack(side="right")
            
            badges = [
                (f"⚠️ {record.get('threats', 0)}", border_color),
                (f"🔗 {record.get('urls', 0)}", "#fbbf24"),
                (f"📎 {record.get('attachments', 0)}", "#22d3ee")
            ]
            for text, color in badges:
                badge = ctk.CTkFrame(stats_row, fg_color="#2a2a5a", corner_radius=10)
                badge.pack(side="left", padx=2)
                ctk.CTkLabel(badge, text=text, font=("Segoe UI", 10), text_color=color).pack(padx=8, pady=2)
            
            action_row = ctk.CTkFrame(content, fg_color="transparent")
            action_row.pack(fill="x", pady=(6, 0))
            
            score = record.get('score', 0)
            score_color = "#22d3ee" if score >= 80 else "#fbbf24" if score >= 50 else "#f87171"
            ctk.CTkLabel(
                action_row, 
                text=f"Security Score: {score}%", 
                font=("Segoe UI", 12, "bold"),
                text_color=score_color
            ).pack(side="left")
            
            view_btn = ctk.CTkButton(
                action_row,
                text="View Details →",
                command=lambda r=record: self.on_select_callback(r),
                height=32,
                width=130,
                fg_color="#6366f1",
                hover_color="#8b5cf6",
                font=("Segoe UI", 11, "bold"),
                corner_radius=8
            )
            view_btn.pack(side="right")


# ============================================================
# ANALYSIS UI - Premium Glass Design
# ============================================================
class AnalysisUI:
    def __init__(self, parent, colors, email_content, email_headers, upload_callback):
        self.parent = parent
        self.colors = colors
        self.email_content = email_content
        self.email_headers = email_headers
        self.upload_callback = upload_callback
        self.email_file = None
        self.attachments = []
        self.threats = []
        self.urls = []
        self.frame = ctk.CTkFrame(parent, fg_color="transparent")
    
    def pack(self):
        self.frame.pack(fill="both", expand=True, padx=20, pady=20)
        self.build_ui()
    
    def get_email_size(self):
        if self.email_file and os.path.exists(self.email_file):
            size = os.path.getsize(self.email_file)
            if size < 1024:
                return f"{size} B"
            elif size < 1024 * 1024:
                return f"{size / 1024:.1f} KB"
            else:
                return f"{size / (1024 * 1024):.1f} MB"
        return "0 KB"
    
    def calculate_score(self):
        if not self.email_headers:
            return 0
        if len(self.threats) == 0:
            return 100
        elif len(self.threats) <= 2:
            return 85
        elif len(self.threats) <= 4:
            return 65
        else:
            return 40
    
    def clean_html(self, html_text):
        if not html_text:
            return ""
        text = unescape(html_text)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL)
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    
    def extract_email_body(self):
        if not self.email_content:
            return "No email content available."
        
        body = self.email_content.get("body", "")
        
        if not body or '<' in body:
            if "raw" in self.email_content:
                raw = self.email_content["raw"]
                if raw.is_multipart():
                    for part in raw.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_content()
                            break
                        elif part.get_content_type() == "text/html":
                            body = self.clean_html(part.get_content())
                            break
                else:
                    if raw.get_content_type() == "text/html":
                        body = self.clean_html(raw.get_content())
                    else:
                        body = raw.get_content()
        
        if body and '<' in body:
            body = self.clean_html(body)
        
        if not body or len(body) < 10:
            return "No readable text content in this email."
        
        if len(body) > 2000:
            body = body[:2000] + "..."
        
        return body
    
    def build_ui(self):
        main_frame = ctk.CTkScrollableFrame(self.frame, fg_color="transparent")
        main_frame.pack(fill="both", expand=True)
        
        header_card = ctk.CTkFrame(
            main_frame, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        header_card.pack(fill="x", pady=(0, 18))
        
        header_inner = ctk.CTkFrame(header_card, fg_color="transparent")
        header_inner.pack(fill="x", padx=30, pady=16)
        
        ctk.CTkLabel(
            header_inner, 
            text="🔍 Email Analysis Overview", 
            font=("Segoe UI", 26, "bold"),
            text_color="#ffffff"
        ).pack(side="left")
        
        score = self.calculate_score()
        score_color = "#22d3ee" if score >= 80 else "#fbbf24" if score >= 50 else "#f87171"
        score_badge = ctk.CTkFrame(
            header_inner, 
            fg_color="#2a2a5a",
            corner_radius=18
        )
        score_badge.pack(side="right")
        ctk.CTkLabel(
            score_badge, 
            text=f"Score: {score}%", 
            font=("Segoe UI", 13, "bold"),
            text_color=score_color
        ).pack(padx=18, pady=6)
        
        if not self.email_headers:
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
                text="Upload an email using the Dashboard page", 
                font=("Segoe UI", 13),
                text_color="#555577"
            ).pack(pady=(8, 30))
            return
        
        columns_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        columns_frame.pack(fill="both", expand=True)
        columns_frame.grid_columnconfigure(0, weight=2)
        columns_frame.grid_columnconfigure(1, weight=1)
        
        left_column = ctk.CTkFrame(columns_frame, fg_color="transparent")
        left_column.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        
        details_card = ctk.CTkFrame(
            left_column, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        details_card.pack(fill="x", pady=(0, 12))
        
        details_header = ctk.CTkFrame(details_card, fg_color="transparent")
        details_header.pack(fill="x", padx=22, pady=(14, 8))
        ctk.CTkLabel(
            details_header, 
            text="📋 Email Details", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(side="left")
        
        details_content = ctk.CTkFrame(details_card, fg_color="transparent")
        details_content.pack(fill="x", padx=22, pady=(0, 14))
        
        from_addr = self.email_headers.get("From", "Unknown")
        to_addr = self.email_headers.get("To", "Unknown")
        subject = self.email_headers.get("Subject", "No Subject")
        date = self.email_headers.get("Date", "Unknown")
        attach_text = f"{len(self.attachments)} attachment(s)" if self.attachments else "No attachments"
        
        details = [
            ("From:", from_addr, "#ffffff"),
            ("To:", to_addr, "#ffffff"),
            ("Subject:", subject, "#6366f1"),
            ("Date:", date, "#555577"),
            ("Attachment:", attach_text, "#22d3ee"),
            ("Email Size:", self.get_email_size(), "#555577")
        ]
        
        for label, value, color in details:
            row = ctk.CTkFrame(details_content, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(
                row, 
                text=label, 
                width=90,
                anchor="w",
                font=("Segoe UI", 12, "bold"),
                text_color="#555577"
            ).pack(side="left")
            ctk.CTkLabel(
                row, 
                text=value,
                anchor="w",
                font=("Segoe UI", 12),
                text_color=color,
                wraplength=380
            ).pack(side="left", padx=8, fill="x", expand=True)
        
        body_card = ctk.CTkFrame(
            left_column, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        body_card.pack(fill="both", expand=True)
        
        body_header = ctk.CTkFrame(body_card, fg_color="transparent")
        body_header.pack(fill="x", padx=22, pady=(14, 8))
        ctk.CTkLabel(
            body_header, 
            text="📝 Email Body", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(side="left")
        
        body_text = ctk.CTkTextbox(
            body_card,
            font=("Segoe UI", 12),
            wrap="word",
            fg_color="#0d0d22",
            corner_radius=10
        )
        body_text.pack(fill="both", expand=True, padx=18, pady=(0, 14))
        body_text.insert("1.0", self.extract_email_body())
        
        right_column = ctk.CTkFrame(columns_frame, fg_color="transparent")
        right_column.grid(row=0, column=1, padx=(10, 0), sticky="nsew")
        
        summary_card = ctk.CTkFrame(
            right_column, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        summary_card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(
            summary_card, 
            text="📊 Analysis Summary", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(14, 8))
        
        if len(self.threats) == 0:
            status_text = "✅ No critical issues found"
            status_color = "#22d3ee"
        else:
            status_text = f"⚠️ {len(self.threats)} potential issue(s) detected"
            status_color = "#fbbf24"
        ctk.CTkLabel(
            summary_card,
            text=status_text,
            font=("Segoe UI", 12),
            text_color=status_color,
            justify="left"
        ).pack(anchor="w", padx=22, pady=(0, 14))
        
        score_card = ctk.CTkFrame(
            right_column, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        score_card.pack(fill="x")
        ctk.CTkLabel(
            score_card, 
            text="🎯 Overall Score", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(14, 6))
        
        score = self.calculate_score()
        score_color = "#22d3ee" if score >= 80 else "#fbbf24" if score >= 50 else "#f87171"
        score_frame = ctk.CTkFrame(score_card, fg_color="transparent")
        score_frame.pack(pady=(8, 2))
        ctk.CTkLabel(
            score_frame,
            text=f"{score}%",
            font=("Segoe UI", 48, "bold"),
            text_color=score_color
        ).pack()
        
        score_label = "Excellent" if score >= 80 else "Good" if score >= 50 else "Needs Review"
        ctk.CTkLabel(
            score_card,
            text=score_label,
            font=("Segoe UI", 13),
            text_color=score_color
        ).pack(pady=(0, 14))
        
        if self.threats:
            threats_card = ctk.CTkFrame(
                right_column, 
                fg_color="#181838", 
                corner_radius=14,
                border_width=1,
                border_color="#2a2a5a"
            )
            threats_card.pack(fill="x", pady=(12, 0))
            ctk.CTkLabel(
                threats_card, 
                text="⚠️ Detected Threats", 
                font=("Segoe UI", 15, "bold"),
                text_color="#f87171"
            ).pack(anchor="w", padx=22, pady=(14, 8))
            for threat in self.threats[:5]:
                threat_row = ctk.CTkFrame(threats_card, fg_color="transparent")
                threat_row.pack(fill="x", padx=22, pady=2)
                ctk.CTkLabel(
                    threat_row,
                    text="•",
                    font=("Segoe UI", 13),
                    text_color="#f87171"
                ).pack(side="left", padx=(0, 6))
                ctk.CTkLabel(
                    threat_row,
                    text=threat,
                    font=("Segoe UI", 11),
                    text_color="#555577",
                    wraplength=260,
                    justify="left"
                ).pack(side="left", fill="x", expand=True)


# ============================================================
# HEADERS UI - Premium Glass Design
# ============================================================
class HeadersUI:
    def __init__(self, parent, colors, email_headers, upload_callback):
        self.parent = parent
        self.colors = colors
        self.email_headers = email_headers
        self.upload_callback = upload_callback
        self.frame = ctk.CTkFrame(parent, fg_color="transparent")
    
    def pack(self):
        self.frame.pack(fill="both", expand=True, padx=20, pady=20)
        self.build_ui()
    
    def build_ui(self):
        main_frame = ctk.CTkScrollableFrame(self.frame, fg_color="transparent")
        main_frame.pack(fill="both", expand=True)
        
        header_card = ctk.CTkFrame(
            main_frame, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        header_card.pack(fill="x", pady=(0, 18))
        
        header_inner = ctk.CTkFrame(header_card, fg_color="transparent")
        header_inner.pack(fill="x", padx=30, pady=16)
        ctk.CTkLabel(
            header_inner, 
            text="📋 Email Header Analysis", 
            font=("Segoe UI", 26, "bold"),
            text_color="#ffffff"
        ).pack(side="left")
        
        if not self.email_headers:
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
                text="Upload an email using the Dashboard page", 
                font=("Segoe UI", 13),
                text_color="#555577"
            ).pack(pady=(8, 30))
            return
        
        from header_analyzer import HeaderAnalyzer
        analyzer = HeaderAnalyzer()
        threats, warnings, info, header_structure = analyzer.analyze_headers(self.email_headers)
        
        trust_score = 100
        for threat in threats:
            if 'SPF FAILED' in threat:
                trust_score -= 25
            elif 'DKIM FAILED' in threat:
                trust_score -= 20
            elif 'DMARC FAILED' in threat:
                trust_score -= 30
            elif 'SPOOFING' in threat or 'impersonating' in threat:
                trust_score -= 40
            elif 'mismatch' in threat.lower():
                trust_score -= 15
            elif 'Future date' in threat:
                trust_score -= 15
            elif 'Suspicious character' in threat:
                trust_score -= 10
        trust_score = max(0, min(100, trust_score))
        
        columns_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        columns_frame.pack(fill="both", expand=True)
        columns_frame.grid_columnconfigure(0, weight=1)
        columns_frame.grid_columnconfigure(1, weight=1)
        
        left_column = ctk.CTkFrame(columns_frame, fg_color="transparent")
        left_column.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        
        details_card = ctk.CTkFrame(
            left_column, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        details_card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(
            details_card, 
            text="📋 Header Details", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(14, 8))
        
        from_header = self.email_headers.get("From", "Unknown")
        to_header = self.email_headers.get("To", "Unknown")
        subject = self.email_headers.get("Subject", "No Subject")
        date = self.email_headers.get("Date", "Unknown")
        
        details = [
            ("From:", from_header[:55] + "..." if len(from_header) > 55 else from_header),
            ("To:", to_header[:55] + "..." if len(to_header) > 55 else to_header),
            ("Subject:", subject[:55] + "..." if len(subject) > 55 else subject),
            ("Date:", date[:55] if len(date) > 55 else date)
        ]
        
        for label, value in details:
            row = ctk.CTkFrame(details_card, fg_color="transparent")
            row.pack(fill="x", padx=22, pady=3)
            ctk.CTkLabel(
                row, 
                text=label, 
                width=65,
                anchor="w",
                font=("Segoe UI", 12, "bold"),
                text_color="#555577"
            ).pack(side="left")
            ctk.CTkLabel(
                row, 
                text=value,
                anchor="w",
                font=("Segoe UI", 11),
                text_color="#ffffff",
                wraplength=330
            ).pack(side="left", padx=8, fill="x", expand=True)
        
        if threats:
            threats_card = ctk.CTkFrame(
                left_column, 
                fg_color="#181838", 
                corner_radius=14,
                border_width=1,
                border_color="#2a2a5a"
            )
            threats_card.pack(fill="x", pady=(0, 12))
            ctk.CTkLabel(
                threats_card, 
                text="⚠️ Detected Threats", 
                font=("Segoe UI", 17, "bold"),
                text_color="#f87171"
            ).pack(anchor="w", padx=22, pady=(14, 8))
            for threat in threats:
                threat_row = ctk.CTkFrame(threats_card, fg_color="transparent")
                threat_row.pack(fill="x", padx=22, pady=3)
                ctk.CTkLabel(
                    threat_row,
                    text="•",
                    font=("Segoe UI", 13),
                    text_color="#f87171"
                ).pack(side="left", padx=(0, 6))
                ctk.CTkLabel(
                    threat_row,
                    text=threat,
                    font=("Segoe UI", 11),
                    text_color="#f87171",
                    wraplength=330,
                    justify="left",
                    anchor="w"
                ).pack(side="left", fill="x", expand=True)
        
        if info:
            info_card = ctk.CTkFrame(
                left_column, 
                fg_color="#181838", 
                corner_radius=14,
                border_width=1,
                border_color="#2a2a5a"
            )
            info_card.pack(fill="x")
            ctk.CTkLabel(
                info_card, 
                text="ℹ️ Information", 
                font=("Segoe UI", 17, "bold"),
                text_color="#6366f1"
            ).pack(anchor="w", padx=22, pady=(14, 8))
            for msg in info[:6]:
                info_row = ctk.CTkFrame(info_card, fg_color="transparent")
                info_row.pack(fill="x", padx=22, pady=2)
                ctk.CTkLabel(
                    info_row,
                    text="•",
                    font=("Segoe UI", 13),
                    text_color="#6366f1"
                ).pack(side="left", padx=(0, 6))
                ctk.CTkLabel(
                    info_row,
                    text=msg,
                    font=("Segoe UI", 10),
                    text_color="#555577",
                    wraplength=330,
                    justify="left",
                    anchor="w"
                ).pack(side="left", fill="x", expand=True)
        
        right_column = ctk.CTkFrame(columns_frame, fg_color="transparent")
        right_column.grid(row=0, column=1, padx=(10, 0), sticky="nsew")
        
        score_card = ctk.CTkFrame(
            right_column, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        score_card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(
            score_card, 
            text="🎯 Header Trust Score", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(pady=(14, 6))
        
        if trust_score >= 80:
            score_color = "#22d3ee"
            score_label = "Low Risk ✅"
        elif trust_score >= 50:
            score_color = "#fbbf24"
            score_label = "Medium Risk ⚠️"
        else:
            score_color = "#f87171"
            score_label = "High Risk 🚨"
        
        ctk.CTkLabel(
            score_card,
            text=f"{trust_score}%",
            font=("Segoe UI", 44, "bold"),
            text_color=score_color
        ).pack(pady=(8, 2))
        ctk.CTkLabel(
            score_card,
            text=score_label,
            font=("Segoe UI", 13, "bold"),
            text_color=score_color
        ).pack(pady=(0, 14))
        
        auth_card = ctk.CTkFrame(
            right_column, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        auth_card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(
            auth_card, 
            text="🔐 Authentication Status", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(14, 8))
        
        spf_status = "Not Found"
        dkim_status = "Not Found"
        dmarc_status = "Not Found"
        
        for msg in info:
            if "SPF PASS" in msg:
                spf_status = "✅ PASS"
            elif "SPF FAIL" in msg:
                spf_status = "❌ FAIL"
            elif "No SPF" in msg:
                spf_status = "⚪ Not Found"
            if "DKIM PASS" in msg:
                dkim_status = "✅ PASS"
            elif "DKIM FAIL" in msg:
                dkim_status = "❌ FAIL"
            elif "No DKIM" in msg:
                dkim_status = "⚪ Not Found"
            if "DMARC PASS" in msg:
                dmarc_status = "✅ PASS"
            elif "DMARC FAIL" in msg:
                dmarc_status = "❌ FAIL"
            elif "No DMARC" in msg:
                dmarc_status = "⚪ Not Found"
        
        auth_frame = ctk.CTkFrame(auth_card, fg_color="transparent")
        auth_frame.pack(fill="x", padx=22, pady=(0, 14))
        
        status_colors = {"✅ PASS": "#22d3ee", "❌ FAIL": "#f87171", "⚪ Not Found": "#555577"}
        for label, status in [("SPF", spf_status), ("DKIM", dkim_status), ("DMARC", dmarc_status)]:
            row = ctk.CTkFrame(auth_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(
                row, 
                text=f"{label}:", 
                font=("Segoe UI", 12, "bold"),
                text_color="#555577",
                width=55,
                anchor="w"
            ).pack(side="left")
            ctk.CTkLabel(
                row,
                text=status,
                font=("Segoe UI", 12),
                text_color=status_colors.get(status, "#555577"),
                anchor="w"
            ).pack(side="left", padx=8)
        
        rec_card = ctk.CTkFrame(
            right_column, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        rec_card.pack(fill="x")
        ctk.CTkLabel(
            rec_card, 
            text="💡 Recommendation", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(14, 8))
        
        if trust_score >= 80:
            rec_text = "✅ Headers appear legitimate. Safe to proceed."
            rec_color = "#22d3ee"
        elif trust_score >= 50:
            rec_text = "⚠️ Exercise caution. Suspicious header indicators found."
            rec_color = "#fbbf24"
        else:
            rec_text = "🚨 HIGH RISK! Do not trust this email. Possible spoofing."
            rec_color = "#f87171"
        
        rec_frame = ctk.CTkFrame(rec_card, fg_color="#0d0d22", corner_radius=10)
        rec_frame.pack(fill="x", padx=22, pady=(0, 14))
        ctk.CTkLabel(
            rec_frame,
            text=rec_text,
            font=("Segoe UI", 12, "bold"),
            text_color=rec_color,
            wraplength=280,
            justify="left",
            anchor="w"
        ).pack(padx=14, pady=10)
        
        headers_card = ctk.CTkFrame(
            main_frame, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        headers_card.pack(fill="both", expand=True, pady=(12, 0))
        ctk.CTkLabel(
            headers_card, 
            text="📄 All Email Headers", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(14, 8))
        
        headers_text = ctk.CTkTextbox(
            headers_card,
            font=("Segoe UI", 10),
            wrap="word",
            fg_color="#0d0d22",
            corner_radius=10
        )
        headers_text.pack(fill="both", expand=True, padx=18, pady=(0, 14))
        for key, value in self.email_headers.items():
            headers_text.insert("end", f"{key}: {value}\n\n")


# ============================================================
# URL SCANNER UI - Premium Glass Design
# ============================================================
class URLScannerUI:
    def __init__(self, parent, colors, urls, scan_callback):
        self.parent = parent
        self.colors = colors
        self.urls = urls if urls else []
        self.scan_callback = scan_callback
        self.frame = ctk.CTkFrame(parent, fg_color="transparent")
        self.scan_results = []
    
    def pack(self):
        self.frame.pack(fill="both", expand=True, padx=20, pady=20)
        self.build_ui()
    
    def build_ui(self):
        self.main_frame = ctk.CTkScrollableFrame(self.frame, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True)
        
        header_card = ctk.CTkFrame(
            self.main_frame, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        header_card.pack(fill="x", pady=(0, 18))
        
        header_inner = ctk.CTkFrame(header_card, fg_color="transparent")
        header_inner.pack(fill="x", padx=30, pady=16)
        ctk.CTkLabel(
            header_inner, 
            text="🔗 URL / Link Scanner", 
            font=("Segoe UI", 26, "bold"),
            text_color="#ffffff"
        ).pack(side="left")
        ctk.CTkLabel(
            header_inner,
            text="Scan and analyze suspicious URLs for phishing threats",
            font=("Segoe UI", 12),
            text_color="#555577"
        ).pack(side="left", padx=(16, 0))
        
        manual_card = ctk.CTkFrame(
            self.main_frame, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        manual_card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(
            manual_card, 
            text="🔍 Manually Check Any URL", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(14, 8))
        
        input_frame = ctk.CTkFrame(manual_card, fg_color="transparent")
        input_frame.pack(fill="x", padx=22, pady=(0, 10))
        
        self.url_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Paste any URL to check (e.g., https://example.com)",
            height=40,
            font=("Segoe UI", 12),
            corner_radius=10,
            fg_color="#0d0d22",
            border_width=1,
            border_color="#2a2a5a"
        )
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        
        check_btn = ctk.CTkButton(
            input_frame,
            text="🔍 Check URL",
            command=self.check_manual_url,
            height=40,
            width=120,
            fg_color="#6366f1",
            hover_color="#8b5cf6",
            font=("Segoe UI", 12, "bold"),
            corner_radius=10
        )
        check_btn.pack(side="right")
        
        self.result_frame = ctk.CTkFrame(manual_card, fg_color="#0d0d22", corner_radius=10)
        
        extracted_card = ctk.CTkFrame(
            self.main_frame, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        extracted_card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(
            extracted_card, 
            text="📧 URLs from Email", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(14, 8))
        
        self.urls_frame = ctk.CTkScrollableFrame(extracted_card, fg_color="transparent", height=160)
        self.urls_frame.pack(fill="x", padx=18, pady=(0, 8))
        
        if self.urls and len(self.urls) > 0:
            display_urls = self.urls[:15]
            for i, url in enumerate(display_urls):
                url_frame = ctk.CTkFrame(self.urls_frame, fg_color="#0d0d22", corner_radius=6)
                url_frame.pack(fill="x", pady=2)
                display_url = url[:75] + "..." if len(url) > 75 else url
                ctk.CTkLabel(
                    url_frame,
                    text=f"{i+1}. {display_url}",
                    font=("Segoe UI", 10),
                    text_color="#555577",
                    anchor="w",
                    wraplength=450
                ).pack(side="left", padx=10, pady=4, fill="x", expand=True)
            if len(self.urls) > 15:
                ctk.CTkLabel(
                    self.urls_frame,
                    text=f"... and {len(self.urls) - 15} more URLs",
                    font=("Segoe UI", 10),
                    text_color="#fbbf24"
                ).pack(pady=4)
        else:
            ctk.CTkLabel(
                self.urls_frame,
                text="No URLs found in email.\nPaste a URL above to check manually.",
                font=("Segoe UI", 11),
                text_color="#555577"
            ).pack(pady=18)
        
        scan_all_btn = ctk.CTkButton(
            extracted_card,
            text="🛡️ Scan All Extracted URLs",
            command=self.scan_all_urls,
            height=40,
            font=("Segoe UI", 13, "bold"),
            fg_color="#fbbf24",
            hover_color="#f59e0b",
            corner_radius=10
        )
        scan_all_btn.pack(pady=(4, 12))
        
        results_card = ctk.CTkFrame(
            self.main_frame, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        results_card.pack(fill="both", expand=True)
        ctk.CTkLabel(
            results_card, 
            text="📊 Scan Results", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(14, 8))
        
        self.results_text = ctk.CTkTextbox(
            results_card,
            font=("Segoe UI", 11),
            fg_color="#0d0d22",
            corner_radius=10
        )
        self.results_text.pack(fill="both", expand=True, padx=18, pady=(0, 14))
        self.results_text.insert("1.0", "Click 'Scan All Extracted URLs' or paste a URL above to begin analysis.\n")
    
    def scan_all_urls(self):
        if not self.urls:
            self.results_text.delete("1.0", "end")
            self.results_text.insert("1.0", "No URLs to scan. Upload an email with URLs first.")
            return
        self.results_text.delete("1.0", "end")
        self.results_text.insert("1.0", "🔄 Scanning URLs... Please wait...\n\n")
        self.frame.update_idletasks()
        if self.scan_callback:
            self.frame.after(100, self.scan_callback)
    
    def check_manual_url(self):
        from threat_detector import ThreatDetector
        from urllib.parse import urlparse
        
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Empty URL", "Please enter a URL to check")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        detector = ThreatDetector()
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
        except:
            domain = url.lower()
        
        findings = []
        is_suspicious = False
        risk = "SAFE"
        risk_color = "#22d3ee"
        risk_icon = "✅"
        
        brands = ['microsoft', 'paypal', 'amazon', 'apple', 'google', 'fedex', 'dhl', 'ups', 'netflix', 'facebook']
        for brand in brands:
            if brand in domain:
                real_domains = {
                    'microsoft': ['microsoft.com'], 'paypal': ['paypal.com'],
                    'amazon': ['amazon.com'], 'apple': ['apple.com'],
                    'google': ['google.com'], 'fedex': ['fedex.com'],
                    'dhl': ['dhl.com'], 'ups': ['ups.com'],
                    'netflix': ['netflix.com'], 'facebook': ['facebook.com']
                }
                is_real = False
                for real in real_domains.get(brand, []):
                    if domain == real or domain.endswith('.' + real):
                        is_real = True
                        break
                if not is_real:
                    findings.append(f"🚨 FAKE: Domain '{domain}' impersonating {brand.title()}")
                    is_suspicious = True
                break
        
        suspicious_words = ['account', 'verify', 'secure', 'update', 'confirm', 'alert', 'security', 'login', 'signin']
        found_words = [w for w in suspicious_words if w in domain]
        if found_words and not is_suspicious:
            findings.append(f"⚠️ Domain contains: {', '.join(found_words)}")
            is_suspicious = True
        
        if not url.startswith('https://'):
            findings.append("⚠️ Connection not secure (uses HTTP)")
            is_suspicious = True
        
        if is_suspicious:
            risk = "HIGH RISK"
            risk_color = "#f87171"
            risk_icon = "🔴"
        elif detector.is_legitimate_domain(domain):
            risk = "SAFE"
            risk_color = "#22d3ee"
            risk_icon = "✅"
            findings = ["✅ Domain appears legitimate"]
        else:
            risk = "LOW RISK"
            risk_color = "#fbbf24"
            risk_icon = "🟡"
            if not findings:
                findings = ["⚠️ Unknown domain - exercise caution"]
        
        self.result_frame.pack(fill="x", padx=22, pady=(10, 14))
        for widget in self.result_frame.winfo_children():
            widget.destroy()
        
        ctk.CTkLabel(
            self.result_frame,
            text=f"{risk_icon} URL Analysis: {risk}",
            font=("Segoe UI", 15, "bold"),
            text_color=risk_color
        ).pack(anchor="w", padx=14, pady=(10, 4))
        ctk.CTkLabel(
            self.result_frame,
            text=f"URL: {url}",
            font=("Segoe UI", 10),
            text_color="#555577",
            wraplength=550
        ).pack(anchor="w", padx=14, pady=2)
        ctk.CTkFrame(self.result_frame, height=1, fg_color="#2a2a5a").pack(fill="x", padx=14, pady=6)
        ctk.CTkLabel(
            self.result_frame,
            text="Findings:",
            font=("Segoe UI", 12, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=14, pady=(4, 0))
        for finding in findings:
            ctk.CTkLabel(
                self.result_frame,
                text=f"• {finding}",
                font=("Segoe UI", 10),
                text_color=risk_color,
                wraplength=550
            ).pack(anchor="w", padx=20, pady=2)
        
        rec_text = "🚨🚨 DO NOT click this link! This appears to be a phishing attempt." if risk == "HIGH RISK" else "⚠️ Exercise caution with this link" if risk == "LOW RISK" else "✅ This link appears safe"
        ctk.CTkFrame(self.result_frame, height=1, fg_color="#2a2a5a").pack(fill="x", padx=14, pady=6)
        ctk.CTkLabel(
            self.result_frame,
            text=rec_text,
            font=("Segoe UI", 11, "bold"),
            text_color=risk_color
        ).pack(anchor="w", padx=14, pady=(4, 10))
    
    def display_scan_results(self, results):
        self.results_text.delete("1.0", "end")
        if results:
            for result in results:
                self.results_text.insert("end", f"{result}\n\n")
        else:
            self.results_text.insert("1.0", "No results returned. Check your URL scanner configuration.")


# ============================================================
# PHISHING UI - FIXED VERSION
# ============================================================
class PhishingUI:
    def __init__(self, parent, colors, analyze_callback, threats,
                 email_headers=None, urls=None, email_content=None):
        self.parent = parent
        self.colors = colors
        self.analyze_callback = analyze_callback
        self.threats = threats  # ← Uses threats from threat_detector!
        self.email_headers = email_headers or {}
        self.urls = urls or []
        self.email_content = email_content or ""
        self.frame = ctk.CTkFrame(parent, fg_color="transparent")
        self._score = None
        self._risk_indicators = []
        self._keywords_found = []

    def pack(self):
        self.frame.pack(fill="both", expand=True, padx=20, pady=20)
        self.build_ui()

    def _compute_phishing_data(self):
        """Compute phishing data - NOW USES THREATS FROM DETECTOR"""
        score = 0
        indicators = []
        keywords_found = []
        
        # ============================================================
        # USE THE THREATS FROM threat_detector.py
        # ============================================================
        for threat in self.threats:
            # Extract keywords from threats
            if "Phishing keyword:" in threat:
                keyword_match = re.search(r"Phishing keyword: '([^']+)'", threat)
                if keyword_match:
                    keywords_found.append(keyword_match.group(1))
            
            # Build indicators from threats
            if "No authentication" in threat:
                indicators.append("❌ No authentication results - email may be spoofed")
                score += 25
            elif "SPF" in threat or "DKIM" in threat or "DMARC" in threat:
                indicators.append(f"⚠️ {threat}")
                score += 25
            
            if "Login page on suspicious domain" in threat:
                indicators.append("⚠️ Login page on suspicious domain")
                score += 25
            
            if "Urgency tactics" in threat:
                indicators.append("⚠️ Urgency tactics detected")
                score += 20
            
            if "Financial information" in threat:
                indicators.append("⚠️ Financial information requested")
                score += 20
            
            if "Domain spoofing" in threat:
                indicators.append(f"⚠️ {threat}")
                score += 25
            
            if "IMPERSONATION" in threat or "impersonating" in threat:
                indicators.append(f"⚠️ {threat}")
                score += 30
            
            if "Fake sender" in threat:
                indicators.append(f"⚠️ {threat}")
                score += 25
            
            if "Reply-To mismatch" in threat:
                indicators.append(f"⚠️ {threat}")
                score += 25
            
            if "Lookalike" in threat:
                indicators.append(f"⚠️ {threat}")
                score += 20
            
            if "BRAND NEW domain" in threat:
                indicators.append(f"⚠️ {threat}")
                score += 35
            
            if "New domain" in threat:
                indicators.append(f"⚠️ {threat}")
                score += 25
            
            if "LINK MISMATCH" in threat:
                indicators.append(f"⚠️ {threat}")
                score += 30
            
            if "URL shortener" in threat:
                indicators.append(f"⚠️ {threat}")
                score += 15
            
            if "Disposable email" in threat:
                indicators.append(f"⚠️ {threat}")
                score += 15
        
        # ============================================================
        # ADD BONUS FOR MULTIPLE THREATS
        # ============================================================
        threat_count = len(self.threats)
        if threat_count >= 5:
            score += 15
        elif threat_count >= 3:
            score += 10
        
        # ============================================================
        # ALSO CHECK EMAIL BODY DIRECTLY (for keywords)
        # ============================================================
        body = self.email_content if isinstance(self.email_content, str) else ""
        subject = self.email_headers.get("Subject", "")
        full_content = (subject + " " + body).lower()
        
        # Expanded phishing keywords
        phishing_keywords = [
            "verify your account", "confirm your identity", "account suspended",
            "account locked", "account limited", "account compromised",
            "unusual activity", "suspicious activity", "unauthorized access",
            "fraud alert", "security alert", "security breach",
            "urgent action required", "immediate action", "within 24 hours",
            "act now", "limited time", "expires today", "expiring soon",
            "click here", "update your payment", "verify immediately",
            "bank account", "payment method", "billing information",
            "transaction", "subscription", "billing", "paypal",
            "password", "login credentials", "social security"
        ]
        
        for keyword in phishing_keywords:
            if keyword in full_content:
                if keyword not in keywords_found:
                    keywords_found.append(keyword)
                if len(keywords_found) <= 2:
                    score += 15  # First few keywords add more
                else:
                    score += 5   # Additional keywords add less
                if len(keywords_found) >= 8:
                    break
        
        # ============================================================
        # CHECK URGENCY WORDS IN BODY
        # ============================================================
        urgency_words = [
            'immediately', 'urgent', 'within 24 hours', 'act now',
            'limited time', 'expires', 'deadline', 'suspended permanently',
            'verify now', 'as soon as possible'
        ]
        found_urgency = [w for w in urgency_words if w in full_content]
        if len(found_urgency) >= 2:
            if not any("Urgency" in i for i in indicators):
                indicators.append(f"⚠️ Urgency words found: {', '.join(found_urgency[:3])}")
            score += 20
        
        # ============================================================
        # CHECK FINANCIAL WORDS IN BODY
        # ============================================================
        financial_words = [
            'payment', 'bank account', 'credit card', 'transaction',
            'billing', 'subscription', 'invoice', 'refund', 'paypal',
            '$', 'money', 'wire transfer'
        ]
        found_financial = [w for w in financial_words if w in full_content]
        if len(found_financial) >= 2:
            if not any("Financial" in i for i in indicators):
                indicators.append(f"⚠️ Financial keywords found: {', '.join(found_financial[:3])}")
            score += 20
        
        # ============================================================
        # CAP SCORE AT 100
        # ============================================================
        score = min(100, score)
        
        # ============================================================
        # REMOVE DUPLICATE INDICATORS
        # ============================================================
        seen = set()
        unique_indicators = []
        for ind in indicators:
            if ind not in seen:
                seen.add(ind)
                unique_indicators.append(ind)
        
        # Remove duplicate keywords
        keywords_found = list(dict.fromkeys(keywords_found))
        
        return score, unique_indicators, keywords_found

    def _risk_level_text(self, score):
        if score >= 70:
            return "High Risk 🚨", "#f87171"
        elif score >= 40:
            return "Medium Risk ⚠️", "#fbbf24"
        else:
            return "Low Risk ✅", "#22d3ee"

    def _draw_gauge(self, canvas, score, color):
        import math
        w, h = 200, 200
        cx, cy, r = w // 2, h // 2 + 10, 75
        canvas.create_arc(cx - r, cy - r, cx + r, cy + r, start=0, extent=359.9, outline="#2a2a5a", width=14, style="arc")
        extent = (score / 100) * 270
        start = 135
        canvas.create_arc(cx - r, cy - r, cx + r, cy + r, start=start, extent=-extent, outline=color, width=14, style="arc")
        canvas.create_text(cx, cy - 8, text=f"{score}%", font=("Segoe UI", 28, "bold"), fill=color)

    def _render_gauge(self, parent, score, risk_text, risk_color):
        import tkinter as tk
        for w in parent.winfo_children():
            w.destroy()

        try:
            canvas = tk.Canvas(parent, width=200, height=180, bg="#181838", highlightthickness=0)
            canvas.pack(pady=4)
            self._draw_gauge(canvas, score, risk_color)
        except Exception:
            ctk.CTkLabel(
                parent,
                text=f"{score}%",
                font=("Segoe UI", 44, "bold"),
                text_color=risk_color
            ).pack(pady=8)

        ctk.CTkLabel(
            parent,
            text=risk_text,
            font=("Segoe UI", 15, "bold"),
            text_color=risk_color
        ).pack(pady=(2, 2))
        desc = {
            "High Risk 🚨": "This email is highly likely to be a phishing attempt.",
            "Medium Risk ⚠️": "This email shows some suspicious indicators. Exercise caution.",
            "Low Risk ✅": "This email appears relatively safe. Stay vigilant."
        }.get(risk_text, "")
        ctk.CTkLabel(
            parent,
            text=desc,
            font=("Segoe UI", 10),
            text_color="#555577",
            wraplength=200,
            justify="center"
        ).pack(pady=(0, 10))

    def _render_indicators(self, parent, indicators):
        for w in parent.winfo_children():
            w.destroy()
        if not indicators:
            ctk.CTkLabel(
                parent,
                text="✅ No risk indicators found.",
                font=("Segoe UI", 12),
                text_color="#22d3ee"
            ).pack(anchor="w")
            return
        for ind in indicators:
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text="⚠️", font=("Segoe UI", 12)).pack(side="left", padx=(0, 6))
            ctk.CTkLabel(
                row,
                text=ind,
                font=("Segoe UI", 11),
                text_color="#555577",
                wraplength=280,
                justify="left",
                anchor="w"
            ).pack(side="left", fill="x", expand=True)

    def _render_keywords(self, parent, keywords):
        for w in parent.winfo_children():
            w.destroy()
        if not keywords:
            ctk.CTkLabel(
                parent,
                text="No phishing keywords detected.",
                font=("Segoe UI", 11),
                text_color="#555577"
            ).pack(anchor="w")
            return
        pill_row = ctk.CTkFrame(parent, fg_color="transparent")
        pill_row.pack(fill="x", anchor="w")
        for kw in keywords[:10]:
            pill = ctk.CTkFrame(
                pill_row,
                fg_color="#2a2a5a",
                corner_radius=18
            )
            pill.pack(side="left", padx=3, pady=3)
            ctk.CTkLabel(
                pill,
                text=kw,
                font=("Segoe UI", 10),
                text_color="#fbbf24"
            ).pack(padx=10, pady=4)

    def _get_recommendation(self, score, risk_text):
        if "High" in risk_text:
            return "🚨 Do NOT interact with this email. It shows strong signs of a phishing attack. Delete immediately and report to your IT/security team."
        elif "Medium" in risk_text:
            return "⚠️ Exercise caution. Verify the sender through an independent channel before clicking any links or providing information."
        else:
            return "✅ Email appears relatively safe, but always stay vigilant. Avoid clicking unexpected links."

    def _run_and_refresh(self):
        if self.analyze_callback:
            self.analyze_callback()
        score, indicators, keywords = self._compute_phishing_data()
        self._score = score
        self._risk_indicators = indicators
        self._keywords_found = keywords
        risk_text, risk_color = self._risk_level_text(score)

        if hasattr(self, '_gauge_frame'):
            self._render_gauge(self._gauge_frame, score, risk_text, risk_color)
        if hasattr(self, '_ind_container'):
            self._render_indicators(self._ind_container, indicators)
        if hasattr(self, '_kw_container'):
            self._render_keywords(self._kw_container, keywords)
        if hasattr(self, '_rec_label'):
            self._rec_label.configure(text=self._get_recommendation(score, risk_text), text_color=risk_color)

    def update_data(self, threats, email_headers=None, urls=None, email_content=None):
        self.threats = threats or []
        if email_headers is not None:
            self.email_headers = email_headers
        if urls is not None:
            self.urls = urls
        if email_content is not None:
            self.email_content = email_content

    def display_results(self):
        self._run_and_refresh()

    def build_ui(self):
        main_frame = ctk.CTkScrollableFrame(self.frame, fg_color="transparent")
        main_frame.pack(fill="both", expand=True)

        header_card = ctk.CTkFrame(
            main_frame, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        header_card.pack(fill="x", pady=(0, 18))
        header_inner = ctk.CTkFrame(header_card, fg_color="transparent")
        header_inner.pack(fill="x", padx=30, pady=16)
        ctk.CTkLabel(
            header_inner, 
            text="🎯 Phishing Analysis", 
            font=("Segoe UI", 26, "bold"),
            text_color="#ffffff"
        ).pack(side="left")
        ctk.CTkLabel(
            header_inner,
            text="Comprehensive phishing detection and risk assessment",
            font=("Segoe UI", 12),
            text_color="#555577"
        ).pack(side="left", padx=(16, 0))

        ctk.CTkButton(
            main_frame,
            text="🔍 Run Phishing Analysis",
            command=self._run_and_refresh,
            height=44,
            font=("Segoe UI", 14, "bold"),
            fg_color="#6366f1",
            hover_color="#8b5cf6",
            corner_radius=10
        ).pack(fill="x", pady=(0, 16))

        columns_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        columns_frame.pack(fill="both", expand=True)
        columns_frame.grid_columnconfigure(0, weight=1)
        columns_frame.grid_columnconfigure(1, weight=1)

        left = ctk.CTkFrame(columns_frame, fg_color="transparent")
        left.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        right = ctk.CTkFrame(columns_frame, fg_color="transparent")
        right.grid(row=0, column=1, padx=(10, 0), sticky="nsew")

        score_card = ctk.CTkFrame(
            left, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        score_card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(
            score_card, 
            text="📊 Phishing Score", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(14, 4))

        self._gauge_frame = ctk.CTkFrame(score_card, fg_color="transparent")
        self._gauge_frame.pack()

        # Compute initial data
        score, indicators, keywords = self._compute_phishing_data()
        self._score = score
        self._risk_indicators = indicators
        self._keywords_found = keywords
        risk_text, risk_color = self._risk_level_text(score)
        self._render_gauge(self._gauge_frame, score, risk_text, risk_color)

        kw_card = ctk.CTkFrame(
            left, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        kw_card.pack(fill="x")
        ctk.CTkLabel(
            kw_card, 
            text="🔑 Phishing Keywords Found", 
            font=("Segoe UI", 15, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(12, 6))
        self._kw_container = ctk.CTkFrame(kw_card, fg_color="transparent")
        self._kw_container.pack(fill="x", padx=22, pady=(0, 12))
        self._render_keywords(self._kw_container, keywords)

        ind_card = ctk.CTkFrame(
            right, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        ind_card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(
            ind_card, 
            text="⚠️ Risk Indicators", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(12, 6))
        self._ind_container = ctk.CTkFrame(ind_card, fg_color="transparent")
        self._ind_container.pack(fill="x", padx=22, pady=(0, 12))
        self._render_indicators(self._ind_container, indicators)

        rec_card = ctk.CTkFrame(
            right, 
            fg_color="#181838", 
            corner_radius=14,
            border_width=1,
            border_color="#2a2a5a"
        )
        rec_card.pack(fill="x")
        ctk.CTkLabel(
            rec_card, 
            text="💡 Recommendation", 
            font=("Segoe UI", 17, "bold"),
            text_color="#6366f1"
        ).pack(anchor="w", padx=22, pady=(12, 6))
        self._rec_label = ctk.CTkLabel(
            rec_card,
            text=self._get_recommendation(score, risk_text),
            font=("Segoe UI", 12),
            text_color=risk_color,
            wraplength=320,
            justify="left"
        )
        self._rec_label.pack(anchor="w", padx=22, pady=(0, 12))


# ============================================================
# REPORT UI - Premium Glass Design
# ============================================================
class ReportUI:
    def __init__(self, parent, colors, generate_callback, email_file,
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
    
    def build_ui(self):
        main_frame = ctk.CTkFrame(
            self.frame, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        main_frame.pack(fill="both", expand=True)
        
        inner = ctk.CTkFrame(main_frame, fg_color="transparent")
        inner.pack(expand=True, padx=40, pady=30)
        
        ctk.CTkLabel(
            inner, 
            text="📄 Report Generation", 
            font=("Segoe UI", 28, "bold"),
            text_color="#ffffff"
        ).pack(pady=(0, 6))
        ctk.CTkLabel(
            inner,
            text="Generate a comprehensive forensic report for your investigation",
            font=("Segoe UI", 13),
            text_color="#555577"
        ).pack()
        
        if self.email_file:
            file_name = os.path.basename(self.email_file)
            file_frame = ctk.CTkFrame(inner, fg_color="#0d0d22", corner_radius=10)
            file_frame.pack(pady=16)
            ctk.CTkLabel(
                file_frame,
                text=f"📧 {file_name}",
                font=("Segoe UI", 12),
                text_color="#22d3ee"
            ).pack(padx=18, pady=8)
            
            score = self.score
            if score >= 80:
                score_color = "#22d3ee"
                score_label = "✅ SAFE - Low Risk"
                score_desc = "This email appears legitimate. No significant threats detected."
            elif score >= 50:
                score_color = "#fbbf24"
                score_label = "⚠️ CAUTION - Medium Risk"
                score_desc = "This email shows some suspicious indicators. Exercise caution."
            else:
                score_color = "#f87171"
                score_label = "🚨 DANGER - High Risk"
                score_desc = "This email is highly suspicious. Do not interact with it."
            
            score_display = ctk.CTkFrame(inner, fg_color="#0d0d22", corner_radius=12)
            score_display.pack(pady=10, fill="x")
            
            score_inner = ctk.CTkFrame(score_display, fg_color="transparent")
            score_inner.pack(padx=20, pady=15)
            
            ctk.CTkLabel(
                score_inner,
                text="Overall Security Score",
                font=("Segoe UI", 14),
                text_color="#555577"
            ).pack()
            ctk.CTkLabel(
                score_inner,
                text=f"{score}%",
                font=("Segoe UI", 52, "bold"),
                text_color=score_color
            ).pack(pady=(5, 0))
            ctk.CTkLabel(
                score_inner,
                text=score_label,
                font=("Segoe UI", 16, "bold"),
                text_color=score_color
            ).pack()
            ctk.CTkLabel(
                score_inner,
                text=score_desc,
                font=("Segoe UI", 11),
                text_color="#555577",
                wraplength=400
            ).pack(pady=(8, 0))
            
            stats_frame = ctk.CTkFrame(inner, fg_color="transparent")
            stats_frame.pack(pady=8)
            
            stats = [
                ("URLs", len(self.urls), "#fbbf24"),
                ("Attachments", len(self.attachments), "#22d3ee"),
                ("Threats", len(self.threats), "#f87171")
            ]
            for label, count, color in stats:
                pill = ctk.CTkFrame(stats_frame, fg_color="#0d0d22", corner_radius=16)
                pill.pack(side="left", padx=4)
                ctk.CTkLabel(
                    pill,
                    text=f"{label}: {count}",
                    font=("Segoe UI", 11),
                    text_color=color
                ).pack(padx=12, pady=4)
            
            if self.threats:
                threat_frame = ctk.CTkFrame(inner, fg_color="#0d0d22", corner_radius=10)
                threat_frame.pack(fill="x", pady=8)
                
                ctk.CTkLabel(
                    threat_frame,
                    text="⚠️ Detected Threats",
                    font=("Segoe UI", 13, "bold"),
                    text_color="#f87171"
                ).pack(anchor="w", padx=15, pady=(10, 5))
                
                threat_text = "\n".join([f"• {t}" for t in self.threats[:5]])
                if len(self.threats) > 5:
                    threat_text += f"\n• ... and {len(self.threats) - 5} more threats"
                
                ctk.CTkLabel(
                    threat_frame,
                    text=threat_text,
                    font=("Segoe UI", 11),
                    text_color="#555577",
                    justify="left",
                    anchor="w",
                    wraplength=450
                ).pack(anchor="w", padx=15, pady=(0, 10))
            
            ctk.CTkButton(
                inner,
                text="📊 Generate Forensic Report",
                command=self.generate_callback,
                height=50,
                width=320,
                font=("Segoe UI", 15, "bold"),
                fg_color="#6366f1",
                hover_color="#8b5cf6",
                corner_radius=10
            ).pack(pady=20)
            
            ctk.CTkLabel(
                inner,
                text="The report will include header analysis, URL scanning results, phishing detection, and more.",
                font=("Segoe UI", 11),
                text_color="#555577",
                wraplength=500
            ).pack()
        else:
            empty_frame = ctk.CTkFrame(inner, fg_color="#0d0d22", corner_radius=10)
            empty_frame.pack(pady=16, fill="x")
            ctk.CTkLabel(
                empty_frame,
                text="⚠️ No email loaded",
                font=("Segoe UI", 15, "bold"),
                text_color="#f87171"
            ).pack(pady=10)
            ctk.CTkLabel(
                empty_frame,
                text="Upload an email first to generate a report",
                font=("Segoe UI", 12),
                text_color="#555577"
            ).pack(pady=(0, 10))


# ============================================================
# ABOUT UI - Premium Glass Design
# ============================================================
class AboutUI:
    def __init__(self, parent, colors):
        self.parent = parent
        self.colors = colors
        self.frame = ctk.CTkFrame(parent, fg_color="transparent")
    
    def pack(self):
        self.frame.pack(fill="both", expand=True, padx=20, pady=20)
        self.build_ui()
    
    def build_ui(self):
        main_frame = ctk.CTkScrollableFrame(self.frame, fg_color="transparent")
        main_frame.pack(fill="both", expand=True)
        
        hero_card = ctk.CTkFrame(
            main_frame, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        hero_card.pack(fill="x", pady=(0, 16))
        hero_inner = ctk.CTkFrame(hero_card, fg_color="transparent")
        hero_inner.pack(fill="x", padx=35, pady=28)
        
        ctk.CTkLabel(
            hero_inner, 
            text="🛡️ Email Forensics Analysis", 
            font=("Segoe UI", 30, "bold"),
            text_color="#ffffff"
        ).pack(anchor="w")
        ctk.CTkLabel(
            hero_inner,
            text="Digital Evidence Analysis & Phishing Investigation Platform",
            font=("Segoe UI", 14),
            text_color="#6366f1"
        ).pack(anchor="w", pady=(4, 0))
        ctk.CTkFrame(hero_inner, height=2, fg_color="#2a2a5a").pack(fill="x", pady=12)
        ctk.CTkLabel(
            hero_inner,
            text="Email Forensics Tool is a comprehensive security analysis platform designed to investigate suspicious emails and detect potential phishing attacks. It provides in-depth analysis of email headers, extracts and scans URLs, identifies phishing indicators, and generates detailed forensic reports.",
            font=("Segoe UI", 12),
            text_color="#555577",
            justify="left",
            wraplength=850
        ).pack(anchor="w")
        
        features_card = ctk.CTkFrame(
            main_frame, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        features_card.pack(fill="x", pady=(0, 16))
        features_inner = ctk.CTkFrame(features_card, fg_color="transparent")
        features_inner.pack(fill="x", padx=35, pady=20)
        
        ctk.CTkLabel(
            features_inner, 
            text="✨ Key Features", 
            font=("Segoe UI", 20, "bold"),
            text_color="#ffffff"
        ).pack(anchor="w", pady=(0, 12))
        
        features_grid = ctk.CTkFrame(features_inner, fg_color="transparent")
        features_grid.pack(fill="x")
        features_grid.grid_columnconfigure(0, weight=1)
        features_grid.grid_columnconfigure(1, weight=1)
        
        left_features = [
            ("📧 Email Analysis", "Parse and analyze .eml files with detailed header extraction"),
            ("🎯 Phishing Detection", "Identify phishing keywords and suspicious patterns"),
            ("📊 Security Scoring", "Calculate risk score based on threat indicators"),
            ("📄 Report Generation", "Generate comprehensive forensic investigation reports")
        ]
        right_features = [
            ("🔗 URL Scanner", "Extract and scan embedded links for malicious content"),
            ("📎 Attachment Analysis", "Extract and examine email attachments"),
            ("📋 Scan History", "Store and review all previous email analyses"),
            ("🔐 Header Analysis", "Examine email headers for spoofing and authentication issues")
        ]
        
        left_col = ctk.CTkFrame(features_grid, fg_color="transparent")
        left_col.grid(row=0, column=0, padx=(0, 8), sticky="nsew")
        for title, desc in left_features:
            item = ctk.CTkFrame(left_col, fg_color="#0d0d22", corner_radius=8)
            item.pack(fill="x", pady=4)
            ctk.CTkLabel(
                item,
                text=title,
                font=("Segoe UI", 13, "bold"),
                text_color="#6366f1"
            ).pack(anchor="w", padx=14, pady=(8, 2))
            ctk.CTkLabel(
                item,
                text=desc,
                font=("Segoe UI", 10),
                text_color="#555577",
                wraplength=370,
                justify="left"
            ).pack(anchor="w", padx=14, pady=(0, 8))
        
        right_col = ctk.CTkFrame(features_grid, fg_color="transparent")
        right_col.grid(row=0, column=1, padx=(8, 0), sticky="nsew")
        for title, desc in right_features:
            item = ctk.CTkFrame(right_col, fg_color="#0d0d22", corner_radius=8)
            item.pack(fill="x", pady=4)
            ctk.CTkLabel(
                item,
                text=title,
                font=("Segoe UI", 13, "bold"),
                text_color="#6366f1"
            ).pack(anchor="w", padx=14, pady=(8, 2))
            ctk.CTkLabel(
                item,
                text=desc,
                font=("Segoe UI", 10),
                text_color="#555577",
                wraplength=370,
                justify="left"
            ).pack(anchor="w", padx=14, pady=(0, 8))
        
        footer_card = ctk.CTkFrame(
            main_frame, 
            fg_color="#181838", 
            corner_radius=16,
            border_width=1,
            border_color="#2a2a5a"
        )
        footer_card.pack(fill="x")
        footer_inner = ctk.CTkFrame(footer_card, fg_color="transparent")
        footer_inner.pack(fill="x", padx=35, pady=16)
        
        version_row = ctk.CTkFrame(footer_inner, fg_color="transparent")
        version_row.pack(fill="x")
        ctk.CTkLabel(
            version_row,
            text="📌 Version 1.0.0",
            font=("Segoe UI", 12, "bold"),
            text_color="#6366f1"
        ).pack(side="left")
        ctk.CTkLabel(
            version_row,
            text="|",
            font=("Segoe UI", 12),
            text_color="#555577"
        ).pack(side="left", padx=8)
        ctk.CTkLabel(
            version_row,
            text="📅 June 2026",
            font=("Segoe UI", 12),
            text_color="#fbbf24"
        ).pack(side="left")
        
        ctk.CTkFrame(footer_inner, height=1, fg_color="#2a2a5a").pack(fill="x", pady=8)
        ctk.CTkLabel(
            footer_inner,
            text="Email Forensics Tool — Protecting Digital Communications",
            font=("Segoe UI", 11),
            text_color="#555577"
        ).pack(anchor="w")
        ctk.CTkLabel(
            footer_inner,
            text="© 2026 Email Forensics Tool | All Rights Reserved",
            font=("Segoe UI", 10),
            text_color="#444466"
        ).pack(anchor="w")