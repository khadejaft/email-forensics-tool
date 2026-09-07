import customtkinter as ctk
from tkinter import filedialog, messagebox
from email_parser import EmailParser
from threat_detector import ThreatDetector
from report_generator import ReportGenerator
from ui_components import DashboardUI, AnalysisUI, HeadersUI, URLScannerUI, PhishingUI, AboutUI, HistoryUI
from report_ui import ReportUI  # Make sure this is importing from report_ui.py
import os
import json
from datetime import datetime

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class EmailForensicsApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Email Forensics Tool - Advanced Threat Detection")
        self.root.state('zoomed')
        self.root.update_idletasks()
        
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        self.root.geometry(f"{screen_width}x{screen_height}+0+0")
        self.root.after(10, lambda: self.root.state('zoomed'))
        
        self.email_parser = EmailParser()
        self.threat_detector = ThreatDetector()
        self.report_generator = ReportGenerator()
        
        self.email_file = None
        self.email_content = None
        self.email_headers = {}
        self.urls_found = []
        self.attachments = []
        self.threats_found = []
        self.informational_msgs = []
        
        # History storage
        self.scan_history = []
        self.load_history()
        
        self.colors = {
            "bg": "#0f172a", "card": "#111c2e", "sidebar": "#0b1220",
            "muted": "#94a3b8", "accent": "#3b82f6", "success": "#10b981",
            "danger": "#ef4444", "warning": "#f59e0b"
        }
        
        self.current_frame = None
        self.dashboard_ui = None
        self.build_ui()
    
    def load_history(self):
        history_file = "scan_history.json"
        if os.path.exists(history_file):
            try:
                with open(history_file, 'r') as f:
                    self.scan_history = json.load(f)
            except:
                self.scan_history = []
    
    def save_history(self):
        history_file = "scan_history.json"
        with open(history_file, 'w') as f:
            json.dump(self.scan_history, f, indent=2)
    
    def add_to_history(self, email_file, headers, urls, attachments, threats):
        risk_analysis = self.threat_detector.calculate_risk_score(threats, headers, urls, attachments)
        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "file": os.path.basename(email_file) if email_file else "Unknown",
            "from": headers.get("From", "Unknown")[:100],
            "to": headers.get("To", "Unknown")[:100],
            "subject": headers.get("Subject", "No Subject")[:100],
            "urls": len(urls),
            "attachments": len(attachments),
            "threats": len(threats),
            "threat_list": threats[:10],
            "score": risk_analysis['confidence']
        }
        self.scan_history.insert(0, record)
        self.scan_history = self.scan_history[:50]
        self.save_history()
    
    def build_ui(self):
        self.main_container = ctk.CTkFrame(self.root, fg_color="#0a0a1a")
        self.main_container.pack(fill="both", expand=True)
        
        # Gradient Sidebar with premium dark theme
        self.sidebar = ctk.CTkFrame(
            self.main_container, 
            width=280, 
            fg_color="#0d0d22", 
            corner_radius=0
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        
        # Logo Section with gradient effect
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.pack(pady=30)
        ctk.CTkLabel(logo_frame, text="🛡️", font=("Segoe UI", 40)).pack()
        ctk.CTkLabel(
            logo_frame, 
            text="EMAIL FORENSICS", 
            font=("Segoe UI", 18, "bold"), 
            text_color="#6366f1"
        ).pack()
        ctk.CTkLabel(
            logo_frame, 
            text="Advanced Threat Detection", 
            font=("Segoe UI", 11), 
            text_color="#555577"
        ).pack()
        
        ctk.CTkFrame(self.sidebar, height=1, fg_color="#2a2a5a").pack(fill="x", padx=20, pady=20)
        
        # Menu buttons with glass effect
        self.menu_buttons = {}
        menu_items = [
            (" Dashboard", self.show_dashboard, "📊"),
            (" Email Analysis", self.show_analysis, "📧"),
            (" Header Analysis", self.show_headers, "📋"),
            (" URL Scanner", self.show_url_scanner, "🔗"),
            (" Phishing Detection", self.show_phishing, "🎯"),
            (" Scan History", self.show_history, "📜"),
            (" Generate Report", self.show_report, "📄"),
            (" About", self.show_about, "ℹ️")
        ]
        
        for text, command, icon in menu_items:
            btn_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
            btn_frame.pack(pady=3, padx=20, fill="x")
            
            btn = ctk.CTkButton(
                btn_frame, 
                text=f"{icon} {text}", 
                command=command, 
                width=240, 
                height=45,
                fg_color="transparent", 
                hover_color="#2a2a5a", 
                text_color="#8888bb",
                anchor="w", 
                font=("Segoe UI", 14),
                corner_radius=10
            )
            btn.pack(fill="x")
            self.menu_buttons[text] = btn
        
        ctk.CTkFrame(self.sidebar, height=1, fg_color="#2a2a5a").pack(fill="x", padx=20, pady=20)
        
        # Status indicator with pulse effect
        status_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        status_frame.pack(pady=10)
        
        status_dot = ctk.CTkFrame(
            status_frame,
            width=8,
            height=8,
            fg_color="#22d3ee",
            corner_radius=4
        )
        status_dot.pack(side="left", padx=(0, 8))
        
        self.status_indicator = ctk.CTkLabel(
            status_frame, 
            text="System Ready", 
            font=("Segoe UI", 11),
            text_color="#22d3ee"
        )
        self.status_indicator.pack(side="left")
        
        # Content area with gradient background
        self.content_area = ctk.CTkFrame(
            self.main_container, 
            fg_color="#0a0a1a"
        )
        self.content_area.pack(side="left", fill="both", expand=True)
        
        # Top bar with glass effect
        self.top_bar = ctk.CTkFrame(
            self.content_area, 
            height=60, 
            fg_color="#111128", 
            corner_radius=0
        )
        self.top_bar.pack(fill="x")
        self.top_bar.pack_propagate(False)
        
        # Page title with gradient text effect
        self.page_title = ctk.CTkLabel(
            self.top_bar, 
            text="Dashboard", 
            font=("Segoe UI", 22, "bold"), 
            text_color="#ffffff"
        )
        self.page_title.pack(side="left", padx=30, pady=15)
        
        # Create dashboard
        self.dashboard_ui = DashboardUI(
            self.content_area, 
            self.colors, 
            self.upload_email, 
            self.analyze_email,
            self.scan_urls, 
            self.generate_report, 
            self.reset_data,
            self.email_headers, 
            self.urls_found, 
            self.attachments, 
            self.threats_found,
            self.show_history
        )
        self.dashboard_ui.email_file = self.email_file
        self.dashboard_ui.email_content = self.email_content
        self.dashboard_ui.pack()
        
        self.current_frame = self.dashboard_ui.frame
    
    def hide_current_frame(self):
        if self.current_frame:
            self.current_frame.pack_forget()
    
    def show_frame(self, frame):
        self.hide_current_frame()
        frame.pack(fill="both", expand=True)
        self.current_frame = frame
    
    def highlight_menu(self, active_text):
        for text, btn in self.menu_buttons.items():
            if text == active_text:
                btn.configure(fg_color="#2a2a5a", text_color="#ffffff")
            else:
                btn.configure(fg_color="transparent", text_color="#8888bb")
    
    def log_activity(self, message):
        if self.dashboard_ui:
            self.dashboard_ui.update_activity_log(message)
    
    def show_dashboard(self):
        self.page_title.configure(text="Dashboard")
        self.highlight_menu(" Dashboard")
        self.show_frame(self.dashboard_ui.frame)
        self.dashboard_ui.refresh_display()
    
    def show_analysis(self):
        self.page_title.configure(text="Email Analysis")
        self.highlight_menu(" Email Analysis")
        
        analysis_ui = AnalysisUI(
            self.content_area, 
            self.colors, 
            self.email_content, 
            self.email_headers, 
            self.upload_email
        )
        analysis_ui.email_file = self.email_file
        analysis_ui.attachments = self.attachments
        analysis_ui.threats = self.threats_found
        analysis_ui.urls = self.urls_found
        analysis_ui.pack()
        self.show_frame(analysis_ui.frame)
    
    def show_headers(self):
        self.page_title.configure(text="Header Analysis")
        self.highlight_menu(" Header Analysis")
        
        headers_ui = HeadersUI(
            self.content_area, 
            self.colors, 
            self.email_headers, 
            self.upload_email
        )
        headers_ui.pack()
        self.show_frame(headers_ui.frame)
     
    def show_url_scanner(self):
        self.page_title.configure(text="URL Scanner")
        self.highlight_menu(" URL Scanner")
        
        url_ui = URLScannerUI(
            self.content_area, 
            self.colors, 
            self.urls_found, 
            self.scan_urls
        )
        url_ui.pack()
        self.show_frame(url_ui.frame)
    
    def show_phishing(self):
        self.page_title.configure(text="Phishing Detection")
        self.highlight_menu(" 🎣 Phishing Detection")
        
        phishing_ui = PhishingUI(
            self.content_area, 
            self.colors, 
            self.analyze_phishing, 
            self.threats_found
        )
        phishing_ui.pack()
        self.show_frame(phishing_ui.frame)
    
    def show_history(self):
        self.page_title.configure(text="Scan History")
        self.highlight_menu(" 📋 Scan History")
        
        history_ui = HistoryUI(
            self.content_area, 
            self.colors, 
            self.scan_history, 
            self.view_history_record, 
            self.reset_data
        )
        history_ui.pack()
        self.show_frame(history_ui.frame)
    
    def view_history_record(self, record):
        temp_headers = {
            "From": record.get("from", "Unknown"),
            "To": "History Record",
            "Subject": record.get("subject", "No Subject"),
            "Date": record.get("timestamp", "Unknown")
        }
        
        class HistoryAnalysisUI(AnalysisUI):
            def build_ui(self):
                main_frame = ctk.CTkScrollableFrame(self.frame, fg_color="transparent")
                main_frame.pack(fill="both", expand=True)
                
                ctk.CTkLabel(
                    main_frame, 
                    text="Email Analysis Overview (History)", 
                    font=("Segoe UI", 28, "bold"), 
                    text_color="#ffffff"
                ).pack(anchor="w", pady=(0, 20))
                
                columns_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
                columns_frame.pack(fill="both", expand=True)
                
                left_column = ctk.CTkFrame(columns_frame, fg_color="transparent")
                left_column.pack(side="left", fill="both", expand=True, padx=(0, 10))
                
                details_card = ctk.CTkFrame(
                    left_column, 
                    fg_color="#181838", 
                    corner_radius=12,
                    border_width=1,
                    border_color="#2a2a5a"
                )
                details_card.pack(fill="x", pady=(0, 15))
                
                ctk.CTkLabel(
                    details_card, 
                    text="Email Details", 
                    font=("Segoe UI", 20, "bold"), 
                    text_color="#6366f1"
                ).pack(anchor="w", padx=20, pady=(15, 10))
                
                details = [
                    ("From:", record.get("from", "Unknown")), 
                    ("To:", "History Record"), 
                    ("Subject:", record.get("subject", "No Subject")), 
                    ("Date:", record.get("timestamp", "Unknown")),
                    ("Attachment:", f"{record.get('attachments', 0)} attachment(s)"),
                    ("Email Size:", "N/A")
                ]
                
                for label, value in details:
                    row_frame = ctk.CTkFrame(details_card, fg_color="transparent")
                    row_frame.pack(fill="x", padx=20, pady=5)
                    ctk.CTkLabel(
                        row_frame, 
                        text=label, 
                        width=100, 
                        anchor="w", 
                        font=("Segoe UI", 14, "bold"), 
                        text_color="#555577"
                    ).pack(side="left")
                    ctk.CTkLabel(
                        row_frame, 
                        text=value, 
                        anchor="w", 
                        font=("Segoe UI", 13), 
                        text_color="#ffffff", 
                        wraplength=450
                    ).pack(side="left", padx=10, fill="x", expand=True)
                
                right_column = ctk.CTkFrame(columns_frame, fg_color="transparent")
                right_column.pack(side="right", fill="both", expand=True, padx=(10, 0))
                
                summary_card = ctk.CTkFrame(
                    right_column, 
                    fg_color="#181838", 
                    corner_radius=12,
                    border_width=1,
                    border_color="#2a2a5a"
                )
                summary_card.pack(fill="x", pady=(0, 15))
                
                ctk.CTkLabel(
                    summary_card, 
                    text="Analysis Summary", 
                    font=("Segoe UI", 20, "bold"), 
                    text_color="#6366f1"
                ).pack(anchor="w", padx=20, pady=(15, 10))
                
                status_text = f"Email analysis completed.\n{record.get('threats', 0)} potential issue(s) detected."
                status_color = "#fbbf24" if record.get('threats', 0) > 0 else "#22d3ee"
                
                ctk.CTkLabel(
                    summary_card, 
                    text=status_text, 
                    font=("Segoe UI", 13), 
                    text_color=status_color, 
                    justify="left"
                ).pack(anchor="w", padx=20, pady=(0, 15))
                
                score_card = ctk.CTkFrame(
                    right_column, 
                    fg_color="#181838", 
                    corner_radius=12,
                    border_width=1,
                    border_color="#2a2a5a"
                )
                score_card.pack(fill="x")
                
                ctk.CTkLabel(
                    score_card, 
                    text="Overall Score", 
                    font=("Segoe UI", 18, "bold"), 
                    text_color="#6366f1"
                ).pack(anchor="w", padx=20, pady=(15, 10))
                
                score = record.get('score', 0)
                score_color = "#22d3ee" if score >= 80 else "#fbbf24" if score >= 50 else "#f87171"
                
                ctk.CTkLabel(
                    score_card, 
                    text=f"{score}%", 
                    font=("Segoe UI", 52, "bold"), 
                    text_color=score_color
                ).pack(pady=(20, 5))
                ctk.CTkLabel(
                    score_card, 
                    text="Overall Score", 
                    font=("Segoe UI", 13), 
                    text_color="#555577"
                ).pack(pady=(0, 20))
                
                if record.get('threats', 0) > 0 and record.get('threat_list'):
                    threats_card = ctk.CTkFrame(
                        right_column, 
                        fg_color="#181838", 
                        corner_radius=12,
                        border_width=1,
                        border_color="#2a2a5a"
                    )
                    threats_card.pack(fill="x", pady=(15, 0))
                    ctk.CTkLabel(
                        threats_card, 
                        text="Detected Threats", 
                        font=("Segoe UI", 18, "bold"), 
                        text_color="#f87171"
                    ).pack(anchor="w", padx=20, pady=(15, 10))
                    for threat in record.get('threat_list', [])[:5]:
                        ctk.CTkLabel(
                            threats_card, 
                            text=f"• {threat}", 
                            font=("Segoe UI", 12), 
                            text_color="#555577", 
                            wraplength=280, 
                            justify="left"
                        ).pack(anchor="w", padx=20, pady=5)
        
        history_analysis = HistoryAnalysisUI(
            self.content_area, 
            self.colors, 
            None, 
            temp_headers, 
            self.upload_email
        )
        history_analysis.pack()
        self.show_frame(history_analysis.frame)
    
    def show_report(self):
        self.page_title.configure(text="Generate Report")
        self.highlight_menu(" Generate Report")
        
        risk_analysis = self.threat_detector.calculate_risk_score(
            self.threats_found, self.email_headers, self.urls_found, self.attachments
        )
        score = risk_analysis['confidence']
        
        report_ui = ReportUI(
            self.content_area, 
            self.colors, 
            self.generate_report, 
            self.email_file,
            self.email_headers,
            self.urls_found,
            self.attachments,
            self.threats_found,
            score
        )
        report_ui.pack()
        self.show_frame(report_ui.frame)
    
    def show_about(self):
        self.page_title.configure(text="About")
        self.highlight_menu(" About")
        
        about_ui = AboutUI(self.content_area, self.colors)
        about_ui.pack()
        self.show_frame(about_ui.frame)
    
    def upload_email(self):
        file_path = filedialog.askopenfilename(filetypes=[("Email files", "*.eml"), ("All files", "*.*")])
        if file_path:
            self.email_file = file_path
            self.log_activity(f"Selected file: {os.path.basename(file_path)}")
            
            result = self.email_parser.parse_email(file_path)
            if result:
                self.email_headers, self.email_content, self.urls_found, self.attachments = result
                self.log_activity(f"Email parsed successfully")
                self.log_activity(f"Found {len(self.urls_found)} URLs and {len(self.attachments)} attachments")
                
                self.threat_detector.attachments = self.attachments
                
                self.threats_found, self.informational_msgs = self.threat_detector.detect_all_threats(
                    self.email_content, self.email_headers, self.urls_found
                )
                
                for msg in self.informational_msgs:
                    self.log_activity(msg)
                
                self.log_activity(f"Threat detection complete: {len(self.threats_found)} threats found")
                
                self.add_to_history(
                    file_path, self.email_headers, self.urls_found, 
                    self.attachments, self.threats_found
                )
                self.log_activity(f"Scan saved to history")
                
                if self.dashboard_ui:
                    self.dashboard_ui.update_stats(
                        self.email_headers, self.urls_found, self.attachments, 
                        self.threats_found, self.email_file
                    )
                
                if self.threats_found:
                    self.status_indicator.configure(text="⚠️ Threats Detected", text_color="#f87171")
                    self.log_activity(f"⚠️ {len(self.threats_found)} threats detected in this email")
                    for threat in self.threats_found[:3]:
                        self.log_activity(f"  - {threat[:80]}")
                else:
                    self.status_indicator.configure(text="✅ Email Loaded", text_color="#22d3ee")
                    self.log_activity("✓ No threats detected")
                
                messagebox.showinfo("Success", f"Email loaded: {os.path.basename(file_path)}")
                self.show_dashboard()
            else:
                self.log_activity("❌ Failed to parse email file")
                messagebox.showerror("Error", "Failed to parse email file")
    
    def analyze_email(self):
        if not self.email_file:
            messagebox.showwarning("No Email", "Upload an email first")
            return
        
        self.log_activity("Starting comprehensive email analysis...")
        self.threat_detector.attachments = self.attachments
        self.threats_found, self.informational_msgs = self.threat_detector.detect_all_threats(
            self.email_content, self.email_headers, self.urls_found
        )
        
        for msg in self.informational_msgs:
            self.log_activity(msg)
        
        self.log_activity(f"Analysis completed. Found {len(self.threats_found)} threats")
        
        if self.dashboard_ui:
            self.dashboard_ui.update_stats(
                self.email_headers, self.urls_found, self.attachments, 
                self.threats_found, self.email_file
            )
        
        messagebox.showinfo("Analysis Complete", f"Found {len(self.threats_found)} threats")
        self.show_analysis()
    
    def scan_urls(self):
        if not self.urls_found:
            messagebox.showinfo("Info", "No URLs found in this email")
            return
        
        self.log_activity(f"Scanning {len(self.urls_found)} URLs...")
        self.root.update_idletasks()
        
        results = self.threat_detector.scan_urls(self.urls_found)
        self.log_activity(f"URL scan completed")
        
        for widget in self.content_area.winfo_children():
            if hasattr(widget, 'display_scan_results'):
                widget.display_scan_results(results)
                break
        
        result_text = "\n".join(results[:10])
        if len(results) > 10:
            result_text += f"\n... and {len(results) - 10} more results"
        
        messagebox.showinfo("URL Scan Complete", f"Scanned {len(results)} URLs\n\n{result_text[:500]}")
    
    def analyze_phishing(self):
        if not self.email_file:
            messagebox.showwarning("No Email", "Upload an email first")
            return
        
        self.log_activity("Running phishing analysis...")
        self.threat_detector.attachments = self.attachments
        self.threats_found, self.informational_msgs = self.threat_detector.detect_all_threats(
            self.email_content, self.email_headers, self.urls_found
        )
        
        for msg in self.informational_msgs:
            self.log_activity(msg)
        
        self.log_activity(f"Phishing analysis complete: {len(self.threats_found)} threats found")
        
        if self.dashboard_ui:
            self.dashboard_ui.update_stats(
                self.email_headers, self.urls_found, self.attachments, 
                self.threats_found, self.email_file
            )
        
        messagebox.showinfo("Phishing Analysis", f"Found {len(self.threats_found)} potential threats")
        self.show_phishing()
    
    def generate_report(self):
        if not self.email_file:
            messagebox.showwarning("No Email", "Upload an email first")
            return
        
        self.log_activity("Generating forensic report...")
        risk_analysis = self.threat_detector.calculate_risk_score(
            self.threats_found, self.email_headers, self.urls_found, self.attachments
        )
        report_file = self.report_generator.generate_report(
            self.email_file, self.email_headers, self.urls_found, 
            self.attachments, self.threats_found, risk_analysis
        )
        
        if report_file:
            self.log_activity(f"Report generated: {os.path.basename(report_file)}")
            messagebox.showinfo("Report Generated", f"Report saved to: {report_file}")
            self.show_report()
    
    def reset_data(self):
        if messagebox.askyesno("Confirm Reset", "Clear all data and history?"):
            self.log_activity("Clearing all data...")
            self.email_file = None
            self.email_content = None
            self.email_headers = {}
            self.urls_found = []
            self.attachments = []
            self.threats_found = []
            self.informational_msgs = []
            self.scan_history = []
            self.save_history()
            self.status_indicator.configure(text="System Ready", text_color="#22d3ee")
            self.log_activity("All data and history cleared. Ready for new analysis.")
            
            if self.dashboard_ui:
                self.dashboard_ui.reset_stats()
            
            messagebox.showinfo("Reset Complete", "All data and history have been cleared")
            self.show_dashboard()
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = EmailForensicsApp()
    app.run()
    