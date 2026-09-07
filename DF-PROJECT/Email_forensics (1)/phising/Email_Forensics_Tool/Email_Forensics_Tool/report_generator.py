import os
from datetime import datetime

class ReportGenerator:
    def generate_report(self, email_file, headers, urls, attachments, threats, risk_analysis=None):
        report_dir = "forensic_reports"
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(report_dir, f"forensic_report_{timestamp}.txt")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("EMAIL FORENSICS ANALYSIS REPORT - ADVANCED THREAT DETECTION\n")
            f.write("="*80 + "\n\n")
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Analyzed File: {os.path.basename(email_file)}\n\n")
            
            # Risk Summary
            if risk_analysis:
                f.write("-"*80 + "\n")
                f.write("RISK ASSESSMENT SUMMARY\n")
                f.write("-"*80 + "\n")
                f.write(f"Risk Score: {risk_analysis['risk_score']}/100\n")
                f.write(f"Confidence Score: {risk_analysis['confidence']}/100\n")
                f.write(f"Risk Level: {risk_analysis['risk_level']}\n\n")
            
            f.write("-"*80 + "\n")
            f.write("EMAIL HEADERS\n")
            f.write("-"*80 + "\n")
            for key, value in list(headers.items())[:15]:
                f.write(f"{key}: {value}\n")
            
            f.write("\n" + "-"*80 + "\n")
            f.write("EXTRACTED URLS\n")
            f.write("-"*80 + "\n")
            for url in urls:
                f.write(f"• {url}\n")
            
            f.write("\n" + "-"*80 + "\n")
            f.write("ATTACHMENTS\n")
            f.write("-"*80 + "\n")
            for att in attachments:
                if isinstance(att, dict):
                    f.write(f"• {att.get('name', 'Unknown')}\n")
                else:
                    f.write(f"• {att}\n")
            
            f.write("\n" + "-"*80 + "\n")
            f.write("THREAT DETECTION RESULTS\n")
            f.write("-"*80 + "\n")
            if threats:
                for threat in threats:
                    f.write(f"⚠️ {threat}\n")
                f.write(f"\nTotal Threats: {len(threats)}\n")
            else:
                f.write("✅ No threats detected\n")
            
            f.write("\n" + "-"*80 + "\n")
            f.write("RECOMMENDATIONS\n")
            f.write("-"*80 + "\n")
            if threats:
                f.write("• DO NOT click any links in this email\n")
                f.write("• DO NOT download or open any attachments\n")
                f.write("• DO NOT reply to this email\n")
                f.write("• Report this email as phishing to your IT department\n")
                f.write("• Delete the email immediately\n")
            else:
                f.write("• Email appears safe, but always verify suspicious requests\n")
                f.write("• Be cautious of unexpected attachments or links\n")
        
        return report_file