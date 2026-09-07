import re
import email
from email import policy
from email.parser import BytesParser
from html import unescape

class EmailParser:
    def clean_html(self, html_text):
        if not html_text:
            return ""
        text = unescape(html_text)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL)
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    
    def parse_email(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                msg = BytesParser(policy=policy.default).parse(f)
            
            headers = dict(msg.items())
            body = ""
            html_body = ""
            
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        body = part.get_content()
                    elif content_type == "text/html":
                        html_body = part.get_content()
                        if not body:
                            body = self.clean_html(html_body)
            else:
                content_type = msg.get_content_type()
                if content_type == "text/plain":
                    body = msg.get_content()
                elif content_type == "text/html":
                    html_body = msg.get_content()
                    body = self.clean_html(html_body)
            
            email_content = {"body": body, "raw": msg, "raw_body": html_body}
            
            # Extract URLs from both plain text and HTML
            url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s<>"\']*'
            urls = list(set(re.findall(url_pattern, body if body else "")))
            
            # Also extract from HTML if available
            if html_body:
                html_urls = re.findall(url_pattern, html_body)
                urls.extend(html_urls)
                urls = list(set(urls))
            
            # Extract attachments with content for hashing
            attachments = []
            for part in msg.walk():
                if part.get_content_disposition() == "attachment":
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'name': filename,
                            'content': part.get_payload(decode=True)
                        })
            
            return headers, email_content, urls, attachments
        
        except Exception as e:
            print(f"Error: {e}")
            return None