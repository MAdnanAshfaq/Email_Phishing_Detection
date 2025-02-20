from flask import Flask, jsonify
from flask_cors import CORS
import imaplib
import email
from email.header import decode_header
import requests
import json
from datetime import datetime
import re
from typing import Dict, List, Any
import os

app = Flask(__name__)
CORS(app)

# Configuration
YAHOO_EMAIL = "hiqahsh123@yahoo.com"
YAHOO_PASSWORD = "xbqvhwniraaysxhy"
VIRUSTOTAL_API_KEY = "e159bd3230294963cb4e9bab76d45bb4abba4b5951b4ff1a6a2ed825d25bb1fb"

class EmailAnalyzer:
    def __init__(self):
        self.mail = None
        self.vt_headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Accept": "application/json"
        }

    def connect_to_yahoo(self) -> bool:
        try:
            self.mail = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
            self.mail.login(YAHOO_EMAIL, YAHOO_PASSWORD)
            return True
        except Exception as e:
            print(f"Connection error: {str(e)}")
            return False

    def get_email_headers(self) -> List[Dict[str, str]]:
        if not self.mail:
            if not self.connect_to_yahoo():
                return None
        
        try:
            self.mail.select('INBOX')
            _, messages = self.mail.search(None, 'ALL')
            headers_list = []
            
            for num in messages[0].split()[-5:]:  # Get last 5 emails
                _, msg_data = self.mail.fetch(num, '(RFC822)')
                email_body = msg_data[0][1]
                email_message = email.message_from_bytes(email_body)
                
                headers = {}
                for header in ['subject', 'from', 'to', 'date']:
                    value = email_message[header]
                    if value:
                        headers[header] = str(value)
                headers_list.append(headers)
            
            return headers_list
        except Exception as e:
            print(f"Error getting headers: {str(e)}")
            return None

    def analyze_with_virustotal(self, content: str) -> Dict[str, Any]:
        url = "https://www.virustotal.com/api/v3/urls"
        
        # Submit URL for analysis
        response = requests.post(
            url,
            headers=self.vt_headers,
            data={"url": content}
        )
        analysis_id = response.json()["data"]["id"]
        
        # Get analysis results
        result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        results = requests.get(result_url, headers=self.vt_headers)
        
        return results.json()["data"]["attributes"]["results"]

    def extract_urls(self, email_content: str) -> List[str]:
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, email_content)

analyzer = EmailAnalyzer()

# Add root route
@app.route('/')
def home():
    return jsonify({
        'status': 'running',
        'endpoints': {
            'complete_analysis': '/api/email/complete-analysis',
            'vendor_analysis': '/api/email/vendor-analysis',
            'malicious_urls': '/api/email/malicious-urls'
        }
    })

@app.route('/api/email/complete-analysis')
def complete_analysis():
    try:
        headers = analyzer.get_email_headers()
        if headers is None:
            return jsonify({'error': 'Failed to fetch email headers'}), 500
            
        return jsonify({
            'headers': headers,
            'vendorAnalysis': {},  # Simplified for testing
            'maliciousUrls': [],   # Simplified for testing
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        print(f"Error in complete analysis: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/email/vendor-analysis')
def vendor_analysis():
    try:
        return jsonify({
            'vendorAnalysis': {},  # Simplified for testing
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/email/malicious-urls')
def malicious_urls():
    try:
        return jsonify({
            'maliciousUrls': [],  # Simplified for testing
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000) 