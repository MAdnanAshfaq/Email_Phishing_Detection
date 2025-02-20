from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime
import imaplib
import email
from email.header import decode_header

app = Flask(__name__)
CORS(app)

# Configuration
YAHOO_EMAIL = "hiqahsh123@yahoo.com"
YAHOO_PASSWORD = "xbqvhwniraaysxhy"

class EmailAnalyzer:
    def __init__(self):
        self.mail = None

    def connect_to_yahoo(self):
        try:
            # Close existing connection if any
            if self.mail:
                try:
                    self.mail.close()
                    self.mail.logout()
                except:
                    pass
            
            # Create new connection
            self.mail = imaplib.IMAP4_SSL("imap.mail.yahoo.com")
            self.mail.login(YAHOO_EMAIL, YAHOO_PASSWORD)
            return True
        except Exception as e:
            print(f"Connection error: {str(e)}")
            self.mail = None
            return False

    def get_email_headers(self):
        try:
            # Always reconnect to ensure fresh connection
            if not self.connect_to_yahoo():
                return None
            
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
            
            return headers_list[::-1]  # Reverse to show newest first
        except Exception as e:
            print(f"Error getting headers: {str(e)}")
            return None
        finally:
            # Always cleanup connection
            try:
                if self.mail:
                    self.mail.close()
                    self.mail.logout()
            except:
                pass

analyzer = EmailAnalyzer()

@app.route('/')
def home():
    return jsonify({
        'status': 'running',
        'message': 'API is working'
    })

@app.route('/api/email/complete-analysis')
def complete_analysis():
    try:
        headers = analyzer.get_email_headers()
        if headers:
            return jsonify({
                'headers': headers,
                'vendorAnalysis': {'status': 'pending'},
                'maliciousUrls': [],
                'timestamp': datetime.now().isoformat()
            })
        return jsonify({
            'error': 'Failed to fetch emails',
            'timestamp': datetime.now().isoformat()
        }), 500
    except Exception as e:
        print(f"Error in complete analysis: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/email/vendor-analysis')
def vendor_analysis():
    try:
        return jsonify({
            'vendorAnalysis': {'status': 'pending'},
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/email/malicious-urls')
def malicious_urls():
    try:
        return jsonify({
            'maliciousUrls': [],
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)