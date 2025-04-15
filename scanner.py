# --- REQUIREMENTS FOR THIS SCANNER TO WORK ---
 
"""
The following are the requirements for the code to work as a threat scanner. Seeing as how this code would
be executed locally on the client's computer, and to protect the client's privacythis code is mostly demonstrative
for the purpose of this project. As such, placeholders are used in place of actual API's, authentication tokens, and
login credentials to prevent the misuse of the client's personal information. The following comments are descriptions of
what would be needed for the scanner to run succesfully on a local host.  
"""
 
 
# 1. Google Cloud Project:
#    - Gmail API must be enabled.
#    - OAuth 2.0 Client ID credentials for "Web application" must be created.
# 2. Environment Variables (.env file in the same directory):
#    - GOOGLE_CLIENT_ID:  OAuth Client ID from Google Cloud Console.
#    - GOOGLE_CLIENT_SECRET:  OAuth Client Secret from Google Cloud Console.
#    - FLASK_SECRET_KEY: A strong, random secret key for Flask session management.
# 3. Redirect URI Configuration:
#    - The redirect URI listed in CLIENT_SECRETS_FILE_CONTENT (e.g., "https://127.0.0.1:5000/callback")
#      MUST EXACTLY MATCH one of the Authorized redirect URIs in the Google Cloud OAuth client settings.
# 4. Python Packages Installed:
#    - pip install Flask google-api-python-client google-auth-oauthlib google-auth-httplib2 requests python-dotenv
# 5. Local HTTPS (if using https redirect URI):
#    - Running with ssl_context='adhoc' requires accepting browser security warnings locally.
# 6. User Consent:
#    - The user must grant permission via the Google consent screen upon first login.
# LIMITATIONS:
# - Scan results are stored in memory.
# - Scanning is synchronous
# - Error handling is minimal. Use only for local testing/demonstration.
# --------------------------------------------------
 
 
import os
import logging
from flask import Flask, redirect, request, session, url_for, jsonify, render_template_string
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import google.auth.transport.requests
from dotenv import load_dotenv
 
load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
 
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:
    logging.error("FLASK_SECRET_KEY not set in environment variables!")
    exit()
 
CLIENT_SECRETS_FILE_CONTENT = {
    "web": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "redirect_uris": ["https://127.0.0.1:5000/callback"],
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token"
    }
}
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
REDIRECT_URI = CLIENT_SECRETS_FILE_CONTENT['web']['redirect_uris'][0]
 
scan_results_store = {}
 
def build_gmail_service():
    if 'credentials' not in session:
        logging.warning("No credentials found in session.")
        return None
 
    try:
        credentials = Credentials(**session['credentials'])
 
        if credentials.expired and credentials.refresh_token:
            logging.info("Credentials expired, attempting refresh.")
 
        gmail_service = build('gmail', 'v1', credentials=credentials)
        return gmail_service
    except Exception as e:
        logging.error(f"Error building Gmail service or refreshing token: {e}")
        session.pop('credentials', None)
        return None
 
def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}
 
def simple_spam_scan(email_data):
    score = 1
    reasons = []
    spam_keywords = ["win", "free", "prize", "lottery", "viagra", "urgent", "action required", "limited time", "password", "verify", "account"]
 
    subject = ""
    snippet = email_data.get('snippet', '')
    headers = email_data.get('payload', {}).get('headers', [])
    sender = ""
    auth_results = ""
 
    for header in headers:
        if header['name'].lower() == 'subject':
            subject = header['value'].lower()
        if header['name'].lower() == 'from':
            sender = header['value']
        if header['name'].lower() == 'authentication-results':
            auth_results = header['value'].lower()
 
    if 'spf=fail' in auth_results or 'dkim=fail' in auth_results:
        score += 2
        reasons.append("SPF or DKIM Failed")
    elif 'spf=softfail' in auth_results:
        score += 1
        reasons.append("SPF Softfail")
 
    for keyword in spam_keywords:
        if keyword in subject:
            score += 1
            reasons.append(f"Keyword '{keyword}' in subject")
            break
 
    for keyword in spam_keywords:
        if keyword in snippet.lower():
            score += 1
            reasons.append(f"Keyword '{keyword}' in snippet")
            break
 
    if '@' in sender:
        local_part = sender.split('@')[0]
        if len(local_part) < 4:
            pass
 
    final_score = min(score, 5)
 
    logging.info(f"Scan result for '{subject[:30]}...': Score={final_score}, Reasons={reasons}")
    return final_score, reasons
 
@app.route('/')
def index():
    if 'credentials' in session:
        return render_template_string("""
<h1>Gmail Threat Scanner (Simple Backend)</h1>
<p>You are logged in.</p>
<a href="{{ url_for('trigger_scan') }}">Scan Recent Emails</a><br>
<a href="{{ url_for('get_results') }}">View Scan Results</a><br>
<a href="{{ url_for('logout') }}">Logout</a>
        """)
    else:
        return render_template_string("""
<h1>Gmail Threat Scanner (Simple Backend)</h1>
<a href="{{ url_for('login') }}">Login with Google</a>
        """)
 
@app.route('/login')
def login():
    flow = Flow.from_client_config(
        CLIENT_SECRETS_FILE_CONTENT,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI)
 
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        prompt='consent',
        include_granted_scopes='true')
    session['state'] = state
 
    logging.info(f"Redirecting user to Google for authentication: {authorization_url}")
    return redirect(authorization_url)
 
@app.route('/callback')
def callback():
    state = session.get('state')
    if not state or state != request.args.get('state'):
        logging.error("State mismatch during OAuth callback. Possible CSRF.")
        return "State mismatch error. Please try logging in again.", 400
 
    flow = Flow.from_client_config(
        CLIENT_SECRETS_FILE_CONTENT,
        scopes=SCOPES,
        state=state,
        redirect_uri=REDIRECT_URI)
 
    try:
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        session['credentials'] = credentials_to_dict(credentials)
        logging.info("Successfully obtained OAuth tokens.")
        session['user_id'] = credentials.id_token['sub']
        if session['user_id'] not in scan_results_store:
            scan_results_store[session['user_id']] = []
        return redirect(url_for('index'))
    except Exception as e:
        logging.error(f"Error fetching OAuth token: {e}")
        return f"Error fetching token: {e}", 500
 
 
@app.route('/scan')
def trigger_scan():
    if 'credentials' not in session:
        return redirect(url_for('login'))
 
    user_id = session.get('user_id')
    if not user_id:
        logging.error("User ID not found in session during scan trigger.")
        return "Error: User session not found.", 500
 
    gmail_service = build_gmail_service()
    if not gmail_service:
        return "Could not connect to Gmail API. Please try logging in again.", 500
 
    logging.info(f"Starting email scan for user {user_id}...")
    scan_results_store[user_id] = []
 
    try:
        results = gmail_service.users().messages().list(
            userId='me',
            labelIds=['INBOX'],
            maxResults=10
        ).execute()
 
        messages = results.get('messages', [])
        count = 0
        if not messages:
            logging.info("No new messages found to scan.")
            return "No new messages found in the INBOX (checked last 10)."
        else:
            logging.info(f"Found {len(messages)} messages to fetch and scan.")
            for message_ref in messages:
                msg_id = message_ref['id']
                if any(r['id'] == msg_id for r in scan_results_store[user_id]):
                    continue
 
                msg = gmail_service.users().messages().get(
                    userId='me', id=msg_id, format='full'
                ).execute()
 
                subject = next((h['value'] for h in msg['payload']['headers'] if h['name'].lower() == 'subject'), 'No Subject')
                sender = next((h['value'] for h in msg['payload']['headers'] if h['name'].lower() == 'from'), 'No Sender')
 
                likelihood, reasons = simple_spam_scan(msg)
 
                scan_results_store[user_id].append({
                    'id': msg_id,
                    'subject': subject,
                    'sender': sender,
                    'snippet': msg.get('snippet', ''),
                    'likelihood': likelihood,
                    'reasons': reasons,
                    'scan_time': datetime.datetime.now().isoformat()
                })
                count += 1
                logging.debug(f"Scanned message ID: {msg_id}, Score: {likelihood}")
 
        logging.info(f"Scan complete. Processed {count} new emails for user {user_id}.")
        return f"Scan complete. Processed {count} emails. <a href='{url_for('get_results')}'>View Results</a>"
 
    except HttpError as error:
        logging.error(f'An error occurred during Gmail API call: {error}')
        if error.resp.status == 401:
            session.pop('credentials', None)
            session.pop('user_id', None)
            return redirect(url_for('login'))
        return f"An API error occurred: {error}", 500
    except Exception as e:
        logging.error(f'An unexpected error occurred during scan: {e}')
        return f"An unexpected error occurred: {e}", 500
 
 
@app.route('/results')
def get_results():
    if 'credentials' not in session:
        return jsonify({"error": "Not authenticated"}), 401
 
    user_id = session.get('user_id')
    if not user_id or user_id not in scan_results_store:
        return jsonify({"results": [], "message": "No results found or user session invalid."})
 
    results = scan_results_store.get(user_id, [])
    logging.info(f"Returning {len(results)} scan results for user {user_id}")
    return jsonify({"results": results})
 
@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.pop('credentials', None)
    session.pop('state', None)
    session.pop('user_id', None)
    if user_id and user_id in scan_results_store:
        del scan_results_store[user_id]
    logging.info(f"User {user_id} logged out.")
    return redirect(url_for('index'))
 
if __name__ == '__main__':
    logging.info("Starting Flask app on https://127.0.0.1:5000")
    app.run(port=5000, debug=True, ssl_context='adhoc')
