import requests
import webbrowser
import subprocess
import platform
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import os
import json
import sys
from dotenv import load_dotenv
load_dotenv()

# --- CONFIGURATION ---
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
REDIRECT_URI = os.getenv('REDIRECT_URI')  # Must match your Developer Portal settings
AUTH_URL = "https://authz.constantcontact.com/oauth2/default/v1/authorize"
TOKEN_URL = "https://authz.constantcontact.com/oauth2/default/v1/token"
SCOPE = "contact_data campaign_data offline_access"


class OAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        query_components = parse_qs(urlparse(self.path).query)
        if 'code' in query_components:
            self.server.auth_code = query_components['code'][0]
            self.wfile.write(b"Authorization successful! You can close this window.")
        else:
            self.server.auth_code = None
            self.wfile.write(b"Authorization failed.")

    def log_message(self, format, *args):
        pass  # Suppress request logs


def open_incognito(url):
    """Open URL in an incognito/private window to avoid existing sessions."""
    system = platform.system()
    try:
        if system == "Darwin":  # macOS
            subprocess.Popen(['open', '-na', 'Google Chrome', '--args', '--incognito', url])
        elif system == "Windows":
            subprocess.Popen(['start', 'chrome', '--incognito', url], shell=True)
        else:  # Linux
            subprocess.Popen(['google-chrome', '--incognito', url])
    except FileNotFoundError:
        # Chrome not found, fall back to default browser
        print("Chrome not found — opening default browser. You may need to log out manually first.")
        webbrowser.open(url)


def get_bearer_token(force_reauth=False):
    params = (
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&response_type=code"
        f"&scope={SCOPE}"
        f"&state=any_string_you_want"
    )
    url = AUTH_URL + params

    if force_reauth:
        print("Opening incognito window so you can log in as a different user...")
        open_incognito(url)
    else:
        webbrowser.open(url)

    server = HTTPServer(('localhost', 8080), OAuthHandler)
    server.handle_request()
    auth_code = server.auth_code

    if not auth_code:
        print("Authorization failed.")
        return None

    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": auth_code,
        "redirect_uri": REDIRECT_URI
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(TOKEN_URL, data=data, headers=headers)

    if response.status_code == 200:
        token_data = response.json()
        token_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".token")
        with open(token_path, "w") as f:
            json.dump(token_data, f, indent=2)
        print("Done.")
        return token_data
    else:
        print(f"Error {response.status_code}: {response.text}")
        return None


if __name__ == "__main__":
    force_reauth = "--reauth" in sys.argv
    get_bearer_token(force_reauth=force_reauth)

