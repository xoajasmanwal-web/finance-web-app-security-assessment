import requests

TARGET = "http://127.0.0.1:3000"

def test_sqli_login():
    payload = {"email": "' OR 1=1--", "password": "password"}
    try:
        r = requests.post(f"{TARGET}/rest/user/login", json=payload, timeout=5)
        print(f"[SQLi Test] Status: {r.status_code} (Expected 401)")
    except Exception as e:
        print(f"[SQLi Test] Error: {e}")

def test_security_headers():
    try:
        r = requests.get(f"{TARGET}/api/Users", timeout=5)
        headers = r.headers
        print("[Headers Test] HSTS:", headers.get("Strict-Transport-Security", "MISSING"))
        print("[Headers Test] X-Frame-Options:", headers.get("X-Frame-Options", "MISSING"))
    except Exception as e:
        print(f"[Headers Test] Error: {e}")

if __name__ == "__main__":
    print("Running automated verification checks against", TARGET)
    test_sqli_login()
    test_security_headers()
