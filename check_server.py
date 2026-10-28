import json
import urllib.error
import urllib.request

BASE_URL = "https://shield3xx.onrender.com"


def check_get(path):
    url = BASE_URL + path
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Shield3xxAV-Diagnostic/1.0"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(2000).decode("utf-8", "replace")
            print(f"\nGET {path}: HTTP {response.status}")
            print(body[:500] or "(empty response)")
            return response.status, body

    except urllib.error.HTTPError as exc:
        body = exc.read(1000).decode("utf-8", "replace")
        print(f"\nGET {path}: HTTP {exc.code}")
        print(body[:300] or "(empty response)")
        return exc.code, body

    except Exception as exc:
        print(f"\nGET {path}: CONNECTION ERROR: {exc}")
        return None, ""


print("Shield3xxAV server diagnostic")
print("Server:", BASE_URL)

for path in ("/", "/health", "/docs", "/openapi.json"):
    status, body = check_get(path)

    if path == "/openapi.json" and status == 200:
        try:
            spec = json.loads(body)
            print("API endpoints:")
            for route, methods in spec.get("paths", {}).items():
                print(f"  {', '.join(methods.keys()).upper():15} {route}")
        except json.JSONDecodeError:
            print("OpenAPI response was not valid JSON.")

print("\nTesting login endpoint with deliberately invalid credentials.")
payload = json.dumps({
    "username": "__shield3xx_diagnostic_invalid_user__",
    "password": "__invalid_diagnostic_password__",
}).encode("utf-8")

request = urllib.request.Request(
    BASE_URL + "/login",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)

try:
    with urllib.request.urlopen(request, timeout=30) as response:
        print("POST /login: HTTP", response.status)
        print(response.read(500).decode("utf-8", "replace"))
except urllib.error.HTTPError as exc:
    print("POST /login: HTTP", exc.code)
    print(exc.read(500).decode("utf-8", "replace"))
except Exception as exc:
    print("POST /login: CONNECTION ERROR:", exc)

print("\nDiagnostic complete. No real account credentials were used.")