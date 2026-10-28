import json
import urllib.request

url = "https://shield3xx.onrender.com/openapi.json"
request = urllib.request.Request(
    url,
    headers={"User-Agent": "Shield3xxAV-Diagnostic/1.0"},
)

with urllib.request.urlopen(request, timeout=30) as response:
    spec = json.loads(response.read().decode("utf-8"))

print("API:", spec.get("info", {}).get("title"))
print("Version:", spec.get("info", {}).get("version"))

for path, methods in spec.get("paths", {}).items():
    for method, details in methods.items():
        print(f"\n{method.upper()} {path}")
        print("Summary:", details.get("summary", ""))

        body = details.get("requestBody", {})
        content = body.get("content", {})
        schema = content.get("application/json", {}).get("schema")

        if schema:
            print("Request schema:")
            print(json.dumps(schema, indent=2))

        for code, result in details.get("responses", {}).items():
            print(f"Response {code}:")
            print(json.dumps(result, indent=2)[:1500])