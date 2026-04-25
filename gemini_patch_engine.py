import os
import json
import time
from google import genai

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSy-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
MODEL_ID = "gemini-2.0-flash"

SYSTEM_PROMPT = """
You are a cybersecurity patch management AI.
Given a list of detected vulnerabilities, generate a structured remediation plan.
Return a JSON object with keys: vulnerability, severity, patch_steps, estimated_fix_time.
"""

VULNERABILITY_CONTEXT = {
    "scan_id": "PSE-2024-0391",
    "target": "honeypot-webapp",
    "detected": [
        {"stage": 1, "type": "Reconnaissance", "path": "/source", "severity": "Low"},
        {"stage": 2, "type": "XSS/SSTI",        "path": "/feedback", "severity": "High"},
        {"stage": 3, "type": "XXE",              "path": "/profile",  "severity": "Critical"},
        {"stage": 4, "type": "Insecure Deserialization", "path": "/verify", "severity": "Critical"},
        {"stage": 5, "type": "SSRF",             "path": "/diagnostics", "severity": "High"},
    ]
}


def fetch_patch_plan(vulnerability: dict) -> dict:
    client = genai.Client(api_key=GEMINI_API_KEY)

    prompt = (
        f"Vulnerability detected:\n"
        f"  Stage     : {vulnerability['stage']}\n"
        f"  Type      : {vulnerability['type']}\n"
        f"  Path      : {vulnerability['path']}\n"
        f"  Severity  : {vulnerability['severity']}\n\n"
        f"Generate a remediation plan as JSON."
    )

    response = client.models.generate_content(
        model=MODEL_ID,
        contents=prompt,
        config={"system_instruction": SYSTEM_PROMPT}
    )

    try:
        text = response.text.strip().lstrip("```json").rstrip("```").strip()
        return json.loads(text)
    except (json.JSONDecodeError, AttributeError):
        return {"raw_response": response.text}


def run_patch_engine():
    print("[*] Patch Management Engine — powered by Gemini AI")
    print(f"[*] Scan ID  : {VULNERABILITY_CONTEXT['scan_id']}")
    print(f"[*] Target   : {VULNERABILITY_CONTEXT['target']}")
    print(f"[*] Model    : {MODEL_ID}")
    print("-" * 60)

    results = []
    for vuln in VULNERABILITY_CONTEXT["detected"]:
        print(f"[*] Fetching patch plan for Stage {vuln['stage']} — {vuln['type']}...")
        plan = fetch_patch_plan(vuln)
        results.append({"vulnerability": vuln, "patch_plan": plan})
        time.sleep(1)

    print("-" * 60)
    print("[+] Patch intelligence fetched for all stages.")
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    run_patch_engine()
