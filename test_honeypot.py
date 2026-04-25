import requests
import time

try:
    print("Sending request to honeypot...")
    response = requests.get('http://127.0.0.1:5001/honeypot')
    print(f"Status Code: {response.status_code}")
    print("Request sent.")
except Exception as e:
    print(f"Error: {e}")
