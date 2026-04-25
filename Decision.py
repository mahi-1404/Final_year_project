import os
import re
from collections import defaultdict
from datetime import datetime, timedelta

def count_hits(log_file_path):
    total_requests = 0
    legit_count = 0
    malicious_count = 0
    honeypot_hits = 0

    ignore_prefixes = ["/static/"]
    ignore_paths = {"/admin", "/admin_data", "/favicon.ico"}

    # Pattern for legacy Apache-style entries
    legacy_pattern = re.compile(
        r'^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>\d{2}/\w{3}/\d{4} \d{2}:\d{2}:\d{2})\] "(?P<method>\w+) (?P<path>[^\s]+) [^"]+" (?P<status>\d{3}) (?P<user_agent>.*)$'
    )

    # Pattern for current app logger: "2025-12-16 12:34:56,789 INFO 127.0.0.1 GET /honeypot 200 Mozilla"
    app_logger_pattern = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2} [\d:,]+) (?P<level>\w+) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<method>\w+) (?P<path>\S+) (?P<status>\d{3}) (?P<user_agent>.*)$'
    )

    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                match = legacy_pattern.match(line) or app_logger_pattern.match(line)
                if match:
                    data = match.groupdict()
                    path = data['path']

                    if path in ignore_paths or any(path.startswith(p) for p in ignore_prefixes):
                        continue

                    total_requests += 1

                    if "/honeypot" in path:
                        malicious_count += 1
                        honeypot_hits += 1
                    else:
                        legit_count += 1
    except FileNotFoundError:
        print(f"Log file not found: {log_file_path}")
        
    return {
        "total_requests": total_requests,
        "legit_count": legit_count,
        "malicious_count": malicious_count,
        "honeypot_hits": honeypot_hits
    }

if __name__ == '__main__':
    # This block is for testing the function directly
    # In a real application, you would pass the actual log file path
    # For demonstration, let's assume a dummy log file path
    dummy_log_file = "web_access.log" # Assuming web_access.log is in the same directory

    # Create a dummy log file for testing if it doesn't exist
    if not os.path.exists(dummy_log_file):
        with open(dummy_log_file, 'w') as f:
            f.write('192.168.1.1 - - [27/Nov/2025 10:00:00] "GET /safe HTTP/1.1" 200 "Mozilla/5.0"\n')
            f.write('10.0.0.5 - - [27/Nov/2025 10:01:00] "POST /honeypot/login HTTP/1.1" 302 "BadBot"\n')
            f.write('192.168.1.2 - - [27/Nov/2025 10:02:00] "GET /stage1 HTTP/1.1" 200 "Mozilla/5.0"\n')
            f.write('10.0.0.6 - - [27/Nov/2025 10:03:00] "GET /honeypot HTTP/1.1" 200 "AnotherBadBot"\n')

    hits_data = count_hits(dummy_log_file)
    print("Legit Hits:", hits_data["legit_count"])
    print("Malicious Hits:", hits_data["malicious_count"])
    print("Total Requests:", hits_data["total_requests"])
