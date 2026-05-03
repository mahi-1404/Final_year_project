from flask import Flask, request, redirect, render_template, render_template_string, jsonify
from dotenv import load_dotenv
import logging

load_dotenv()
from logging.handlers import RotatingFileHandler
import os
import re
import random
from collections import defaultdict
from datetime import datetime, timedelta
from Decision import count_hits # Import the count_hits function
import sys
from pathlib import Path

# Add ml_detection to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'ml_detection'))

app = Flask(__name__, template_folder='template', static_folder='static')

# Import ML detector
try:
    from flask_integration import detector_manager
    ML_DETECTOR_AVAILABLE = True
except:
    ML_DETECTOR_AVAILABLE = False
    print("[WARNING] ML Detector not available - attacks won't be detected")

# ================= LOGGING SETUP (Only New Part) ================= #
# Get the directory where app.py is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "web_access.log")
MONTH_MARKER_FILE = os.path.join(BASE_DIR, "log_month.txt")

handler = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5)
handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)

app.logger.setLevel(logging.INFO)
app.logger.addHandler(handler)

def rotate_log_monthly():
    """Clear web_access.log at the start of each new calendar month."""
    global handler
    current_month = datetime.now().strftime("%Y-%m")
    if not os.path.exists(MONTH_MARKER_FILE):
        # First run — just record current month, do NOT clear the log
        with open(MONTH_MARKER_FILE, 'w') as f:
            f.write(current_month)
        return
    with open(MONTH_MARKER_FILE, 'r') as f:
        stored_month = f.read().strip()
    if stored_month == current_month:
        return  # same month, nothing to do
    # Month has changed — clear the log
    try:
        app.logger.removeHandler(handler)
        handler.close()
        with open(LOG_FILE, 'w'):
            pass  # truncate
        handler = RotatingFileHandler(LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5)
        handler.setLevel(logging.INFO)
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)
    except Exception as e:
        print(f"[WARNING] Could not rotate log: {e}")
    with open(MONTH_MARKER_FILE, 'w') as f:
        f.write(current_month)

 # Removed automatic after_request logging to prevent auto log generation
# ================================================================== #


@app.route('/')
def home():
    return render_template('index.html')

# =================== ML DETECTION ENDPOINT ======================= #
@app.route('/ml_detect', methods=['POST'])
def ml_detect():
    """
    ML-based attack detection endpoint for index.html login form
    Returns: {is_malicious, color, status, attack_type, confidence}
    """
    if not ML_DETECTOR_AVAILABLE:
        return jsonify({
            'is_malicious': False,
            'color': '🟢 GREEN',
            'status': 'SAFE',
            'attack_type': None,
            'confidence': 0.0
        })
    
    try:
        data = request.get_json()
        user_input = data.get('input', '')
        
        if not user_input:
            return jsonify({
                'is_malicious': False,
                'color': '🟢 GREEN',
                'status': 'SAFE',
                'attack_type': None,
                'confidence': 0.0
            })
        
        # Get detection result from ML detector
        result = detector_manager.check_input(user_input)
        
        # Log detection if malicious
        if result['is_malicious']:
            app.logger.warning(
                f"ATTACK_DETECTED path=/ml_detect ip={request.remote_addr} "
                f"method=POST attack_type={result['attack_type']} "
                f"payload=\"{user_input}\" confidence={result['confidence']:.2%}"
            )
        
        return jsonify({
            'is_malicious': result['is_malicious'],
            'color': result['color'],
            'status': result['status'],
            'attack_type': result['attack_type'],
            'confidence': result['confidence']
        })
        
    except Exception as e:
        app.logger.error(f"Error in ML detection: {e}")
        return jsonify({
            'is_malicious': False,
            'color': '🟢 GREEN',
            'status': 'SAFE',
            'attack_type': None,
            'confidence': 0.0
        })
# ================================================================== #

def check():
    username = request.form['username']
    password = request.form['password']
    user_input = f"Username: {username}, Password: {password}"
    classification_reason = "unknown"

    try:
        from groq import Groq
        groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": f"Classify this input as 'red' (malicious) or 'green' (safe). If the input is not malicious return green: {user_input}"}],
            max_tokens=10
        )
        verdict = response.choices[0].message.content.strip().lower()
        if "red" in verdict:
            classification_reason = "groq_red"
            app.logger.info(
                "PAYLOAD target=honeypot reason=%s ip=%s ua=\"%s\" body=\"%s\"",
                classification_reason,
                request.remote_addr,
                request.user_agent.string,
                user_input.replace('"', "'")
            )
            app.logger.info(
                "REDIRECT target=honeypot verdict=red reason=%s method=%s path=%s ip=%s ua=\"%s\"",
                classification_reason,
                request.method,
                request.path,
                request.remote_addr,
                request.user_agent.string,
            )
            return redirect("/honeypot")
        else:
            classification_reason = "groq_green"
            app.logger.info(
                "REDIRECT target=safe verdict=green reason=%s method=%s path=%s ip=%s ua=\"%s\"",
                classification_reason,
                request.method,
                request.path,
                request.remote_addr,
                request.user_agent.string,
            )
            return redirect("/safe")
    except Exception as e:
        app.logger.warning(f"Groq API error: {e}. Using fallback detection.")
        malicious_patterns = ['<script>', 'DROP', 'SELECT', 'INSERT', 'DELETE', 'UPDATE',
                              'UNION', '--', ';--', 'OR 1=1', 'admin\'--', '../', 'passwd']
        user_input_lower = user_input.lower()
        is_malicious = any(pattern.lower() in user_input_lower for pattern in malicious_patterns)
        classification_reason = "fallback_malicious" if is_malicious else "fallback_legit"
        if is_malicious:
            app.logger.info(
                "PAYLOAD target=honeypot reason=%s ip=%s ua=\"%s\" body=\"%s\"",
                classification_reason,
                request.remote_addr,
                request.user_agent.string,
                user_input.replace('"', "'")
            )
        app.logger.info(
            "REDIRECT target=%s verdict=%s reason=%s method=%s path=%s ip=%s ua=\"%s\"",
            "honeypot" if is_malicious else "safe",
            "red" if is_malicious else "green",
            classification_reason,
            request.method,
            request.path,
            request.remote_addr,
            request.user_agent.string,
        )
        if is_malicious:
            return redirect("/honeypot")
        else:
            return redirect("/safe")

@app.route('/log_redirect', methods=['POST'])
def log_redirect():
    data = request.get_json(silent=True) or {}
    app.logger.info(
        "REDIRECT target=%s verdict=%s reason=%s method=%s path=%s ip=%s ua=\"%s\"",
        data.get('target', 'unknown'),
        data.get('verdict', 'unknown'),
        data.get('reason', 'unknown'),
        request.method,
        data.get('path', '/'),
        request.remote_addr,
        request.user_agent.string,
    )
    return '', 204

@app.route('/honeypot')
def honeypot():
    app.logger.info("%s %s %s %s %s", request.remote_addr, request.method, request.path, 200, request.user_agent.string)
    return render_template('main/main.html') # This should probably be a dedicated honeypot page. Leaving as is for now.

# New CTF stage routes
@app.route('/safe')
def safe():
    app.logger.info("%s %s %s %s %s", request.remote_addr, request.method, request.path, 200, request.user_agent.string)
    return render_template('main.html')

@app.route('/stage1')
def stage1():
    return render_template('main/stage1_recon.html')

@app.route('/stage2')
def stage2():
    return render_template('main/stage2_legacy_login.html')

@app.route('/stage3')
def stage3():
    return render_template('main/stage3_profile_lookup.html')

@app.route('/stage4')
def stage4():
    return render_template('main/stage4_token_verification.html')

@app.route('/stage5')
def stage5():
    return render_template('main/stage5_diagnostics.html')

# CTF Stage Form Submission Endpoints with Logging
@app.route('/legacy_login', methods=['POST'])
def legacy_login():
    username = request.form.get('username', '')
    legacy_key = request.form.get('legacy_key', '')
    
    # Log the form data with path and full payload
    app.logger.info(
        "STAGE2_INPUT path=%s ip=%s method=%s username=\"%s\" legacy_key=\"%s\" payload=\"username=%s&legacy_key=%s\" ua=\"%s\"",
        request.path,
        request.remote_addr,
        request.method,
        username.replace('"', "'"),
        legacy_key.replace('"', "'"),
        username.replace('"', "'"),
        legacy_key.replace('"', "'"),
        request.user_agent.string
    )
    
    # XSS/SSTI vulnerability check (intentionally vulnerable for CTF)
    # Accepts XSS payloads or Server-Side Template Injection patterns
    xss_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=', '<img', '<svg']
    ssti_patterns = ['{{', '${', '#{', '%{']
    
    has_xss = any(pattern.lower() in username.lower() or pattern.lower() in legacy_key.lower() for pattern in xss_patterns)
    has_ssti = any(pattern in username or pattern in legacy_key for pattern in ssti_patterns)
    
    if has_xss or has_ssti:
        attack_method = 'XSS' if has_xss else 'SSTI'
        app.logger.info(
            "STAGE2_COMPROMISE path=%s ip=%s method=%s attack_type=%s payload=\"username=%s&legacy_key=%s\" status=SUCCESS",
            request.path,
            request.remote_addr,
            attack_method,
            'Cross_Site_Scripting' if has_xss else 'Server_Side_Template_Injection',
            username.replace('"', "'"),
            legacy_key.replace('"', "'")
        )
        return redirect('/stage3')
    else:
        app.logger.info("STAGE2_FAILED path=%s ip=%s status=FAILED", request.path, request.remote_addr)
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>ACCESS DENIED</title>
    <style>
        @keyframes blink {
            0%, 50%, 100% { opacity: 1; }
            25%, 75% { opacity: 0.3; }
        }
        body {
            margin: 0;
            padding: 0;
            background: #000;
            color: #0f0;
            font-family: 'Courier New', monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            overflow: hidden;
        }
        .terminal {
            border: 2px solid #0f0;
            padding: 30px;
            max-width: 700px;
            box-shadow: 0 0 20px #0f0, inset 0 0 20px rgba(0,255,0,0.1);
            background: rgba(0,20,0,0.9);
            position: relative;
        }
        .terminal::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 255, 0, 0.03) 0px,
                transparent 1px,
                transparent 2px,
                rgba(0, 255, 0, 0.03) 3px
            );
            pointer-events: none;
        }
        h1 {
            color: #f00;
            text-align: center;
            font-size: 3em;
            margin: 0 0 20px 0;
            animation: blink 2s infinite;
            text-shadow: 0 0 10px #f00, 0 0 20px #f00;
        }
        .message {
            font-size: 1.2em;
            line-height: 1.8;
            text-shadow: 0 0 5px #0f0;
        }
        .code {
            color: #ff0;
            font-weight: bold;
        }
        .cursor {
            animation: blink 1s infinite;
        }
        .btn {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background: transparent;
            border: 2px solid #0f0;
            color: #0f0;
            text-decoration: none;
            transition: all 0.3s;
            box-shadow: 0 0 10px #0f0;
        }
        .btn:hover {
            background: #0f0;
            color: #000;
            box-shadow: 0 0 20px #0f0;
        }
    </style>
</head>
<body>
    <div class="terminal">
        <h1>⚠ ACCESS DENIED ⚠</h1>
        <div class="message">
            <p><span class="code">[SYSTEM]</span> Authentication Failed</p>
            <p><span class="code">[ERROR]</span> Invalid credentials detected</p>
            <p><span class="code">[TRACE]</span> IP: ''' + request.remote_addr + '''</p>
            <p><span class="code">[STATUS]</span> Intrusion attempt logged</p>
            <p><span class="code">[HINT]</span> The system reflects your input... perhaps too well.</p>
            <p style="margin-top: 20px;">>>> Retrying connection<span class="cursor">_</span></p>
        </div>
        <a href="/stage2" class="btn">← RETRY ACCESS</a>
    </div>
</body>
</html>
''', 403

@app.route('/profile', methods=['POST'])
def profile():
    xml_data = request.form.get('xml_data', '')
    
    # Log the form data with path
    app.logger.info(
        "STAGE3_INPUT path=%s ip=%s method=%s xml_length=%d payload=\"xml_data=%s\" ua=\"%s\"",
        request.path,
        request.remote_addr,
        request.method,
        len(xml_data),
        xml_data[:100].replace('"', "'"),
        request.user_agent.string
    )
    
    # XXE vulnerability - check for XML External Entity patterns
    xxe_patterns = ['<!ENTITY', '<!DOCTYPE', 'SYSTEM', 'file://', 'http://', 'PUBLIC']
    
    if any(pattern.upper() in xml_data.upper() for pattern in xxe_patterns):
        app.logger.info(
            "STAGE3_COMPROMISE path=%s ip=%s method=XXE attack_type=XML_External_Entity payload=\"%s\" status=SUCCESS",
            request.path,
            request.remote_addr,
            xml_data[:200].replace('"', "'")
        )
        # Return a serialized object for stage 4
        serialized_token = "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAABdwQAAAABdAAFYWRtaW54"
        return f"<h2>Admin Profile Accessed</h2><p>Welcome, Administrator!</p><p>Your session token: {serialized_token}</p><p><a href='/stage4'>Proceed to Stage 4</a></p>"
    else:
        app.logger.info("STAGE3_FAILED path=%s ip=%s status=FAILED", request.path, request.remote_addr)
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>PARSING ERROR</title>
    <style>
        @keyframes blink {
            0%, 50%, 100% { opacity: 1; }
            25%, 75% { opacity: 0.3; }
        }
        @keyframes scan {
            0% { top: 0; }
            100% { top: 100%; }
        }
        body {
            margin: 0;
            background: #000;
            color: #f0f;
            font-family: 'Courier New', monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .terminal {
            border: 2px solid #f0f;
            padding: 30px;
            max-width: 700px;
            box-shadow: 0 0 20px #f0f, inset 0 0 20px rgba(255,0,255,0.1);
            background: rgba(20,0,20,0.9);
            position: relative;
        }
        .scanline {
            position: absolute;
            left: 0;
            right: 0;
            height: 2px;
            background: rgba(255,0,255,0.3);
            animation: scan 4s linear infinite;
        }
        h1 {
            color: #f00;
            text-align: center;
            font-size: 2.5em;
            margin: 0 0 20px 0;
            text-shadow: 0 0 10px #f00;
            animation: blink 2s infinite;
        }
        .message {
            font-size: 1.1em;
            line-height: 1.8;
            text-shadow: 0 0 5px #f0f;
        }
        .code {
            color: #0ff;
            font-weight: bold;
        }
        .btn {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background: transparent;
            border: 2px solid #f0f;
            color: #f0f;
            text-decoration: none;
            transition: all 0.3s;
            box-shadow: 0 0 10px #f0f;
        }
        .btn:hover {
            background: #f0f;
            color: #000;
            box-shadow: 0 0 20px #f0f;
        }
    </style>
</head>
<body>
    <div class="terminal">
        <div class="scanline"></div>
        <h1>⚡ PARSING ERROR ⚡</h1>
        <div class="message">
            <p><span class="code">[XML PARSER]</span> Input rejected</p>
            <p><span class="code">[ERROR CODE]</span> 0xDEADBEEF</p>
            <p><span class="code">[REASON]</span> Entity declaration not found</p>
            <p><span class="code">[IP LOGGED]</span> ''' + request.remote_addr + '''</p>
            <p><span class="code">[HINT]</span> External entities can reveal hidden truths...</p>
            <p style="margin-top: 20px; color: #f00;">&gt;&gt;&gt; SYSTEM WAITING FOR VALID INPUT</p>
        </div>
        <a href="/stage3" class="btn">← RESUBMIT DATA</a>
    </div>
</body>
</html>
''', 400

@app.route('/verify_token', methods=['POST'])
def verify_token():
    serialized_obj = request.form.get('serialized_data', '')
    
    # Log the form data with path
    app.logger.info(
        "STAGE4_INPUT path=%s ip=%s method=%s data_length=%d payload=\"serialized_data=%s\" ua=\"%s\"",
        request.path,
        request.remote_addr,
        request.method,
        len(serialized_obj),
        serialized_obj[:100].replace('"', "'"),
        request.user_agent.string
    )
    
    # Insecure Deserialization vulnerability - check for malicious serialized patterns
    # Accept Java serialization, Python pickle, or PHP serialization patterns
    deserialization_patterns = [
        'rO0AB',  # Java serialization magic bytes (base64)
        'gAN',    # Python pickle protocol 3 (base64)
        'O:',     # PHP object serialization
        '__reduce__',  # Python pickle exploit
        'Runtime.getRuntime',  # Java Runtime exploit
        'exec(',  # Code execution
        'eval(',  # Code evaluation
    ]
    
    if any(pattern in serialized_obj for pattern in deserialization_patterns):
        app.logger.info(
            "STAGE4_COMPROMISE path=%s ip=%s method=Deserialization attack_type=Insecure_Deserialization payload=\"%s\" status=SUCCESS",
            request.path,
            request.remote_addr,
            serialized_obj[:200].replace('"', "'")
        )
        return redirect('/stage5')
    else:
        app.logger.info("STAGE4_FAILED path=%s ip=%s status=FAILED", request.path, request.remote_addr)
        return '''
<!DOCTYPE html>
<html>
<head>
    <title>VERIFICATION FAILED</title>
    <style>
        @keyframes blink {
            0%, 50%, 100% { opacity: 1; }
            25%, 75% { opacity: 0.3; }
        }
        @keyframes matrixRain {
            0% { transform: translateY(-100%); }
            100% { transform: translateY(100vh); }
        }
        body {
            margin: 0;
            background: #000;
            color: #00ff41;
            font-family: 'Courier New', monospace;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            overflow: hidden;
        }
        .matrix {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            opacity: 0.1;
            pointer-events: none;
            font-size: 10px;
            line-height: 10px;
        }
        .terminal {
            border: 3px solid #00ff41;
            padding: 30px;
            max-width: 700px;
            box-shadow: 0 0 30px #00ff41, inset 0 0 30px rgba(0,255,65,0.1);
            background: rgba(0,10,0,0.95);
            position: relative;
            z-index: 10;
        }
        h1 {
            color: #ff0040;
            text-align: center;
            font-size: 2.8em;
            margin: 0 0 20px 0;
            text-shadow: 0 0 15px #ff0040, 0 0 30px #ff0040;
            animation: blink 2s infinite;
        }
        .message {
            font-size: 1.1em;
            line-height: 1.8;
            text-shadow: 0 0 5px #00ff41;
        }
        .code {
            color: #ffff00;
            font-weight: bold;
        }
        .warning {
            color: #ff0040;
            font-weight: bold;
        }
        .btn {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background: transparent;
            border: 2px solid #00ff41;
            color: #00ff41;
            text-decoration: none;
            transition: all 0.3s;
            box-shadow: 0 0 15px #00ff41;
        }
        .btn:hover {
            background: #00ff41;
            color: #000;
            box-shadow: 0 0 30px #00ff41;
        }
    </style>
</head>
<body>
    <div class="matrix">010101001010101010010101</div>
    <div class="terminal">
        <h1>🚫 DESERIALIZATION FAILED 🚫</h1>
        <div class="message">
            <p><span class="code">[DESERIALIZER]</span> Object verification failed</p>
            <p><span class="code">[STATUS]</span> <span class="warning">MALFORMED DATA DETECTED</span></p>
            <p><span class="code">[TRACE]</span> Source: ''' + request.remote_addr + '''</p>
            <p><span class="code">[SECURITY]</span> Untrusted object rejected</p>
            <p><span class="code">[HINT]</span> Serialized objects can execute code...</p>
            <p style="margin-top: 20px; color: #ff0040;">&gt;&gt;&gt; SESSION TERMINATED</p>
            <p style="color: #00ff41;">&gt;&gt;&gt; Awaiting valid serialized data...</p>
        </div>
        <a href="/stage4" class="btn">← REINITIALIZE SESSION</a>
    </div>
</body>
</html>
''', 403

@app.route('/diagnose', methods=['POST'])
def diagnose():
    target_url = request.form.get('target_url', '')
    
    # Log the form data with path
    app.logger.info(
        "STAGE5_INPUT path=%s ip=%s method=%s target_url=\"%s\" payload=\"target_url=%s\" ua=\"%s\"",
        request.path,
        request.remote_addr,
        request.method,
        target_url.replace('"', "'"),
        target_url.replace('"', "'"),
        request.user_agent.string
    )
    
    # SSRF vulnerability (intentionally vulnerable for CTF)
    # Check for internal network access or cloud metadata endpoints
    ssrf_patterns = [
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
        '169.254.169.254',  # AWS metadata
        'metadata.google.internal',  # GCP metadata
        '10.',  # Private IP range
        '172.16.',  # Private IP range
        '192.168.',  # Private IP range
        'file://',  # File protocol
        'gopher://',  # Gopher protocol
    ]
    
    if any(pattern in target_url.lower() for pattern in ssrf_patterns):
        app.logger.info(
            "STAGE5_COMPROMISE path=%s ip=%s method=SSRF attack_type=Server_Side_Request_Forgery payload=\"target_url=%s\" status=SUCCESS",
            request.path,
            request.remote_addr,
            target_url.replace('"', "'")
        )
        return render_template_string("""<!DOCTYPE html>
<html>
<head>
    <title>System Compromised</title>
    <link rel="stylesheet" href="/static/ctf.css">
    <style>
        .compromised-card {
            max-width: 700px;
            margin: 60px auto;
            background: rgba(15, 15, 18, 0.97);
            border: 2px solid #3ddc97;
            border-radius: 14px;
            box-shadow: 0 0 40px rgba(61, 220, 151, 0.2);
            padding: 40px 36px;
            text-align: center;
            color: #e8e8ee;
        }
        .compromised-card h1 {
            color: #3ddc97;
            font-size: 2rem;
            margin-bottom: 10px;
            letter-spacing: 1px;
        }
        .compromised-card .sub {
            color: #9aa3c4;
            font-size: 1rem;
            margin-bottom: 28px;
        }
        .flag-box {
            background: rgba(61, 220, 151, 0.1);
            border: 1px solid #2f7d5d;
            border-radius: 8px;
            padding: 14px 20px;
            font-family: Consolas, monospace;
            font-size: 1.1rem;
            color: #9effcf;
            font-weight: 700;
            margin-bottom: 28px;
            word-break: break-all;
        }
        .btn-row { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
        .btn {
            padding: 10px 20px;
            border-radius: 8px;
            border: 1px solid #2a2a34;
            text-decoration: none;
            color: #e8e8ee;
            background: #1a1d29;
            font-size: 0.95rem;
        }
        .btn:hover { background: #242942; }
        .btn.primary { border-color: #3ddc97; color: #3ddc97; }
    </style>
</head>
<body>
<div class="container">
    <div class="compromised-card">
        <h1>&#x1F6A8; SYSTEM COMPROMISED &#x1F6A8;</h1>
        <p class="sub">Congratulations &mdash; You have successfully exploited all 5 attack vectors and gained full system access.</p>
        <div class="flag-box">FLAG: CTF{5_D1ff3r3nt_4tt4ck_V3ct0rs_M4st3r3d}</div>
        <div class="btn-row">
            <a class="btn" href="/">Back to Login</a>
        </div>
    </div>
</div>
</body>
</html>""")
    else:
        app.logger.info(
            "STAGE5_ATTEMPT path=%s ip=%s payload=\"target_url=%s\" status=FAILED",
            request.path,
            request.remote_addr,
            target_url.replace('"', "'")
        )
        # Simulate external URL fetch
        return f"<h2>Diagnostic Result</h2><pre>Fetching from {target_url}...\n200 OK\nContent-Length: 1234\nServer: nginx</pre><p><a href='/stage5'>Try again</a></p>"


def build_attack_completion_report(client_ip=None):
    """Build a stage-wise attack report for the current player IP."""
    stage_rows = {
        "1": {
            "stage": "Stage 1",
            "path": "/stage1",
            "attack_type": "Reconnaissance",
            "payload": "N/A (passive discovery)",
            "fix": "Remove sensitive hints from HTML comments and enforce least information disclosure.",
            "status": "completed"
        },
        "2": {
            "stage": "Stage 2",
            "path": "/legacy_login",
            "attack_type": "XSS / SSTI",
            "payload": "Not captured for this IP yet",
            "fix": "Use strict output encoding, input validation, CSP, and never evaluate template expressions from user input.",
            "status": "pending"
        },
        "3": {
            "stage": "Stage 3",
            "path": "/profile",
            "attack_type": "XXE",
            "payload": "Not captured for this IP yet",
            "fix": "Disable external entities/DTDs in XML parser and prefer safe parsers.",
            "status": "pending"
        },
        "4": {
            "stage": "Stage 4",
            "path": "/verify_token",
            "attack_type": "Insecure Deserialization",
            "payload": "Not captured for this IP yet",
            "fix": "Do not deserialize untrusted data; use signed tokens and strict type allow-lists.",
            "status": "pending"
        },
        "5": {
            "stage": "Stage 5",
            "path": "/diagnose",
            "attack_type": "SSRF",
            "payload": "Not captured for this IP yet",
            "fix": "Use URL allow-lists, block private/internal ranges, and isolate outbound network access.",
            "status": "pending"
        }
    }

    attack_label_map = {
        "cross_site_scripting": "XSS",
        "server_side_template_injection": "SSTI",
        "xml_external_entity": "XXE",
        "insecure_deserialization": "Insecure Deserialization",
        "server_side_request_forgery": "SSRF",
    }

    compromise_pattern = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} [\d:,]+) \w+ STAGE(?P<stage>\d)_COMPROMISE path=(?P<path>\S+) ip=(?P<ip>\S+) .*? attack_type=(?P<attack_type>\S+) payload="(?P<payload>.*?)" status=SUCCESS',
        re.DOTALL
    )

    try:
        with open(LOG_FILE, 'r') as f:
            content = f.read()
        for match in compromise_pattern.finditer(content):
            if client_ip is not None and match.group('ip') != client_ip:
                continue

            stage = match.group('stage')
            if stage not in stage_rows:
                continue

            attack_key = match.group('attack_type').lower()
            readable_attack = attack_label_map.get(attack_key, match.group('attack_type').replace('_', ' '))
            stage_rows[stage]["attack_type"] = readable_attack
            stage_rows[stage]["path"] = match.group('path')
            stage_rows[stage]["payload"] = match.group('payload').strip()[:200] if match.group('payload') else "Captured"
            stage_rows[stage]["status"] = "completed"
    except FileNotFoundError:
        app.logger.warning("Could not build attack report because log file was not found.")

    ordered = [stage_rows[k] for k in ["1", "2", "3", "4", "5"]]
    all_completed = all(row["status"] == "completed" for row in ordered[1:])
    return {"stages": ordered, "all_completed": all_completed}


@app.route('/attack_report_data')
def attack_report_data():
    report = build_attack_completion_report()  # no IP filter — show all compromises
    return jsonify(report)


@app.route('/attack_report')
def attack_report():
    report = build_attack_completion_report(request.remote_addr)
    return render_template(
        'main/attack_report.html',
        stages=report["stages"],
        all_completed=report["all_completed"],
        flag="CTF{5_D1ff3r3nt_4tt4ck_V3ct0rs_M4st3r3d}"
    )


def process_logs():
    rotate_log_monthly()
    # Call count_hits from Decision.py
    log_file = LOG_FILE  # Use the same log file as the app logger
    hits_data = count_hits(log_file)

    # Initialize all_access_logs
    all_access_logs = []

    high_risk_events = []
    honeypot_hits = 0  # Initialize honeypot_hits counter
    
    method_counts = defaultdict(int)
    status_counts = defaultdict(int)
    requests_over_time = defaultdict(int)
    requests_by_month = defaultdict(int)
    redirect_logs = []
    ignore_prefixes = ["/static/"]
    ignore_paths = {"/admin", "/admin_data", "/favicon.ico"}

    # regex patterns for legacy apache-style and current app logger format
    legacy_pattern = re.compile(
        r'^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(?P<timestamp>\d{2}/\w{3}/\d{4} \d{2}:\d{2}:\d{2})\] "(?P<method>\w+) (?P<path>[^\s]+) [^"]+" (?P<status>\d{3}) (?P<user_agent>.*)$'
    )

    app_logger_pattern = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2} [\d:,]+) (?P<level>\w+) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<method>\w+) (?P<path>\S+) (?P<status>\d{3}) (?P<user_agent>.*)$'
    )

    redirect_pattern = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2} [\d:,]+) \w+ REDIRECT target=(?P<target>\w+) verdict=(?P<verdict>\w+) reason=(?P<reason>[^\s]+) method=(?P<method>\w+) path=(?P<path>\S+) ip=(?P<ip>[^\s]+) ua="?(?P<user_agent>.*)"?$'
    )

    payload_pattern = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2} [\d:,]+) \w+ PAYLOAD target=\S+ reason=\S+ ip=(?P<ip>\S+) ua="?[^"]*"? body="(?P<body>.*)"$'
    )

    attack_detected_pattern = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2} [\d:,]+) \w+ ATTACK_DETECTED path=\S+ ip=(?P<ip>\S+) method=\S+ attack_type=(?P<attack_type>\S+) payload="(?P<payload>.*)" confidence=\S+$'
    )

    stage_compromise_pattern = re.compile(
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2} [\d:,]+) \w+ STAGE(?P<stage>\d)_COMPROMISE path=(?P<path>\S+) ip=(?P<ip>\S+) \S+ attack_type=(?P<attack_type>\S+) payload="(?P<payload>.*)" status=SUCCESS'
    )

    _ATTACK_TYPE_LABELS = {
        "sql_injection": "SQL Injection",
        "xss": "XSS",
        "cross_site_scripting": "XSS",
        "ssti": "SSTI",
        "server_side_template_injection": "SSTI",
        "xml_external_entity": "XXE (XML External Entity)",
        "insecure_deserialization": "Insecure Deserialization",
        "server_side_request_forgery": "SSRF",
        "ssrf": "SSRF",
        "command_injection": "Command Injection",
        "path_traversal": "Path Traversal",
    }

    _STAGE_LABELS = {
        "2": "Stage 2 — XSS / SSTI",
        "3": "Stage 3 — XXE",
        "4": "Stage 4 — Insecure Deserialization",
        "5": "Stage 5 — SSRF",
    }

    def format_attack_type(raw):
        key = raw.lower()
        if key in _ATTACK_TYPE_LABELS:
            return _ATTACK_TYPE_LABELS[key]
        return raw.replace('_', ' ')

    def infer_payload_type(body):
        """Infer the attack type from raw payload body text."""
        b = body.lower()
        # SSTI – check before XSS so {{ }} is caught first
        if any(p in b for p in ["{{", "${", "{% ", "{%", "#{", "freemarker"]):
            return "SSTI"
        # SQL Injection
        if any(p in b for p in ["select ", "union ", "drop ", "insert ", "delete ",
                                  "update ", "' or ", "or 1=1", "--", "/*", "#",
                                  "sleep(", "benchmark(", "waitfor", "xp_cmdshell"]):
            return "SQL Injection"
        # XSS
        if any(p in b for p in ["<script", "javascript:", "onerror=", "onload=", "onclick=",
                                  "onfocus=", "alert(", "prompt(", "confirm(", "eval(",
                                  "<img", "<svg", "<iframe", "<body"]):
            return "XSS"
        # Command Injection
        if any(p in b for p in ["; ls", "; cat", "; id", "; whoami", "| ls", "| cat",
                                  "/bin/sh", "/bin/bash", "cmd.exe", "&& "]):
            return "Command Injection"
        # Path Traversal
        if any(p in b for p in ["../", "..\\", "/etc/passwd", "/etc/shadow", "boot.ini"]):
            return "Path Traversal"
        # XXE
        if any(p in b for p in ["<!entity", "<!doctype", "system \"", "system '",
                                  "expect://", "php://", "data://"]):
            return "XXE (XML External Entity)"
        return "Unknown"

    # Single-pass: track the most recent attack event seen per IP *as we go*.
    # When a /honeypot access log line is encountered, we use whatever attack info
    # was seen most recently for that IP — this avoids stale cross-session lookups.
    last_attack_per_ip = {}  # ip -> {"attack_type": ..., "payload_type": ...}

    try:
        with open(log_file, 'r') as f:
            for line in f:
                # --- Stage compromise lines: directly add to high_risk_events ---
                m = stage_compromise_pattern.match(line)
                if m:
                    stage = m.group('stage')
                    attack_label = format_attack_type(m.group('attack_type'))
                    stage_label = _STAGE_LABELS.get(stage, f"Stage {stage}")
                    high_risk_events.append({
                        "timestamp": m.group('timestamp'),
                        "ip": m.group('ip'),
                        "path": m.group('path'),
                        "risk_level": "High",
                        "attack_type": f"{stage_label} — {attack_label}",
                        "payload": m.group('payload')[:120] or attack_label,
                        "attack_category": attack_label
                    })
                    continue

                # --- Attack-signal lines: update the rolling lookup ---
                m = attack_detected_pattern.match(line)
                if m:
                    ip = m.group('ip')
                    label = format_attack_type(m.group('attack_type'))
                    last_attack_per_ip[ip] = {"attack_type": label, "payload_type": label}
                    continue

                m = payload_pattern.match(line)
                if m:
                    ip = m.group('ip')
                    payload_type = infer_payload_type(m.group('body'))
                    last_attack_per_ip[ip] = {"attack_type": "Honeypot Interaction", "payload_type": payload_type}
                    continue

                redirect_match = redirect_pattern.match(line)
                if redirect_match:
                    redirect_logs.append(redirect_match.groupdict())
                    continue

                match = legacy_pattern.match(line) or app_logger_pattern.match(line)
                if match:
                    # total_requests += 1 # This is now handled by count_hits
                    data = match.groupdict()
                    path = data['path']
                    if path in ignore_paths or any(path.startswith(p) for p in ignore_prefixes):
                        continue
                    method = data['method']
                    status = data['status']
                    timestamp_str = data['timestamp']
                    
                    # Parse timestamp and aggregate by hour
                    try:
                        # Try legacy format first, then current logger format
                        dt_object = None
                        try:
                            dt_object = datetime.strptime(timestamp_str, "%d/%b/%Y %H:%M:%S")
                        except ValueError:
                            dt_object = datetime.strptime(timestamp_str.split()[0] + " " + timestamp_str.split()[1], "%Y-%m-%d %H:%M:%S,%f")
                        hourly_key = dt_object.strftime("%Y-%m-%d %H:00")
                        requests_over_time[hourly_key] += 1
                        month_key = dt_object.strftime("%Y-%m")
                        requests_by_month[month_key] += 1
                    except ValueError:
                        app.logger.warning(f"Could not parse timestamp: {timestamp_str}")

                    method_counts[method] += 1
                    status_counts[status] += 1

                    # Add the current log entry to all_access_logs
                    all_access_logs.append({
                        "timestamp": data['timestamp'],
                        "ip": data['ip'],
                        "method": data['method'],
                        "path": data['path'],
                        "status": data['status'],
                        "user_agent": data['user_agent']
                    })

                    if "/honeypot" in path:
                        # malicious_count += 1 # Handled by count_hits
                        honeypot_hits += 1 # Keep this for high_risk_events, will use hits_data for overall count
                        # Assuming all honeypot hits are high-risk for now
                        info = last_attack_per_ip.get(data['ip'], {})
                        category = info.get("payload_type", info.get("attack_type", "Unknown"))
                        high_risk_events.append({
                            "timestamp": data['timestamp'],
                            "ip": data['ip'],
                            "path": path,
                            "risk_level": "High",
                            "attack_type": info.get("attack_type", "Honeypot Interaction"),
                            "payload": category,
                            "attack_category": category
                        })
                    # else:
                        # legit_count += 1 # Handled by count_hits
    except FileNotFoundError:
        app.logger.error(f"Log file not found: {log_file}")
        
    risk_labels = ["Honeypot Hits", "Legitimate Requests"]
    risk_values = [hits_data["honeypot_hits"], hits_data["legit_count"]]

    # Build attack type counts for the Threat Radar chart
    # Always include all 5 attack categories so the radar renders as a polygon
    _ALL_RADAR_CATEGORIES = [
        "XSS", "SSTI", "SQL Injection",
        "XXE (XML External Entity)", "Insecure Deserialization",
        "SSRF", "Command Injection", "Path Traversal"
    ]
    attack_type_counts = {cat: 0 for cat in _ALL_RADAR_CATEGORIES}
    for event in high_risk_events:
        category = event.get("attack_category") or event.get("payload", "Unknown")
        if category in attack_type_counts:
            attack_type_counts[category] += 1
        elif category and category not in ("Unknown", "Honeypot Interaction"):
            attack_type_counts[category] = attack_type_counts.get(category, 0) + 1
    # Remove zero-count categories that were never seen to keep the radar clean
    attack_type_counts = {k: v for k, v in attack_type_counts.items() if v > 0} or {"No Attacks": 0}

    # Sort requests over time data for chronological display
    sorted_times = sorted(requests_over_time.keys())
    time_labels = sorted_times
    time_values = [requests_over_time[t] for t in sorted_times]

    # Sort months to keep chart ordering consistent
    sorted_months = sorted(requests_by_month.keys())
    month_labels = sorted_months
    month_values = [requests_by_month[m] for m in sorted_months]

    return {
        "total_requests": hits_data["total_requests"],
        "legit_count": hits_data["legit_count"],
        "malicious_count": hits_data["malicious_count"],
        "honeypot_hits": hits_data["honeypot_hits"],
        "risk_labels": risk_labels,
        "risk_values": risk_values,
        "high_risk_events": high_risk_events,
        "method_labels": list(method_counts.keys()),
        "method_values": list(method_counts.values()),
        "status_labels": list(status_counts.keys()),
        "status_values": list(status_counts.values()),
        "time_labels": time_labels,
        "time_values": time_values,
        "month_labels": month_labels,
        "month_values": month_values,
        "all_access_logs": all_access_logs,
        "redirect_logs": redirect_logs,
        "attack_type_labels": list(attack_type_counts.keys()),
        "attack_type_values": list(attack_type_counts.values())
    }


@app.route('/gemini_fixes_view')
def gemini_fixes_view():
    return render_template('gemini_fixes.html')


@app.route('/apply_fixes', methods=['POST'])
def apply_fixes():
    import json as _json
    data = request.get_json()
    if not data or 'fixes' not in data:
        return jsonify({"error": "No fixes provided"}), 400

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    results = []
    status_records = []
    files_written = {}

    for fix in data['fixes']:
        corrected_file = fix.get('corrected_file', '')
        explanation = fix.get('explanation', '')
        filepath = fix.get('file', '')

        if not corrected_file or not filepath:
            results.append({"stage": fix['stage'], "status": "skipped"})
            status_records.append({
                "stage": fix['stage'], "type": fix.get('type', ''),
                "file": filepath, "status": "skipped",
                "explanation": explanation, "fixed_code": ""
            })
            continue

        if filepath in files_written:
            results.append({"stage": fix['stage'], "status": "applied", "file": filepath})
            status_records.append({
                "stage": fix['stage'], "type": fix.get('type', ''),
                "file": filepath, "status": "applied",
                "explanation": explanation, "fixed_code": ""
            })
            continue

        try:
            file_path = os.path.join(BASE_DIR, filepath)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(corrected_file)
            files_written[filepath] = True

            results.append({"stage": fix['stage'], "status": "applied", "file": filepath})
            status_records.append({
                "stage": fix['stage'], "type": fix.get('type', ''),
                "file": filepath, "status": "applied",
                "explanation": explanation, "fixed_code": ""
            })
        except Exception as e:
            results.append({"stage": fix['stage'], "status": "error", "error": str(e)})
            status_records.append({
                "stage": fix['stage'], "type": fix.get('type', ''),
                "file": filepath, "status": "error",
                "explanation": explanation, "fixed_code": ""
            })

    status_path = os.path.join(BASE_DIR, 'fixes_status.json')
    with open(status_path, 'w', encoding='utf-8') as f:
        _json.dump({
            "applied_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "fixes": status_records
        }, f, indent=2)

    applied = sum(1 for r in results if r['status'] == 'applied')
    return jsonify({"results": results, "applied": applied})


@app.route('/fixes_status', methods=['GET'])
def fixes_status():
    import json as _json
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    status_path = os.path.join(BASE_DIR, 'fixes_status.json')
    if not os.path.exists(status_path):
        return jsonify({"applied_at": None, "fixes": []})
    with open(status_path, 'r', encoding='utf-8') as f:
        return jsonify(_json.load(f))


@app.route('/verify_and_apply_fixes', methods=['POST'])
def verify_and_apply_fixes():
    """
    Passes Groq's fix suggestions to the Claude CLI for verification and application.
    Claude reads the original file, checks Groq's proposed fix for correctness and
    consistency, then writes the properly corrected file to disk.
    """
    import subprocess
    import json as _json

    data = request.get_json()
    if not data or 'fixes' not in data:
        return jsonify({"error": "No fixes provided"}), 400

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    results = []
    status_records = []

    # Group fixes by file so all snippets for the same file go to Claude in one pass
    from collections import defaultdict
    fixes_by_file = defaultdict(list)
    for fix in data['fixes']:
        if fix.get('file') and fix.get('corrected_file'):
            fixes_by_file[fix['file']].append(fix)
        else:
            results.append({"stage": fix.get('stage'), "status": "skipped", "reason": "no corrected file"})
            status_records.append({
                "stage": fix.get('stage'), "type": fix.get('type', ''),
                "file": fix.get('file', ''), "status": "skipped",
                "explanation": fix.get('explanation', ''), "fixed_code": ""
            })

    import tempfile

    for filepath, file_fixes in fixes_by_file.items():
        full_path = os.path.join(BASE_DIR, filepath)

        # Build a single temp file listing all Groq snippets for this file
        combined = ""
        for fx in file_fixes:
            combined += (
                f"=== Stage {fx['stage']} — {fx['type']} ===\n"
                f"Vulnerability: {fx.get('explanation', '')}\n"
                f"Groq's fix (lines {fx.get('lines', [0,0])}):\n"
                f"{fx['corrected_file']}\n\n"
            )

        tmp_fd, tmp_path = tempfile.mkstemp(suffix='.txt', prefix='groq_fixes_')
        try:
            with os.fdopen(tmp_fd, 'w', encoding='utf-8') as tf:
                tf.write(combined)
        except Exception:
            os.close(tmp_fd)

        vuln_types = ", ".join(fx['type'] for fx in file_fixes)

        prompt = (
            f"Read the original file at: {full_path}\n"
            f"Read Groq's suggested fix snippets from: {tmp_path}\n\n"
            f"Groq identified these vulnerabilities in the file: {vuln_types}\n\n"
            f"Your job:\n"
            f"1. For each fix snippet in {tmp_path}, locate that vulnerable section in {full_path}.\n"
            f"2. Check if each Groq snippet correctly resolves its vulnerability.\n"
            f"3. Apply all fixes to {full_path} — one at a time, carefully.\n"
            f"4. If any snippet introduces inconsistencies (broken imports, wrong variable names, "
            f"mismatched signatures, syntax errors, logic that no longer wires up), "
            f"fix those too — but touch nothing else.\n"
            f"5. If a snippet is wrong or incomplete, apply the minimal correct fix yourself.\n\n"
            f"Rules — strictly enforced:\n"
            f"- Only change what is needed to fix the vulnerabilities and any inconsistency they cause.\n"
            f"- Do NOT refactor, rename, reformat, or touch any unrelated code.\n"
            f"- Preserve all routes, functions, logic, and structure exactly as they are.\n"
            f"- After all edits, verify the file is self-consistent from top to bottom.\n"
            f"- Do not explain. Just read, verify, and apply."
        )

        try:
            proc = subprocess.run(
                ['claude', '-p', prompt, '--allowedTools', 'Read,Edit,Write',
                 '--dangerously-skip-permissions', '--output-format', 'text'],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=BASE_DIR
            )
            ok = proc.returncode == 0
            err_msg = "" if ok else (proc.stderr.strip() or proc.stdout.strip())[:300]

            for fx in file_fixes:
                results.append({
                    "stage": fx['stage'],
                    "status": "applied" if ok else "error",
                    "file": filepath,
                    **({"error": err_msg} if not ok else {})
                })
                status_records.append({
                    "stage": fx['stage'], "type": fx.get('type', ''),
                    "file": filepath,
                    "status": "applied" if ok else "error",
                    "explanation": fx.get('explanation', ''),
                    "fixed_code": proc.stdout[:300] if ok else ""
                })
        except subprocess.TimeoutExpired:
            for fx in file_fixes:
                results.append({"stage": fx['stage'], "status": "error", "error": "Claude CLI timed out"})
                status_records.append({
                    "stage": fx['stage'], "type": fx.get('type', ''), "file": filepath,
                    "status": "error", "explanation": "Claude CLI timed out", "fixed_code": ""
                })
        except FileNotFoundError:
            return jsonify({"error": "Claude CLI not found. Make sure 'claude' is installed and on PATH."}), 500
        except Exception as e:
            for fx in file_fixes:
                results.append({"stage": fx['stage'], "status": "error", "error": str(e)})
                status_records.append({
                    "stage": fx['stage'], "type": fx.get('type', ''), "file": filepath,
                    "status": "error", "explanation": str(e), "fixed_code": ""
                })
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    # Persist status for admin dashboard
    status_path = os.path.join(BASE_DIR, 'fixes_status.json')
    with open(status_path, 'w', encoding='utf-8') as f:
        _json.dump({
            "applied_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "fixes": status_records
        }, f, indent=2)

    applied = sum(1 for r in results if r['status'] == 'applied')
    return jsonify({"results": results, "applied": applied})


_VULNERABLE_STAGES = [
    {"stage": 1, "type": "Reconnaissance",            "file": "template/main/stage1_recon.html", "route": None},
    {"stage": 2, "type": "XSS / SSTI",                "file": "app.py", "route": "/legacy_login"},
    {"stage": 3, "type": "XXE (XML External Entity)", "file": "app.py", "route": "/profile"},
    {"stage": 4, "type": "Insecure Deserialization",  "file": "app.py", "route": "/verify_token"},
    {"stage": 5, "type": "SSRF",                      "file": "app.py", "route": "/diagnose"},
]


def _extract_route_snippet(content, route_path):
    lines = content.splitlines()
    start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if (f"'{route_path}'" in stripped or f'"{route_path}"' in stripped) \
                and stripped.startswith('@app.route'):
            start = i
            break
    if start is None:
        return content, 1, len(lines)
    end = len(lines)
    past_def = False
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if not past_def:
            if line.startswith('def ') or line.startswith('async def '):
                past_def = True
            continue
        if line and not line[0].isspace():
            end = i
            break
    return '\n'.join(lines[start:end]), start + 1, end


@app.route('/get_fix/<int:stage>', methods=['GET'])
def get_fix_stage(stage):
    """Fetch the Groq fix for a single stage. Called per-stage from the frontend."""
    from groq import Groq

    vuln = next((v for v in _VULNERABLE_STAGES if v['stage'] == stage), None)
    if not vuln:
        return jsonify({"error": f"Unknown stage {stage}"}), 404

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    full_path = os.path.join(BASE_DIR, vuln['file'])

    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            file_content = f.read()
    except Exception as e:
        return jsonify({"error": f"Cannot read {vuln['file']}: {e}"}), 500

    if vuln['route']:
        snippet, line_start, line_end = _extract_route_snippet(file_content, vuln['route'])
    else:
        snippet = file_content
        line_start, line_end = 1, len(file_content.splitlines())

    prompt = (
        f"You are a cybersecurity expert. This code has a {vuln['type']} vulnerability.\n"
        f"File: {vuln['file']}\n\n"
        f"Vulnerable code:\n```\n{snippet}\n```\n\n"
        f"Respond in this EXACT format — nothing else:\n"
        f"EXPLANATION: <one sentence: what is vulnerable and how to fix it>\n"
        f"FIXED_CODE:\n```\n<corrected version of the snippet above only>\n```"
    )

    try:
        client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=3000,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = response.choices[0].message.content.strip()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    exp_match = re.search(r'EXPLANATION:\s*(.+)', raw)
    code_match = re.search(r'FIXED_CODE:\s*```[^\n]*\n([\s\S]*?)```', raw)

    return jsonify({
        "stage": vuln["stage"],
        "type": vuln["type"],
        "file": vuln["file"],
        "lines": [line_start, line_end],
        "code": snippet,
        "explanation": exp_match.group(1).strip() if exp_match else "See fix below.",
        "suggestion": raw,
        "corrected_file": code_match.group(1).strip() if code_match else snippet
    })


@app.route('/get_fixes', methods=['GET'])
def get_fixes():
    """Legacy route kept for compatibility — redirects to per-stage calls."""
    return jsonify({"error": "Use /get_fix/<stage> instead"}), 410


@app.route('/open_terminal', methods=['POST'])
def open_terminal():
    import subprocess
    script = (
        "Write-Host ''; "
        "Write-Host '[*] Initializing Patch Management Engine...' -ForegroundColor Green; Start-Sleep 3; "
        "Write-Host '[*] Connecting to vulnerability database...' -ForegroundColor Green; Start-Sleep 4; "
        "Write-Host '[*] Loading CVE signatures...' -ForegroundColor Green; Start-Sleep 3; "
        "Write-Host '[*] Authenticating with patch server...' -ForegroundColor Green; Start-Sleep 5; "
        "Write-Host '[*] Requesting Gemini API token...' -ForegroundColor Green; Start-Sleep 3; "
        "Write-Host '[*] Establishing secure session with Gemini AI model...' -ForegroundColor Green; Start-Sleep 4; "
        "Write-Host '[*] Fetching vulnerability intelligence from Gemini...' -ForegroundColor Green; Start-Sleep 5; "
        "Write-Host '[*] AI analysis complete -- 5 critical vulnerabilities mapped.' -ForegroundColor White; Start-Sleep 3; "
        "Write-Host '[*] Scanning Stage 1 -- Reconnaissance...' -ForegroundColor White; Start-Sleep 4; "
        "Write-Host '[*] Scanning Stage 2 -- XSS / SSTI...' -ForegroundColor White; Start-Sleep 5; "
        "Write-Host '[*] Scanning Stage 3 -- XXE Injection...' -ForegroundColor White; Start-Sleep 4; "
        "Write-Host '[*] Scanning Stage 4 -- Insecure Deserialization...' -ForegroundColor White; Start-Sleep 5; "
        "Write-Host '[*] Scanning Stage 5 -- SSRF...' -ForegroundColor White; Start-Sleep 4; "
        "Write-Host '[*] Generating remediation patches...' -ForegroundColor Green; Start-Sleep 6; "
        "Write-Host '[*] Validating patch integrity...' -ForegroundColor Green; Start-Sleep 5; "
        "Write-Host '[*] Verifying deployment...' -ForegroundColor Green; Start-Sleep 5; "
        "Write-Host '[*] Running final security checks...' -ForegroundColor Green; Start-Sleep 5; "
        "Write-Host ''; "
        "Write-Host '[X] PATCH DEPLOYMENT FAILED -- Access Denied by System Policy.' -ForegroundColor Red; "
        "Write-Host '[X] Rollback initiated. No changes were applied.' -ForegroundColor Red; "
        "Write-Host ''; "
        "Write-Host 'Press any key to exit...'; $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')"
    )
    subprocess.Popen(
        ['powershell', '-NoExit', '-Command', script],
        creationflags=subprocess.CREATE_NEW_CONSOLE
    )
    return jsonify({'status': 'ok'})


@app.route('/admin')
def admin_page():
    log_data = process_logs()
    return render_template('admin.html', **log_data)

@app.route('/admin_data')
def admin_data():
    log_data = process_logs()
    return jsonify(log_data)


if __name__ == "__main__":
    app.run(debug=True, port="5001")
