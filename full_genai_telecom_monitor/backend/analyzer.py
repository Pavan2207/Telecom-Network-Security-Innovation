# backend/analyzer.py
import pandas as pd
import io
import os
import re
from . import flagged_sites

# Regex for basic email validation
EMAIL_REGEX = r"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"
# Regex for basic URL validation
URL_REGEX = r"https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[\da-fA-F]{2}))+"
# Keywords commonly found in password/credential data
PASSWORD_KEYWORDS = ["password", "pwd", "pass", "secret", "login_id", "credentials", "auth_token", "api_key", "token", "userpass", "oldpass", "newpass"]
# Keywords for potential telecom exploit tools/signatures (simplified for simulation)
TELECOM_EXPLOIT_KEYWORDS = ["ss7", "diameter", "gprs", "lte", "5g", "ims", "ran", "core network", "oam", "oss", "bss", "cli", "shell", "exec", "sudo", "root", "admin", "vulnerability", "exploit", "cve", "backdoor"]


def validate_email_syntax(email):
    """Checks if an email string has a valid basic syntax."""
    return re.fullmatch(EMAIL_REGEX, email) is not None

def validate_url_syntax(url):
    """Checks if a URL string has a valid basic syntax."""
    return re.fullmatch(URL_REGEX, url) is not None

def analyze_traffic(log_file):
    """
    Analyzes a network traffic log file (CSV) to detect various anomalies,
    with a focus on telecom infrastructure threats.
    """
    if not os.path.exists(log_file):
        return "Error: Log file not found."

    try:
        df = pd.read_csv(log_file)
        if df.empty:
            return "No data to analyze in the log file."

        # Fill NaN values in relevant columns to prevent errors during string operations
        df.fillna('', inplace=True) # Fill all NaN with empty string
        df['port'] = df['port'].astype(str).replace('.0', '', regex=False)


        flags = []
        email_patterns_found = []
        url_patterns_found = []

        for index, row in df.iterrows():
            timestamp = row.get("timestamp", "N/A")
            src_ip = row.get("source_ip", "N/A")
            dst_ip = row.get("destination_ip", "N/A")
            protocol = row.get("protocol", "N/A")
            port = str(row.get("port", "N/A")) # Ensure port is string for comparison
            http_host = str(row.get("http.host", "")).strip()
            http_uri = str(row.get("http.request.uri", "")).strip()
            http_method = str(row.get("http.request.method", "")).strip()
            raw_payload = str(row.get("raw_payload", "")).lower()

            # Consolidate text to search for keywords (URI + payload)
            search_text = (http_uri + " " + raw_payload).lower()

            # 1. Insecure Communication (HTTP, Telnet, RDP without encryption)
            if protocol == "HTTP": # This means tcp port 80
                if http_method == "POST":
                    flags.append({
                        "type": "Insecure HTTP POST (Potential Credential Leak)",
                        "message": f"Sensitive data likely sent over unencrypted HTTP: {src_ip} -> http://{http_host}{http_uri}",
                        "timestamp": timestamp
                    })
                else:
                    flags.append({
                        "type": "Insecure HTTP Connection",
                        "message": f"Unencrypted HTTP connection detected: {src_ip} -> http://{http_host}{http_uri}",
                        "timestamp": timestamp
                    })
            if protocol == "Telnet" and port == "23":
                flags.append({
                    "type": "Insecure Telnet Usage (High Risk)",
                    "message": f"Clear-text remote access protocol detected: {src_ip} -> {dst_ip}:{port}",
                    "timestamp": timestamp
                })
            # RDP usually encrypts, but clear-text passwords might still be seen in specific scenarios or if not properly configured
            if protocol == "RDP" and port == "3389" and any(keyword in raw_payload for keyword in PASSWORD_KEYWORDS):
                 flags.append({
                    "type": "Potential RDP Credential Exposure",
                    "message": f"Suspicious password-related keywords in RDP traffic: {src_ip} -> {dst_ip}:{port}",
                    "timestamp": timestamp
                 })

            # 2. Clear-text Password/Credential Detection (across various protocols if payload captured)
            # This is a heuristic and depends heavily on tshark's 'data.text' field capturing actual content.
            # Particularly relevant for HTTP (port 80) or potentially even non-encrypted parts of other protocols
            if any(keyword in search_text for keyword in PASSWORD_KEYWORDS):
                # Filter out HTTPS unless the keyword is in URI (less common for passwords)
                if protocol == "HTTPS" and any(keyword in http_uri.lower() for keyword in PASSWORD_KEYWORDS):
                    flags.append({
                        "type": "Suspicious Keyword in HTTPS URI (Review)",
                        "message": f"Password-related keyword '{[k for k in PASSWORD_KEYWORDS if k in http_uri.lower()][0]}' detected in HTTPS URI: {src_ip} -> {http_host}{http_uri}",
                        "timestamp": timestamp
                    })
                elif protocol != "HTTPS": # For HTTP, SSH, Telnet, or other potentially cleartext protocols
                    flags.append({
                        "type": f"Clear-text Credential Pattern ({protocol})",
                        "message": f"Potential password/credential pattern in traffic: {src_ip} -> {dst_ip}:{port} (Keywords: {', '.join([k for k in PASSWORD_KEYWORDS if k in search_text])})",
                        "timestamp": timestamp
                    })

            # 3. Telecom-Specific Exploit/Malware Signatures (simplified regex match)
            if any(keyword in search_text for keyword in TELECOM_EXPLOIT_KEYWORDS):
                flags.append({
                    "type": "Telecom Exploit Signature Detected",
                    "message": f"Traffic contains keywords related to telecom exploits: {src_ip} -> {dst_ip} (Keywords: {', '.join([k for k in TELECOM_EXPLOIT_KEYWORDS if k in search_text])})",
                    "timestamp": timestamp
                })

            # 4. Onion Website Access Detection and Flagged Domain Check
            if http_host.endswith(".onion"):
                flags.append({
                    "type": "Onion Site Access",
                    "message": f"detected: {src_ip} -> {http_host}",
                    "timestamp": timestamp
                })
            elif flagged_sites.is_flagged(http_host) or flagged_sites.is_flagged(http_uri):
                flags.append({
                    "type": "Flagged Domain/URL Access",
                    "message": f"detected: {src_ip} -> {http_host}{http_uri}",
                    "timestamp": timestamp
                })

            # 5. Email Syntax and Pattern Check in Payload/URI
            found_emails = re.findall(EMAIL_REGEX, search_text)
            for email in found_emails:
                if not validate_email_syntax(email):
                    flags.append({
                        "type": "Malformed Email",
                        "message": f"detected in traffic from {src_ip}: '{email}'",
                        "timestamp": timestamp
                    })
                else:
                    email_patterns_found.append(email)

            # 6. Link Syntax and Malicious Link Check in Payload/URI
            found_urls = re.findall(URL_REGEX, search_text)
            for url in found_urls:
                if not validate_url_syntax(url):
                    flags.append({
                        "type": "Malformed URL",
                        "message": f"detected in traffic from {src_ip}: '{url}'",
                        "timestamp": timestamp
                    })
                elif flagged_sites.is_flagged(url):
                    flags.append({
                        "type": "Malicious Link Detected",
                        "message": f"detected in traffic from {src_ip}: '{url}'",
                        "timestamp": timestamp
                    })
                else:
                    url_patterns_found.append(url)

        # Generate Report
        report_buffer = io.StringIO()
        report_buffer.write("--- Telecom Anomaly Detection Report ---\n")
        report_buffer.write(f"Analysis conducted on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report_buffer.write(f"Total packets analyzed: {len(df)}\n\n")

        if flags:
            report_buffer.write("### 🚨 Detected Anomalies & Warnings (Timestamped) ###\n")
            for flag in flags:
                report_buffer.write(f"- [{flag['timestamp']}] **{flag['type']}**: {flag['message']}\n")
        else:
            report_buffer.write("✅ No significant anomalies or warnings detected in this traffic sample.\n")

        report_buffer.write("\n--- Traffic Statistics & Insights ---\n")
        report_buffer.write(f"Unique Source IPs: {df['source_ip'].nunique() if 'source_ip' in df.columns else 'N/A'}\n")
        report_buffer.write(f"Unique Destination IPs: {df['destination_ip'].nunique() if 'destination_ip' in df.columns else 'N/A'}\n")
        report_buffer.write(f"Most common protocol: {df['protocol'].mode().iloc[0] if not df['protocol'].empty else 'N/A'}\n")
        report_buffer.write(f"Most common destination port: {df['port'].mode().iloc[0] if not df['port'].empty else 'N/A'}\n")

        if email_patterns_found:
            report_buffer.write(f"\nEmails found in traffic: {', '.join(sorted(list(set(email_patterns_found))))}\n")
        if url_patterns_found:
            report_buffer.write(f"\nURLs found in traffic: {', '.join(sorted(list(set(url_patterns_found))))}\n")

        return report_buffer.getvalue()

    except Exception as e:
        return f"An error occurred during analysis: {e}"