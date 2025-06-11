# backend/packet_sniffer.py
import time
import pandas as pd
import os
from datetime import datetime
import subprocess
import re

# IMPORTANT: Define the full path to tshark.exe
# You MUST adjust this path if your Wireshark installation is elsewhere.
TSHARK_PATH = "C:\\Program Files\\Wireshark\\tshark.exe"

def capture_packets(output_csv_file, duration=30):
    """
    Captures live network packets using tshark and saves relevant HTTP/HTTPS fields
    to a CSV file. Specifically targets common web ports for telecom-related interactions.

    Args:
        output_csv_file (str): The path to the CSV file where captured data will be saved.
        duration (int): The duration of the capture in seconds.
    """
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting live packet capture to {output_csv_file} for {duration} seconds using tshark...")

    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_csv_file), exist_ok=True)

    # Temporary pcap file to store raw capture before conversion to CSV
    temp_pcap_file = output_csv_file.replace(".csv", ".pcap")

    try:
        # --- Step 1: Capture live traffic to a .pcap file ---
        # Using -f "tcp port 80 or tcp port 443 or tcp port 22 or tcp port 23 or tcp port 3389"
        # to filter for common web (HTTP/S), SSH, Telnet, RDP ports, which are relevant in telecom.
        # -i <interface> MUST be changed to your actual network interface!
        # Run 'tshark -D' in Command Prompt to list interfaces.
        tshark_capture_command = [
            TSHARK_PATH,
            '-i', 'Wi-Fi',  # <--- !!! CHANGE THIS TO YOUR ACTUAL NETWORK INTERFACE NAME (e.g., 'Ethernet', 'Wi-Fi') !!!
            '-a', f'duration:{duration}',
            '-w', temp_pcap_file,
            '-f', 'tcp port 80 or tcp port 443 or tcp port 22 or tcp port 23 or tcp port 3389' # Focus on web, SSH, Telnet, RDP
        ]
        print(f"Executing capture command: {' '.join(tshark_capture_command)}")
        # Use subprocess.CREATE_NO_WINDOW to hide the tshark console on Windows
        subprocess.run(tshark_capture_command, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Live capture complete. Data saved to {temp_pcap_file}.")

        # --- Step 2: Read the .pcap and export specific fields to CSV ---
        # We need to extract: timestamp, source IP, dest IP, protocol, port,
        # HTTP Host, URI, Method, and raw payload for analysis.
        # For 'raw_payload' in tshark, it's not a direct field. We'll use frame.len as size
        # and rely on parsing for sensitive info.
        tshark_export_command = [
            TSHARK_PATH,
            '-r', temp_pcap_file,
            '-T', 'fields',
            '-e', 'frame.time',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport', # Include UDP for completeness (e.g., DNS)
            '-e', 'udp.dstport',
            '-e', 'frame.len', # Captured length of the frame
            '-e', 'http.host', # HTTP host header
            '-e', 'http.request.uri', # HTTP request URI
            '-e', 'http.request.method', # HTTP request method
            '-e', 'data.text', # Attempts to extract text data from TCP/UDP segments, may contain payload snippets
            '-E', 'header=y',
            '-E', 'separator=,',
            '-E', 'quote=d' # Quote fields to handle commas or special characters
        ]
        print(f"Executing export command: {' '.join(tshark_export_command)}")
        with open(output_csv_file, 'w', encoding='utf-8', newline='') as f: # newline='' for correct CSV writing
            subprocess.run(tshark_export_command, stdout=f, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Converted {temp_pcap_file} to {output_csv_file}.")

        # Clean up the temporary pcap file
        os.remove(temp_pcap_file)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Cleaned up temporary file: {temp_pcap_file}")

        # --- Step 3: Post-process the CSV to standardize column names and add 'protocol' ---
        df = pd.read_csv(output_csv_file)

        # Sanitize column names: replace '.' with '_' and convert to lowercase
        df.columns = [re.sub(r'\.', '_', col).lower() for col in df.columns]

        # Standardize 'frame_time' to 'timestamp'
        df.rename(columns={'frame_time': 'timestamp'}, inplace=True)

        # Add 'protocol' column based on common ports
        df['protocol'] = 'Other'
        if 'tcp_srcport' in df.columns or 'tcp_dstport' in df.columns:
            df.loc[(df['tcp_srcport'].notna() | df['tcp_dstport'].notna()), 'protocol'] = 'TCP'
            df.loc[(df['tcp_srcport'] == 80) | (df['tcp_dstport'] == 80), 'protocol'] = 'HTTP'
            df.loc[(df['tcp_srcport'] == 443) | (df['tcp_dstport'] == 443), 'protocol'] = 'HTTPS'
            df.loc[(df['tcp_srcport'] == 22) | (df['tcp_dstport'] == 22), 'protocol'] = 'SSH'
            df.loc[(df['tcp_srcport'] == 23) | (df['tcp_dstport'] == 23), 'protocol'] = 'Telnet'
            df.loc[(df['tcp_srcport'] == 3389) | (df['tcp_dstport'] == 3389), 'protocol'] = 'RDP'

        if 'udp_srcport' in df.columns or 'udp_dstport' in df.columns:
             df.loc[(df['udp_srcport'].notna() | df['udp_dstport'].notna()), 'protocol'] = 'UDP'
             df.loc[(df['udp_srcport'] == 53) | (df['udp_dstport'] == 53), 'protocol'] = 'DNS'


        # Consolidate source/destination IPs and ports
        df.rename(columns={
            'ip_src': 'source_ip',
            'ip_dst': 'destination_ip',
            'frame_len': 'size_bytes'
        }, inplace=True)

        # Determine the primary port (destination port is often more indicative for client-server)
        df['port'] = df['tcp_dstport'].fillna(df['udp_dstport']).fillna(df['tcp_srcport']).fillna(df['udp_srcport'])
        df['port'] = df['port'].astype(str).replace('.0', '', regex=False) # Clean float representation

        # Rename payload field if it exists, otherwise fill with empty string
        if 'data_text' in df.columns:
            df.rename(columns={'data_text': 'raw_payload'}, inplace=True)
        else:
            df['raw_payload'] = '' # Ensure 'raw_payload' column always exists

        # Rename http fields for consistency with analyzer
        df.rename(columns={
            'http_host': 'http.host',
            'http_request_uri': 'http.request.uri',
            'http_request_method': 'http.request.method'
        }, inplace=True)

        # Select and reorder columns for the final CSV to ensure consistency with analyzer
        desired_columns = [
            "timestamp", "source_ip", "destination_ip", "protocol", "port", "size_bytes",
            "http.host", "http.request.uri", "http.request.method", "raw_payload"
        ]
        # Only include columns that actually exist in the DataFrame
        df = df[[col for col in desired_columns if col in df.columns]]

        df.to_csv(output_csv_file, index=False)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Post-processed CSV saved to {output_csv_file}.")

    except FileNotFoundError:
        print(f"Error: tshark.exe not found at '{TSHARK_PATH}'. Please ensure Wireshark/tshark is installed and the path is correct.")
        pd.DataFrame().to_csv(output_csv_file, index=False) # Create empty CSV to prevent app crash
    except subprocess.CalledProcessError as e:
        print(f"Error during tshark execution: {e}")
        print(f"Command '{' '.join(e.cmd)}' returned non-zero exit status {e.returncode}.")
        print("Please ensure you have the necessary permissions (run as administrator) and the correct network interface.")
        pd.DataFrame().to_csv(output_csv_file, index=False) # Create empty CSV
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        pd.DataFrame().to_csv(output_csv_file, index=False) # Create empty CSV