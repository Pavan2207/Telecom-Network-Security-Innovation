import subprocess
import datetime
import os
import time

def capture_live_traffic(duration_seconds=30, output_dir="logs", tshark_path="C:\\Program Files\\Wireshark\\tshark.exe"):
    """
    Captures live network traffic using tshark and saves it as a .pcap file,
    then converts the .pcap to a .csv file.

    Args:
        duration_seconds (int): The duration of the capture in seconds.
        output_dir (str): The directory to save the log files.
        tshark_path (str): The full path to the tshark.exe executable.

    Returns:
        str or None: The path to the generated CSV file if successful, None otherwise.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_filename = os.path.join(output_dir, f"live_traffic_{timestamp}.pcap")
    csv_filename = os.path.join(output_dir, f"live_traffic_{timestamp}.csv")

    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Starting live packet capture to {pcap_filename} for {duration_seconds} seconds using {tshark_path}...")

    try:
        # --- Step 1: Capture live traffic using tshark ---
        # IMPORTANT: Replace 'Wi-Fi' with your actual network interface name.
        # You can find your interface names by running 'tshark -D' in Command Prompt.
        # This command might require administrator privileges to run successfully.
        tshark_capture_command = [
            tshark_path, '-i', 'Wi-Fi',  # <--- !!! CHANGE 'Wi-Fi' TO YOUR INTERFACE NAME !!!
            '-a', f'duration:{duration_seconds}',
            '-w', pcap_filename
        ]
        print(f"Executing command: {' '.join(tshark_capture_command)}")
        subprocess.run(tshark_capture_command, check=True, creationflags=subprocess.CREATE_NO_WINDOW) # CREATE_NO_WINDOW hides the tshark console

        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Live capture complete. Converting {pcap_filename} to CSV...")

        # --- Step 2: Export the captured .pcap to a .csv ---
        # This command extracts specific fields from the .pcap and formats them as CSV.
        tshark_export_command = [
            tshark_path, '-r', pcap_filename,
            '-T', 'fields',
            '-e', 'frame.time',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'udp.srcport',
            '-e', 'udp.dstport',
            '-e', 'frame.len',
            '-E', 'header=y',      # Include header row
            '-E', 'separator=,'    # Use comma as separator
        ]
        print(f"Executing command: {' '.join(tshark_export_command)}")
        with open(csv_filename, 'w') as f:
            subprocess.run(tshark_export_command, stdout=f, check=True, creationflags=subprocess.CREATE_NO_WINDOW)

        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Converted {pcap_filename} to {csv_filename}.")
        return csv_filename

    except FileNotFoundError:
        print(f"Error: tshark.exe not found at '{tshark_path}'. Please ensure the path is correct.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error during tshark execution: {e}")
        print(f"Command '{' '.join(e.cmd)}' returned non-zero exit status {e.returncode}.")
        print("Please ensure you have the necessary permissions to capture traffic (e.g., run your script as administrator).")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

# --- How to integrate this into your Streamlit app (app.py) ---

# Import streamlit
import streamlit as st
import pandas as pd # Assuming you'll use pandas to read the CSV

# Example usage within your Streamlit app
def main():
    st.title("Live Traffic Monitor")

    # You can get the tshark path from user input or keep it hardcoded if known
    # tshark_exe_path = st.text_input("Path to tshark.exe", "C:\\Program Files\\Wireshark\\tshark.exe")
    tshark_exe_path = "C:\\Program Files\\Wireshark\\tshark.exe" # Hardcoded for demonstration

    st.write("---")

    if st.button("Start Live Traffic Capture (30 seconds)"):
        with st.spinner("Capturing live traffic... This might take a moment and require administrator privileges."):
            captured_csv_file = capture_live_traffic(duration_seconds=30, tshark_path=tshark_exe_path)

        if captured_csv_file:
            st.success(f"Live traffic captured and saved to: `{captured_csv_file}`")
            try:
                # Display the captured data
                df_captured = pd.read_csv(captured_csv_file)
                st.subheader("Captured Traffic Data (First 10 rows):")
                st.dataframe(df_captured.head(10))

                # You can then perform analysis or visualization on df_captured
            except Exception as e:
                st.error(f"Error reading captured CSV file: {e}")
        else:
            st.error("Failed to capture live traffic. Check console for errors.")

if __name__ == "__main__":
    main()