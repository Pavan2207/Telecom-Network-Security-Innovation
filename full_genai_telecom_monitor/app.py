import os
import streamlit as st
from datetime import datetime
import pandas as pd
import re # For regex operations (though analyzer.py handles most)

# Import backend modules
# Ensure these files are in the 'backend' directory relative to app.py
import backend.packet_sniffer
import backend.analyzer
import backend.flagged_sites
import backend.genai_insights

# Set Streamlit page configuration for a wider layout and title
st.set_page_config(page_title="GenAI Telecom Threat Monitor", layout="wide", initial_sidebar_state="expanded")
st.title("📡 GenAI-Assisted Telecom Cyber Threat Monitor")
st.markdown("""
    This application simulates a cutting-edge **GenAI-powered system** for monitoring
    telecom infrastructure for cyber threats. It captures live network traffic (using `tshark`),
    analyzes it for anomalies and known exploit patterns, and then leverages
    **simulated Generative AI** to predict breach points, assess threats, and monitor dark web chatter.
""")
st.markdown("---") # Visual separator

# Define the log file path. It will be placed in a 'logs' directory.
if 'log_file' not in st.session_state:
    st.session_state.log_file = None

# Ensure the logs directory exists
os.makedirs("logs", exist_ok=True)

# --- Sidebar for settings and explanations ---
with st.sidebar:
    st.header("App Settings & Info")
    st.info("""
        **Running Requirements:**
        1. **Wireshark/tshark** installed on your system.
        2. **Run Streamlit as Administrator** for live packet capture.
        3. **Correct network interface** name in `backend/packet_sniffer.py`.
        (e.g., 'Ethernet', 'Wi-Fi' - find using `tshark -D` in CMD)
    """)
    st.subheader("What's Happening?")
    st.markdown("""
        1. **Live Capture:** Uses `tshark` to sniff packets on your selected interface.
           Filters for common telecom-relevant ports (HTTP/S, SSH, Telnet, RDP).
        2. **Anomaly Detection:** Analyzes captured data for insecure communication,
           clear-text credentials, onion site access, flagged domains, and
           simulated telecom exploit signatures.
        3. **GenAI Insights (Simulated):** Provides AI-driven threat predictions,
           breach point analysis, and dark web monitoring context based on the analysis.
    """)
    st.markdown("---")
    st.subheader("Flagged Domains:")
    st.write("Current list of domains considered suspicious:")
    flagged_domains_list = backend.flagged_sites.get_flagged_domains()
    for domain in flagged_domains_list:
        st.markdown(f"- `{domain}`")
    st.caption("This list can be updated in `backend/flagged_sites.py`.")


# --- Main Content Area ---

# Button to start packet capture
if st.button("🚦 Start Live Packet Capture (30s)", key="start_capture_button"):
    current_log_file = f"logs/traffic_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    st.session_state.log_file = current_log_file # Store the current log file path

    st.warning("⚠️ Capturing live traffic requires **Administrator privileges**. Please ensure your terminal/IDE is running as Administrator.")
    with st.spinner(f"Initiating live network traffic capture to `{current_log_file}` for 30 seconds..."):
        backend.packet_sniffer.capture_packets(st.session_state.log_file, duration=30)
    
    # Check if capture was successful and file is not empty
    if os.path.exists(st.session_state.log_file) and not pd.read_csv(st.session_state.log_file).empty:
        st.success(f"✅ Live traffic captured and saved to: `{st.session_state.log_file}`")
        st.info("Click 'Analyze Traffic' to view findings.")
    else:
        st.error("❌ Live traffic capture failed or captured no relevant data. Please check:")
        st.markdown("""
            * Is `tshark` installed and `TSHARK_PATH` correct in `backend/packet_sniffer.py`?
            * Are you running Streamlit as **Administrator**?
            * Is the network interface name (`-i 'YourInterface'`) correct in `backend/packet_sniffer.py`?
            * Is there active network traffic on the selected interface?
        """)
        st.info("Check your terminal for detailed tshark error messages.")


st.markdown("---") # Visual separator

# Button to analyze captured traffic
if st.button("🔍 Analyze Captured Traffic & Get GenAI Insights", key="analyze_button"):
    if st.session_state.log_file and os.path.exists(st.session_state.log_file) and not pd.read_csv(st.session_state.log_file).empty:
        st.success("Analyzing traffic and generating AI-driven insights...")
        
        # Perform traffic analysis
        report = backend.analyzer.analyze_traffic(st.session_state.log_file)
        st.subheader("🚨 Anomaly Report:")
        st.code(report) # Display the analysis report

        st.markdown("---") # Visual separator

        # Get GenAI simulated insights
        genai_report = backend.genai_insights.get_genai_threat_insights(report)
        st.subheader("🤖 GenAI-Simulated Threat Intelligence:")
        st.markdown(genai_report) # Display GenAI insights (using markdown for formatting)
        
    else:
        st.warning("No valid traffic log found for analysis. Please capture traffic first.")

st.markdown("---") # Visual separator

# --- Section to display captured traffic ---
st.subheader("📊 Captured Network Traffic (Latest Batch)")
st.markdown("""
    This table displays a **parsed and structured view** of captured network traffic,
    obtained directly from `tshark`'s output. It includes fields relevant for
    security analysis, such as source/destination IPs, ports, and HTTP/HTTPS details.
""")
if st.session_state.log_file and os.path.exists(st.session_state.log_file):
    try:
        df_traffic = pd.read_csv(st.session_state.log_file)
        if not df_traffic.empty:
            st.dataframe(df_traffic) # Display the captured traffic in a DataFrame
        else:
            st.info("No traffic data in the latest log file. Capture might have failed or no relevant traffic was detected.")
    except pd.errors.EmptyDataError:
        st.info("The captured log file is empty. No data to display.")
    except Exception as e:
        st.error(f"Error loading traffic data: {e}. The CSV might be malformed or corrupted.")
else:
    st.info("Start live packet capture to see traffic data here.")