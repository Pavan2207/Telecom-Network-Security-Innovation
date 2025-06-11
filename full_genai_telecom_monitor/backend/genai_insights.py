# backend/genai_insights.py
import random
from datetime import datetime

def get_genai_threat_insights(analysis_report):
    """
    Simulates GenAI insights for telecom threats, predicting breach points,
    and monitoring dark web chatter based on the analysis report.
    In a real system, this would involve sending the report/data to an LLM
    (e.g., Google Gemini, OpenAI GPT) for complex analysis.
    """
    insights = []
    
    insights.append("### 🧠 GenAI-Simulated Telecom Threat Insights & Predictions ###")
    insights.append(f"*(Analysis generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')})*")
    insights.append("\n**Based on observed network traffic and threat intelligence simulation:**")

    # --- Threat Prediction & Breach Point Analysis ---
    if "Insecure HTTP POST" in analysis_report or "Clear-text Credential Pattern" in analysis_report:
        insights.append("- **High-Risk Threat:** Detected clear-text credentials (e.g., HTTP login, Telnet) or insecure communication. This is a critical breach point. **Prediction:** High probability of credential harvesting and unauthorized access to internal telecom systems (e.g., OAM portals, network devices). **Action:** Immediately audit exposed services, enforce HTTPS/SSH, implement MFA.")
    elif "Insecure HTTP Connection" in analysis_report:
        insights.append("- **Medium-Risk Threat:** Unencrypted HTTP traffic on potentially sensitive internal telecom web interfaces. **Prediction:** Data interception risk. Adversaries could gain valuable intelligence or manipulate traffic. **Action:** Migrate all internal web services to HTTPS.")
    
    if "Onion Site Access" in analysis_report or "Flagged Domain/URL Access" in analysis_report:
        insights.append("- **Severe Threat:** User/system access to known malicious or dark web domains (e.g., `.onion`, C2 servers, exploit sites). **Prediction:** Indicates potential malware infection (botnet C2), data exfiltration, or reconnaissance by advanced persistent threats (APTs) targeting telecom infrastructure. **Breach Point:** Compromised endpoint or insider threat. **Action:** Isolate source, conduct forensic analysis, update threat intelligence feeds.")
    
    if "Telecom Exploit Signature Detected" in analysis_report:
        insights.append("- **Critical Threat:** Network traffic contains patterns or keywords indicative of active telecom-specific exploits (e.g., SS7, Diameter, 5G vulnerabilities). **Prediction:** Active attack or reconnaissance against core network elements. **Breach Point:** Signalling network (SS7, Diameter), RAN components, or core network control plane. **Action:** Activate incident response, engage security operations center (SOC), patch vulnerable systems immediately.")

    if "Malformed Email" in analysis_report or "Malformed URL" in analysis_report:
        insights.append("- **Potential Phishing/Malware Delivery:** Malformed communications often precede social engineering or malware delivery attempts. **Prediction:** Users might be targeted for phishing to gain access to telecom employee credentials or systems. **Action:** Enhance email filtering, conduct phishing awareness training, monitor for anomalous login attempts.")
    
    # --- Simulated Dark Web Chatter Monitoring ---
    dark_web_insights = [
        "Dark web forums show increasing chatter around '5G slicing vulnerabilities' and 'RAN exploits'. Threat actors are exchanging reconnaissance tools.",
        "Monitored channels indicate new zero-day exploits being traded for 'Cisco IOS' and 'Juniper Junos' devices common in telecom networks.",
        "Discussions about 'SS7 bypass techniques' for intercepting calls and SMS are resurfacing on private dark web communities.",
        "Threat intelligence suggests specific ransomware groups are targeting telecom operators, aiming for service disruption and data exfiltration.",
        "New phishing kits specifically designed to mimic telecom operator login pages are being advertised.",
        "A new tool for 'Telnet backdoor' creation on older network equipment is gaining traction.",
    ]
    insights.append(f"\n**Dark Web Chatter Monitoring (Simulated):** {random.choice(dark_web_insights)}")

    # --- General Predictive Recommendations ---
    insights.append("\n**GenAI Predictive Recommendations for Telecom Security:**")
    insights.append("- **Proactive Patching:** Prioritize patching of all network devices and management systems, especially those exposed to the internet (e.g., BSS/OSS portals, remote access VPNs).")
    insights.append("- **Behavioral Analytics:** Implement AI-driven behavioral analytics on network and user activity to detect deviations from baseline (e.g., unusual SSH logins, data transfer patterns).")
    insights.append("- **Threat Hunting:** Regularly perform proactive threat hunting for signs of compromise, focusing on common telecom attack vectors (SS7, Diameter, IoT endpoints).")
    insights.append("- **Supply Chain Security:** Vet third-party vendors and their security practices rigorously, as they often represent significant breach points.")
    insights.append("- **Zero Trust Architecture:** Advance towards a Zero Trust security model, segmenting networks and enforcing least privilege access.")

    # Fallback if no specific threats detected
    if len(insights) == 3: # Only the initial headers
        insights.append("- **Current Assessment:** No immediate high-confidence threats detected in this capture. Continuous, deeper analysis is recommended.")
        insights.append("- **Recommendation:** Continue real-time monitoring and integrate more specific telecom-focused threat intelligence feeds.")


    insights.append("\n*(Disclaimer: These are simulated GenAI insights for demonstration purposes. A real-world GenAI system would integrate with advanced threat intelligence platforms and machine learning models.)*")
    
    return "\n".join(insights)