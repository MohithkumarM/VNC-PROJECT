"""
VNC Security Monitor - Protection Recommendations
Provides static protection comments based on attack type.
"""

PROTECTION_ADVICE = {
    'Normal': "Traffic is normal. No action required. Continue monitoring.",
    'PortScan': "Port Scan detected! \nRecommendation: \n1. Block the source IP immediately.\n2. Enable firewall rules to limit port access.\n3. Implement IDS/IPS to detect scanning patterns.",
    'DoS': "DoS Attack detected! \nRecommendation: \n1. Implement rate limiting on VNC ports.\n2. Filter traffic from suspicious IPs.\n3. Use a load balancer to distribute traffic (though VNC is stateful).",
    'Malware': "Malware activity detected! \nRecommendation: \n1. Isolate the affected machine immediately.\n2. Run a full system antivirus scan.\n3. Check for unauthorized processes or services.",
    'DDoS': "DDoS Attack detected! \nRecommendation: \n1. Activate DDoS protection services (e.g., Cloudflare, AWS Shield).\n2. Rate limit incoming connections.\n3. Block traffic from known botnet IPs.",
    'File Exfiltration': "Data Exfiltration detected! \nRecommendation: \n1. Terminate the VNC session immediately.\n2. Block the destination IP.\n3. Audit file access logs to determine what was stolen.",
    'Clipboard Hijacking': "Clipboard Hijacking detected! \nRecommendation: \n1. Disable clipboard sharing in VNC server configuration.\n2. Monitor clipboard access by non-standard processes.",
    'Keylogging': "Keylogging detected! \nRecommendation: \n1. Reset all passwords immediately.\n2. Scan for and remove keylogger software.\n3. Use virtual keyboards for sensitive input if possible.",
    'Unencrypted': "Unencrypted VNC traffic detected! \nRecommendation: \n1. Enforce SSH tunneling for VNC connections.\n2. Use VNC over VPN.\n3. Configure VNC server to require encryption."
}

def get_recommendation(attack_type):
    return PROTECTION_ADVICE.get(attack_type, "Unknown attack type. Investigate immediately.")
