# pcap_analyzer.py

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
import sys
from collections import defaultdict
import datetime
import base64
import re
import json  # For saving results in JSON format


# --- Helper function to save results to JSON ---
def save_results_to_json(results_data, filename_prefix):
    """
    Saves structured results data to a JSON file.

    Args:
        results_data (dict or list): The data structure to save (e.g., list of scan dicts, or categorized creds).
        filename_prefix (str): Prefix for the filename (e.g., "network_scan_results", "credentials_results").

    Returns:
        bool: True if saved successfully, False otherwise.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{timestamp}.json"

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results_data, f, indent=4, ensure_ascii=False)
        print(f"\nResults successfully saved to '{filename}'")
        return True
    except Exception as e:
        print(f"\nError saving results to JSON: {e}")
        return False


# --- Helper function for scan type classification ---
def classify_scan_type(scan_data):
    """
    Classifies the type of network scan based on collected data (protocols, TCP flags, IPID increments).
    Returns a tuple: (primary_scan_type_string, list_of_detailed_reasons).
    """
    scan_types = []
    reasons = []

    total_tcp = scan_data['protocols'].get('TCP', 0)
    total_udp = scan_data['protocols'].get('UDP', 0)
    total_icmp = scan_data['protocols'].get('ICMP', 0)

    # --- 1. Basic Protocol-based Classification ---
    if total_tcp > 0 and total_udp == 0 and total_icmp == 0:
        scan_types.append("TCP Scan")
    elif total_udp > 0 and total_tcp == 0 and total_icmp == 0:
        scan_types.append("UDP Scan")
    elif total_icmp > 0 and total_tcp == 0 and total_udp == 0:
        scan_types.append("ICMP Scan")
    elif total_tcp > 0 and (total_udp > 0 or total_icmp > 0):
        scan_types.append("Mixed Protocol Scan")

    # --- 2. TCP Flag-based Classification ---
    if 'TCP' in scan_data['protocols'] and total_tcp > 0:
        syn_count = scan_data['tcp_flags'].get('SYN', 0)
        ack_count = scan_data['tcp_flags'].get('ACK', 0)
        fin_count = scan_data['tcp_flags'].get('FIN', 0)
        rst_count = scan_data['tcp_flags'].get('RST', 0)
        psh_count = scan_data['tcp_flags'].get('PSH', 0)
        urg_count = scan_data['tcp_flags'].get('URG', 0)

        total_tcp_flags_activity = syn_count + ack_count + fin_count + rst_count + psh_count + urg_count

        if total_tcp_flags_activity > 0:
            if syn_count > (total_tcp_flags_activity * 0.7) and \
                    ack_count < (total_tcp_flags_activity * 0.1) and \
                    fin_count < (total_tcp_flags_activity * 0.1) and \
                    rst_count < (total_tcp_flags_activity * 0.1):
                scan_types.append("SYN Scan (Stealth)")
                reasons.append(f"High SYN flag count ({syn_count}), very low other TCP flags.")

            elif syn_count > 0 and ack_count > 0 and \
                    (syn_count / total_tcp_flags_activity) > 0.4 and \
                    (ack_count / total_tcp_flags_activity) > 0.4:
                scan_types.append("Connect Scan (Full Handshake)")
                reasons.append(
                    f"Significant SYN ({syn_count}) and ACK ({ack_count}) flags, indicating full handshake attempts.")

            elif fin_count > (total_tcp_flags_activity * 0.7) and syn_count == 0 and ack_count == 0:
                scan_types.append("FIN Scan")
                reasons.append(f"High FIN flag count ({fin_count}), absence of SYN/ACK flags.")

            elif (fin_count > (total_tcp_flags_activity * 0.2) and \
                  psh_count > (total_tcp_flags_activity * 0.2) and \
                  urg_count > (total_tcp_flags_activity * 0.2)) and \
                    (syn_count == 0 and ack_count == 0):
                scan_types.append("XMAS Scan")
                reasons.append(
                    f"Dominant FIN, PSH, URG flags ({fin_count}/{psh_count}/{urg_count}), absence of SYN/ACK flags.")

            elif total_tcp_flags_activity < (total_tcp * 0.1) and total_tcp > 0 and \
                    not any(
                        st in scan_types for st in ["SYN Scan", "Connect Scan", "FIN Scan", "XMAS Scan", "ACK Scan"]):
                scan_types.append("NULL Scan (No Flags)")
                reasons.append(
                    f"Very low TCP flag activity relative to total TCP packets ({total_tcp_flags_activity} flags for {total_tcp} TCP packets).")

            elif ack_count > (total_tcp_flags_activity * 0.8) and syn_count == 0 and fin_count == 0:
                scan_types.append("ACK Scan")
                reasons.append(f"High ACK flag count ({ack_count}), absence of SYN/FIN flags.")

    # --- 3. Zombie Scan (Idle Scan / -sI Nmap) Heuristic ---
    rst_count = scan_data['tcp_flags'].get('RST', 0)
    syn_count_from_this_ip = scan_data['tcp_flags'].get('SYN', 0)

    # --- DEBUGGING ZOMBIE HEURISTIC (uncomment to activate) ---
    # print(f"\nDEBUG: Analyzing IP {scan_data['source_ip']} for Zombie Scan:")
    # print(f"  RST count: {rst_count}, Total TCP: {total_tcp}, RST ratio: {rst_count / total_tcp if total_tcp > 0 else 0:.2f}")
    # print(f"  SYN count from this IP: {syn_count_from_this_ip}, SYN ratio: {syn_count_from_this_ip / total_tcp if total_tcp > 0 else 0:.2f}")
    # print(f"  IPID Increments: {scan_data['ipid_increments']}")
    # print(f"  Len IPID Increments: {len(scan_data['ipid_increments'])}")
    # if scan_data['ipid_increments']:
    #     one_increments = scan_data['ipid_increments'].count(1)
    #     consistency_ratio = one_increments / len(scan_data['ipid_increments'])
    #     print(f"  One Increments: {one_increments}, Consistency Ratio: {consistency_ratio:.2f}")
    # print(f"  Unique Ports: {len(scan_data['ports'])}")
    # --- END DEBUGGING ---

    # Condition 1: Check if this IP is primarily sending RSTs and not many SYNs
    if total_tcp > 0 and \
            rst_count > (total_tcp * 0.6) and \
            syn_count_from_this_ip < (total_tcp * 0.15):

        # Condition 2: Check for consistent IP-ID increments
        if scan_data['ipid_increments'] and len(scan_data['ipid_increments']) >= 3:
            one_increments = scan_data['ipid_increments'].count(1)

            if len(scan_data['ipid_increments']) > 0:
                consistency_ratio = one_increments / len(scan_data['ipid_increments'])

                if consistency_ratio > 0.6:
                    # Condition 3: Does it interact with a reasonable number of unique ports?
                    if len(scan_data['ports']) >= 3:
                        scan_types.append("Suspected Zombie Host (Idlescan)")
                        reasons.append(
                            f"Characteristic behavior for a Zombie host in an Idlescan: "
                            f"High RST traffic ({rst_count} RSTs, >60% of TCP flags from this host), "
                            f"low SYN traffic ({syn_count_from_this_ip} SYNs from this host). "
                            f"Highly consistent IP-ID increments detected ({one_increments}/{len(scan_data['ipid_increments'])} increments are 1, consistency {consistency_ratio:.2f}), "
                            f"indicating its IP-ID is being probed sequentially. "
                            f"Interacted with {len(scan_data['ports'])} unique ports, which is typical for a scanned zombie."
                        )

    if not scan_types:
        final_scan_type_str = "Unspecified/Generic Scan"
    else:
        final_scan_type_str = ", ".join(sorted(list(set(scan_types))))

    return final_scan_type_str, reasons


# --- Main analysis function ---
def analyze_pcap_for_scans(pcap_file, min_unique_targets=1, min_unique_ports=500, time_window_seconds=30):
    """
    Analyzes a Pcap file for signs of network scans.
    """
    try:
        print(f"\nReading Pcap file: {pcap_file}...")
        packets = rdpcap(pcap_file)
        print(f"Loaded {len(packets)} packets.")
    except FileNotFoundError:
        print(f"Error: File '{pcap_file}' not found. Please check the path and filename.")
        return
    except Exception as e:
        print(f"Error loading Pcap file: {e}")
        return

    scan_candidates = defaultdict(lambda: {
        'targets': set(),
        'ports': set(),
        'first_seen': None,
        'last_seen': None,
        'is_scan': False,
        'protocols': defaultdict(int),
        'tcp_flags': defaultdict(int),
        'last_ipid': None,
        'ipid_increments': []
    })

    print("Analyzing packets for scan patterns...")

    for i, packet in enumerate(packets):
        if i % 1000 == 0 and i > 0:
            sys.stdout.write(f"\rProcessing packet {i}/{len(packets)}...")
            sys.stdout.flush()

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            timestamp = packet.time
            ip_id = packet[IP].id

            if scan_candidates[src_ip]['first_seen'] is None:
                scan_candidates[src_ip]['first_seen'] = timestamp

            scan_candidates[src_ip]['last_seen'] = timestamp
            scan_candidates[src_ip]['targets'].add(dst_ip)

            # Update IPID for this source, and check for increment
            if scan_candidates[src_ip]['last_ipid'] is not None:
                current_ipid = ip_id
                previous_ipid = scan_candidates[src_ip]['last_ipid']

                # Check for wrap-around (ID goes from max to 0) or simple increment
                if current_ipid > previous_ipid:
                    increment = current_ipid - previous_ipid
                    scan_candidates[src_ip]['ipid_increments'].append(increment)
                elif current_ipid < previous_ipid:  # Handle wrap-around
                    increment = (65535 - previous_ipid) + current_ipid + 1
                    scan_candidates[src_ip]['ipid_increments'].append(increment)

            scan_candidates[src_ip]['last_ipid'] = ip_id

            if packet.haslayer(TCP):
                scan_candidates[src_ip]['ports'].add(packet[TCP].dport)
                scan_candidates[src_ip]['protocols']['TCP'] += 1

                flags = packet[TCP].flags
                flags_int = int(flags) if hasattr(flags, 'value') else int(flags)

                if flags_int & 0x02: scan_candidates[src_ip]['tcp_flags']['SYN'] += 1
                if flags_int & 0x10: scan_candidates[src_ip]['tcp_flags']['ACK'] += 1
                if flags_int & 0x01: scan_candidates[src_ip]['tcp_flags']['FIN'] += 1
                if flags_int & 0x04: scan_candidates[src_ip]['tcp_flags']['RST'] += 1
                if flags_int & 0x08: scan_candidates[src_ip]['tcp_flags']['PSH'] += 1
                if flags_int & 0x20: scan_candidates[src_ip]['tcp_flags']['URG'] += 1

            elif packet.haslayer(UDP):
                scan_candidates[src_ip]['ports'].add(packet[UDP].dport)
                scan_candidates[src_ip]['protocols']['UDP'] += 1
            elif packet.haslayer(ICMP):
                scan_candidates[src_ip]['protocols']['ICMP'] += 1

    sys.stdout.write(f"\rProcessing {len(packets)} packets completed.\n")

    found_scans = []
    print("\nEvaluating scan candidates:")
    for src_ip, data in scan_candidates.items():
        num_unique_targets = len(data['targets'])
        num_unique_ports = len(data['ports'])
        duration = data['last_seen'] - data['first_seen'] if data['first_seen'] is not None else 0

        is_port_scan = num_unique_ports >= min_unique_ports and num_unique_targets >= 1
        is_host_scan = num_unique_targets >= min_unique_targets and num_unique_ports >= 1

        if (is_port_scan or is_host_scan) and duration <= time_window_seconds:
            data['is_scan'] = True

            scan_type_str, scan_details_reasons = classify_scan_type(data)

            found_scans.append({
                'source_ip': src_ip,
                'start_time': datetime.datetime.fromtimestamp(float(data['first_seen'])).strftime(
                    '%Y-%m-%d %H:%M:%S UTC') if data['first_seen'] else 'N/A',
                'end_time': datetime.datetime.fromtimestamp(float(data['last_seen'])).strftime(
                    '%Y-%m-%d %H:%M:%S UTC') if data['last_seen'] else 'N/A',
                'duration_seconds': round(duration, 2),
                'unique_targets': num_unique_targets,
                'unique_ports': num_unique_ports,
                'protocols_used': dict(data['protocols']),
                'tcp_flags_used': dict(data['tcp_flags']),
                'scan_type': scan_type_str,
                'scan_details_reasons': scan_details_reasons
            })

    # --- Step 1: Check for and highlight Zombie Scans first ---
    zombie_hosts_found = []
    for scan in found_scans:
        if "Suspected Zombie Host (Idlescan)" in scan['scan_type']:
            zombie_hosts_found.append(scan)

    if zombie_hosts_found:
        print("\n" + "=" * 70)
        print("!!! URGENT ALERT: SUSPECTED ZOMBIE HOST(S) (IDLESCAN) DETECTED !!!".center(70))
        print("=" * 70)
        for zombie_scan in zombie_hosts_found:
            print(f"Source IP: {zombie_scan['source_ip']}")
            print(f"  Scan Type: {zombie_scan['scan_type']}")
            if zombie_scan['scan_details_reasons']:
                for reason in zombie_scan['scan_details_reasons']:
                    print(f"  Reason: {reason}")
            print("-" * 60)
        print("Please investigate these hosts immediately.".center(70))
        print("=" * 70 + "\n")

    # --- Step 2: Print all Detected Network Scans (Detailed Report) ---
    if found_scans:
        print("\n--- Detected Network Scans (Detailed Report) ---")
        for scan in found_scans:
            print(f"\n--- Scan Report for Source IP: {scan['source_ip']} ---")

            print(f"  Scan Type: {scan['scan_type']}")
            if scan['scan_details_reasons']:
                for reason in scan['scan_details_reasons']:
                    detail_prefix = "Reason" if "Suspected Zombie Host (Idlescan)" in scan['scan_type'] else "Details"
                    print(f"  {detail_prefix}: {reason}")

            print(f"\n  Timeframe:")
            print(f"    Start Time: {scan['start_time']}")
            print(f"    End Time: {scan['end_time']}")
            print(f"    Duration: {scan['duration_seconds']} seconds")

            print(f"\n  Scope of Activity:")
            print(f"    Unique Targets: {scan['unique_targets']}")
            print(f"    Unique Ports: {scan['unique_ports']}")

            if scan['protocols_used']:
                protocol_summary = ", ".join([f"{proto} ({count})" for proto, count in scan['protocols_used'].items()])
                print(f"    Protocols Used: {protocol_summary}")

            if scan['tcp_flags_used']:
                flags_summary = ", ".join([f"{flag} ({count})" for flag, count in scan['tcp_flags_used'].items()])
                print(f"    TCP Flags Used: {flags_summary}")

            print("-" * 40)
    else:
        print("\nNo suspicious network scans found based on the current thresholds.")

    print("\n--- Summary of All Scan Candidates ---")
    for src_ip, data in scan_candidates.items():
        print(
            f"IP: {src_ip}, Unique Targets: {len(data['targets'])}, Unique Ports: {len(data['ports'])}, Duration: {round(data['last_seen'] - data['first_seen'], 2) if data['first_seen'] else 'N/A'}s")

    # --- NEW: JSON Saving Option for Scan Analysis ---
    if found_scans:  # Only ask to save if there are results
        save_choice = input("Do you want to save these scan results to a JSON file? (yes/no): ").strip().lower()
        if save_choice == 'yes':
            save_results_to_json(found_scans, "network_scan_results")


# ==============================================================================
# --- NEW FEATURE: CREDENTIAL EXTRACTION ---
# ==============================================================================

def extract_credentials(pcap_file):
    """
    Analyzes a Pcap file for plaintext credentials (FTP, HTTP Basic Auth, Telnet, POP3, IMAP, SMTP, SNMP)
    and TFTP file operations.
    """
    print(f"\nAttempting to extract plaintext credentials and file operations from: {pcap_file}...")

    try:
        packets = rdpcap(pcap_file)
        print(f"Loaded {len(packets)} packets for credential analysis.")
    except FileNotFoundError:
        print(f"Error: File '{pcap_file}' not found. Please check the path and filename.")
        return
    except Exception as e:
        print(f"Error loading Pcap file: {e}")
        return

    found_credentials = []

    for i, packet in enumerate(packets):
        if i % 1000 == 0 and i > 0:
            sys.stdout.write(f"\rProcessing packet {i}/{len(packets)} for credentials...")
            sys.stdout.flush()

        # Basic IP information
        src_ip = packet[IP].src if packet.haslayer(IP) else "N/A"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "N/A"
        timestamp_str = datetime.datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S UTC')

        # Define ports for TCP or UDP packets early
        src_port = "N/A"
        dst_port = "N/A"
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):  # If it's a UDP packet, get its ports
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Check if a Raw layer with payload is present
        if packet.haslayer(Raw):
            payload_bytes = packet[Raw].load
            # Attempt decoding with utf-8, fall back to latin-1 if utf-8 fails
            try:
                payload_str = payload_bytes.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                payload_str = payload_bytes.decode('latin-1', errors='ignore')

                # --- FTP Credential Extraction (Port 21) ---
            if (dst_port == 21 or src_port == 21) and packet.haslayer(TCP):
                user_match = re.search(r'(USER|user)\s+(.+)', payload_str)
                pass_match = re.search(r'(PASS|pass)\s+(.+)', payload_str)

                if user_match or pass_match:
                    cred_info = {
                        'protocol': 'FTP',
                        'source': f"{src_ip}:{src_port}",
                        'destination': f"{dst_ip}:{dst_port}",
                        'timestamp': timestamp_str
                    }
                    if user_match:
                        cred_info['username'] = user_match.group(2).strip()
                    if pass_match:
                        cred_info['password'] = pass_match.group(2).strip()
                    found_credentials.append(cred_info)

            # --- HTTP Basic Authentication Extraction (Port 80) ---
            elif (dst_port == 80 or src_port == 80) and packet.haslayer(TCP):
                auth_match = re.search(r'Authorization: Basic\s+([a-zA-Z0-9+/=]+)', payload_str)
                if auth_match:
                    encoded_creds = auth_match.group(1)
                    try:
                        decoded_creds = base64.b64decode(encoded_creds).decode('utf-8', errors='ignore')
                        if ':' in decoded_creds:
                            username, password = decoded_creds.split(':', 1)
                            found_credentials.append({
                                'protocol': 'HTTP Basic Auth',
                                'source': f"{src_ip}:{src_port}",
                                'destination': f"{dst_ip}:{dst_port}",
                                'username': username.strip(),
                                'password': password.strip(),
                                'timestamp': timestamp_str
                            })
                    except Exception:
                        pass  # Silently ignore malformed Base64

            # --- HTTP POST Parameters (Port 80) ---
            elif (dst_port == 80 or src_port == 80) and packet.haslayer(
                    TCP) and b'POST /' in payload_bytes and b'Content-Type: application/x-www-form-urlencoded' in payload_bytes:
                form_data_match = re.search(r'\r\n\r\n(.+)', payload_str, re.DOTALL)
                if form_data_match:
                    form_data = form_data_match.group(1)
                    user_param = re.search(r'(user(?:name)?|login|id)=([^&]+)', form_data, re.IGNORECASE)
                    pass_param = re.search(r'(pass(?:word)?|pwd)=([^&]+)', form_data, re.IGNORECASE)

                    if user_param or pass_param:
                        cred_info = {
                            'protocol': 'HTTP POST',
                            'source': f"{src_ip}:{src_port}",
                            'destination': f"{dst_ip}:{dst_port}",
                            'timestamp': timestamp_str,
                            'details': 'Potential login form submission'
                        }
                        if user_param:
                            username_encoded = user_param.group(2)
                            username = re.sub(r'%([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)),
                                              username_encoded)
                            cred_info['username'] = username.strip()
                        if pass_param:
                            password_encoded = pass_param.group(2)
                            password = re.sub(r'%([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)),
                                              password_encoded)
                            cred_info['password'] = password.strip()
                        found_credentials.append(cred_info)


            # --- Telnet Credential Heuristic (Port 23) ---
            elif (dst_port == 23 or src_port == 23) and packet.haslayer(TCP):
                login_prompt_match = re.search(r'(login|username|user name):?\s*([a-zA-Z0-9._-]+)?', payload_str,
                                               re.IGNORECASE)
                password_prompt_match = re.search(r'(password):?\s*([a-zA-Z0-9._-]+)?', payload_str, re.IGNORECASE)

                if login_prompt_match and login_prompt_match.group(2):
                    found_credentials.append({
                        'protocol': 'Telnet (Potential Username)',
                        'source': f"{src_ip}:{src_port}",
                        'destination': f"{dst_ip}:{dst_port}",
                        'username': login_prompt_match.group(2).strip(),
                        'timestamp': timestamp_str,
                        'details': 'Heuristic match, input after login prompt.'
                    })
                if password_prompt_match and password_prompt_match.group(2):
                    found_credentials.append({
                        'protocol': 'Telnet (Potential Password)',
                        'source': f"{src_ip}:{src_port}",
                        'destination': f"{dst_ip}:{dst_port}",
                        'password': password_prompt_match.group(2).strip(),
                        'timestamp': timestamp_str,
                        'details': 'Heuristic match, input after password prompt.'
                    })

            # --- POP3 (Port 110) ---
            elif (dst_port == 110 or src_port == 110) and packet.haslayer(TCP):
                user_match = re.search(r'(USER|user)\s+(.+)', payload_str)
                pass_match = re.search(r'(PASS|pass)\s+(.+)', payload_str)

                if user_match or pass_match:
                    cred_info = {
                        'protocol': 'POP3',
                        'source': f"{src_ip}:{src_port}",
                        'destination': f"{dst_ip}:{dst_port}",
                        'timestamp': timestamp_str
                    }
                    if user_match:
                        cred_info['username'] = user_match.group(2).strip()
                    if pass_match:
                        cred_info['password'] = pass_match.group(2).strip()
                    found_credentials.append(cred_info)

            # --- IMAP (Port 143) ---
            elif (dst_port == 143 or src_port == 143) and packet.haslayer(TCP):
                # Plaintext LOGIN
                login_match = re.search(r'LOGIN\s+"?([^"\s]+)"?\s+"?([^"\s]+)"?', payload_str, re.IGNORECASE)
                if login_match:
                    found_credentials.append({
                        'protocol': 'IMAP (Plaintext)',
                        'source': f"{src_ip}:{src_port}",
                        'destination': f"{dst_ip}:{dst_port}",
                        'username': login_match.group(1).strip('"'),
                        'password': login_match.group(2).strip('"'),
                        'timestamp': timestamp_str
                    })
                # AUTHENTICATE PLAIN (Base64)
                auth_plain_match = re.search(r'AUTHENTICATE PLAIN\s+([a-zA-Z0-9+/=]+)', payload_str, re.IGNORECASE)
                if auth_plain_match:
                    encoded_creds = auth_plain_match.group(1)
                    try:
                        decoded_creds = base64.b64decode(encoded_creds).decode('utf-8', errors='ignore')
                        parts = decoded_creds.split('\x00')
                        if len(parts) >= 3:
                            username = parts[-2].strip()
                            password = parts[-1].strip()
                            found_credentials.append({
                                'protocol': 'IMAP (AUTH PLAIN)',
                                'source': f"{src_ip}:{src_port}",
                                'destination': f"{dst_ip}:{dst_port}",
                                'username': username,
                                'password': password,
                                'timestamp': timestamp_str,
                                'details': f'Authzid: {parts[1]}' if len(parts) == 4 else ''
                            })
                    except Exception:
                        pass

            # --- SMTP (Port 25, 587) ---
            elif (dst_port in [25, 587] or src_port in [25, 587]) and packet.haslayer(TCP):
                # Client sends to server
                is_client_to_server_flow = (dst_port in [25, 587])

                # Check for AUTH LOGIN or AUTH PLAIN commands from client
                auth_command_match = re.search(r'AUTH\s+(LOGIN|PLAIN)\r\n', payload_str, re.IGNORECASE)
                if is_client_to_server_flow and auth_command_match:
                    pass  # Command itself, credential comes in next packet

                # Heuristic: Look for Base64 encoded strings in packets sent by the client.
                # These are often responses to a server's 334 challenge (for AUTH LOGIN) or the PLAIN credential.
                base64_cred_match = re.fullmatch(r'([a-zA-Z0-9+/=]+)\r\n', payload_str)

                if is_client_to_server_flow and base64_cred_match:
                    encoded_val = base64_cred_match.group(1)
                    try:
                        decoded_val = base64.b64decode(encoded_val).decode('utf-8', errors='ignore')

                        # Differentiate between AUTH PLAIN format and single Base64 values (username/password for AUTH LOGIN)
                        if '\x00' in decoded_val:  # AUTH PLAIN format: <null>authzid<null>username<null>password
                            parts = decoded_val.split('\x00')
                            if len(parts) >= 3:
                                username = parts[-2].strip()
                                password = parts[-1].strip()
                                found_credentials.append({
                                    'protocol': 'SMTP (AUTH PLAIN)',
                                    'source': f"{src_ip}:{src_port}",
                                    'destination': f"{dst_ip}:{dst_port}",
                                    'username': username,
                                    'password': password,
                                    'timestamp': timestamp_str,
                                    'details': f'Base64-encoded (Authzid: {parts[1]})' if len(
                                        parts) == 4 else 'Base64-encoded'
                                })
                        else:  # Likely single Base64 encoded username or password from AUTH LOGIN
                            found_credentials.append({
                                'protocol': 'SMTP (AUTH LOGIN Credential)',
                                'source': f"{src_ip}:{src_port}",
                                'destination': f"{dst_ip}:{dst_port}",
                                'username_or_password': decoded_val.strip(),  # Cannot distinguish user/pass here.
                                'timestamp': timestamp_str,
                                'details': f'Base64-encoded. Value: {decoded_val}'
                            })

                    except Exception:
                        pass  # Malformed Base64 or non-credential Base64

        # --- NEW PROTOCOL: SNMP Community String Extraction (Port 161 UDP) ---
        # SNMP runs over UDP, standard port 161. Community string is in the SNMP layer.
        elif (dst_port == 161 or src_port == 161) and packet.haslayer(UDP) and packet.haslayer(SNMP):
            try:
                community_string_bytes = packet[SNMP].community
                community_string = community_string_bytes.decode('ascii', errors='ignore')

                # Filter out common community strings to reduce noise
                common_communities = ["public", "private", "manager", "monitor"]

                if community_string.lower() not in common_communities:
                    found_credentials.append({
                        'protocol': 'SNMP Community String',
                        'source': f"{src_ip}:{src_port}",
                        'destination': f"{dst_ip}:{dst_port}",
                        'password': community_string.strip(),  # Stored as 'password' as it functions as a passcode
                        'timestamp': timestamp_str,
                        'details': 'SNMP Community String in plaintext.'
                    })
                # else: Common community string ignored for cleaner report.

            except Exception:  # Catch parsing errors for malformed SNMP packets
                pass

        # --- TFTP Read/Write Request Extraction (Port 69 UDP) ---
        elif packet.haslayer(UDP) and packet.haslayer(Raw) and (dst_port == 69 or src_port == 69):
            payload_bytes = packet[Raw].load
            # --- DEBUGGING TFTP HEURISTIC (uncomment to activate) ---
            # raw_load = packet[Raw].load
            # print(f"\nDEBUG TFTP: Found UDP packet on port 69 from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
            # print(f"  Raw Payload (bytes): {raw_load.hex()}")
            # if len(raw_load) >= 2:
            #     tftp_opcode_bytes_debug = raw_load[0:2]
            #     tftp_opcode_debug = int.from_bytes(tftp_opcode_bytes_debug, byteorder='big')
            #     print(f"  Detected Opcode (raw): {tftp_opcode_bytes_debug.hex()} -> Decimal: {tftp_opcode_debug}")
            #     if tftp_opcode_debug not in [1, 2, 3, 4, 5]:
            #         print("  WARNING: TFTP Opcode is not RRQ(1), WRQ(2), DATA(3), ACK(4), ERROR(5)!")
            # first_null_debug = raw_load.find(b'\x00', 2)
            # print(f"  First null byte index (after opcode): {first_null_debug}")
            # if first_null_debug != -1:
            #     print(f"  Potential Filename Bytes: {raw_load[2:first_null_debug].hex()}")
            # --- END DEBUGGING ---

            if len(payload_bytes) >= 4:

                tftp_opcode_bytes = payload_bytes[0:2]
                tftp_opcode = int.from_bytes(tftp_opcode_bytes, byteorder='big')

                filename = "N/A"
                mode = "N/A"

                try:
                    first_null_byte_index = payload_bytes.find(b'\x00', 2)
                    if first_null_byte_index != -1:
                        filename = payload_bytes[2:first_null_byte_index].decode('ascii', errors='ignore')

                        second_null_byte_index = payload_bytes.find(b'\x00', first_null_byte_index + 1)
                        if second_null_byte_index != -1:
                            mode = payload_bytes[first_null_byte_index + 1:second_null_byte_index].decode('ascii',
                                                                                                          errors='ignore')

                except Exception:
                    filename = "Parsing Error"
                    mode = "Parsing Error"

                tftp_type = "UNKNOWN"
                if tftp_opcode == 1:
                    tftp_type = "RRQ (Read Request)"
                elif tftp_opcode == 2:
                    tftp_type = "WRQ (Write Request)"

                if tftp_type != "UNKNOWN":
                    found_credentials.append({
                        'protocol': f"TFTP {tftp_type}",
                        'source': f"{src_ip}:{src_port}",
                        'destination': f"{dst_ip}:{dst_port}",
                        'filename': filename.strip(),
                        'mode': mode.strip(),
                        'timestamp': timestamp_str,
                        'details': 'File operation in plaintext.'
                    })

    sys.stdout.write(f"\rProcessing {len(packets)} packets for credentials completed.\n")

    # --- Categorize found credentials for clearer reporting ---
    primary_creds = []  # Entries with both username and password
    partial_creds = []  # Entries with username OR password, but not both (e.g., Telnet heuristic, SMTP AUTH LOGIN user-only)
    file_ops = []  # TFTP operations

    for cred_entry in found_credentials:
        if 'username' in cred_entry and 'password' in cred_entry:
            primary_creds.append(cred_entry)
        elif 'username' in cred_entry or 'password' in cred_entry or 'benutzername_oder_passwort' in cred_entry:  # Includes the new field for SMTP AUTH LOGIN
            partial_creds.append(cred_entry)
        elif 'filename' in cred_entry and 'mode' in cred_entry:  # TFTP entries have 'filename' and 'mode'
            file_ops.append(cred_entry)

    # --- Plaintext Credential & File Operation Report ---
    print("\n--- Plaintext Credential & File Operation Report ---")

    # --- 1. Urgent Alert for Full Plaintext Credentials ---
    if primary_creds:
        print("\n" + "#" * 70)
        print("!!! URGENT ALERT: FULL PLAINTEXT CREDENTIALS DETECTED !!!".center(70))
        print("#" * 70)
        for cred in primary_creds:
            print(f"\n--- Protocol: {cred.get('protocol', 'N/A')} ---")
            print(f"  Source: {cred.get('source', 'N/A')}")
            print(f"  Destination: {cred.get('destination', 'N/A')}")
            print(f"  Timestamp: {cred.get('timestamp', 'N/A')}")
            print(f"  Username: {cred['username']}")
            print(f"  Password: {cred['password']}")
            if 'details' in cred:
                print(f"  Details: {cred['details']}")
            print("-" * 40)
        print("#" * 70 + "\n")
        print("These credentials should be considered HIGHLY COMPROMISED. Investigate immediately.".center(70))
        print("#" * 70 + "\n")

    # --- 2. Other Detected Sensitive Information (secondary priority) ---
    if partial_creds or file_ops:
        if not primary_creds:
            print(
                "\n!!! WARNING: The following additional plaintext credentials or sensitive file operations were found !!!")
            print(
                "!!! These findings should also be investigated.                                                 !!!\n")

        other_findings_combined = partial_creds + file_ops

        if other_findings_combined:
            print("\n--- Other Detected Sensitive Information ---")
            for cred in other_findings_combined:
                print(f"--- Found Entry ({cred.get('protocol', 'N/A')}) ---")
                print(f"  Source: {cred.get('source', 'N/A')}")
                print(f"  Destination: {cred.get('destination', 'N/A')}")
                print(f"  Timestamp: {cred.get('timestamp', 'N/A')}")
                if 'username' in cred:
                    print(f"  Username: {cred['username']}")
                if 'password' in cred:
                    print(f"  Password: {cred['password']}")
                if 'benutzername_oder_passwort' in cred:
                    print(f"  Username/Password (unspec.): {cred['benutzername_oder_passwort']}")
                if 'filename' in cred:
                    print(f"  Filename: {cred['filename']}")
                if 'mode' in cred:
                    print(f"  Mode: {cred['mode']}")
                if 'details' in cred:
                    print(f"  Details: {cred['details']}")
                print("-" * 40)

    # --- 3. If NOTHING was found ---
    if not primary_creds and not partial_creds and not file_ops:
        print("No plaintext credentials or sensitive file operations found based on common patterns.")

    print("--------------------------------------------------\n")

    # --- NEW: JSON Saving Option for Credential Extraction ---
    if primary_creds or partial_creds or file_ops:  # Only ask to save if there are any findings
        save_choice = input(
            "Do you want to save these credential/file operation results to a JSON file? (yes/no): ").strip().lower()
        if save_choice == 'yes':
            # Structure the data for JSON export
            creds_export_data = {
                "primary_credentials_found": primary_creds,
                "partial_credentials_found": partial_creds,
                "file_operations_found": file_ops
            }
            save_results_to_json(creds_export_data, "credentials_results")


# ==============================================================================
# --- MODIFIED: MENU INTEGRATION ---
# ==============================================================================
if __name__ == "__main__":
    # Default thresholds for scan detection
    min_targets = 1
    min_ports = 500
    time_window = 30

    print("---------------------------------------------")
    print("      Welcome to the PcapAnalyzer Script     ")
    print("---------------------------------------------")
    print("\nThis script analyzes Pcap files for network scans and extracts credentials.")

    while True:  # Loop for the main menu
        print("\n--- Please select an option ---")
        print("1. Network Scan Analysis")
        print("2. Credential & File Operations")
        print("3. Exit")

        choice_input = input("Your choice (1, 2 or 3): ").strip().lower()

        if choice_input == '1' or choice_input in ['scan', 'analyse', 'analyze', 'network scan']:
            print(f"\n--- Network Scan Analysis ---")
            print(f"Current default thresholds for scan detection:")
            print(f"  - Minimum Unique Targets: {min_targets}")
            print(f"  - Minimum Unique Ports: {min_ports}")
            print(f"  - Time Window for Scan Duration: {time_window} seconds")
            print("You can adjust these values if needed.")
            print("---------------------------------------------\n")

            pcap_file_path = input(
                "Please enter the full path to the Pcap file for scan analysis (e.g., nmap_standard_scan.pcap): ").strip()

            change_thresholds = input(
                "Do you want to adjust the default thresholds? (yes/no, Default: no): ").strip().lower()

            if change_thresholds == 'yes':
                while True:
                    try:
                        new_min_targets_str = input(
                            f"New Minimum Unique Targets (current {min_targets}, Enter for default): ")
                        if new_min_targets_str:
                            min_targets = int(new_min_targets_str)

                        new_min_ports_str = input(
                            f"New Minimum Unique Ports (current {min_ports}, Enter for default): ")
                        if new_min_ports_str:
                            min_ports = int(new_min_ports_str)

                        new_time_window_str = input(
                            f"New Time Window in seconds (current {time_window}, Enter for default): ")
                        if new_time_window_str:
                            time_window = int(new_time_window_str)
                        break
                    except ValueError:
                        print("Invalid input. Please enter valid numbers or press Enter for the default value.")

            print(f"\nStarting analysis with the following thresholds:")
            print(f"  - Minimum Unique Targets: {min_targets}")
            print(f"  - Minimum Unique Ports: {min_ports}")
            print(f"  - Time Window for Scan Duration: {time_window} seconds")
            print("---------------------------------------------\n")

            analyze_pcap_for_scans(pcap_file_path, min_targets, min_ports, time_window)

        elif choice_input == '2' or choice_input in ['cred', 'credentials', 'extract', 'plaintext',
                                                     'extract credentials', 'file ops', 'tftp', 'snmp']:
            print(f"\n--- Plaintext Credential & File Operation Extraction ---")
            pcap_file_path = input("Please enter the full path to the Pcap file for extraction: ").strip()
            extract_credentials(pcap_file_path)

        elif choice_input == '3' or choice_input in ['exit', 'quit', 'end', 'bye']:
            print("\nExiting PcapAnalyzer. Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice. Please enter '1', '2', '3', or a recognized keyword (e.g., 'scan', 'cred', 'exit').")