Absolut\! Ein gut strukturiertes `README.md` ist entscheidend für jedes GitHub-Projekt. Es ist die erste Anlaufstelle für jeden, der dein Projekt sieht.

Hier ist ein Entwurf für deine `README.md`-Datei, komplett auf Englisch und mit einem Autor-Feld am Ende.

Du kannst diesen Text einfach in eine Datei namens `README.md` in deinem Projektordner kopieren und dann zu deinem Repository hinzufügen und pushen.

-----

### **`README.md` Inhalt**

````markdown
# PcapAnalyzer

A powerful and user-friendly Python script for network security analysis, focusing on identifying various network scan types and extracting plaintext credentials or sensitive file operations from Packet Capture (PCAP) files. Designed for cybersecurity labs, blue team exercises, and network forensics.

## Features

* **Network Scan Analysis:**
    * Identifies and classifies common network scan types (e.g., TCP Connect, SYN, FIN, XMAS, NULL, ACK Scans).
    * Detects and highlights **Suspected Zombie Hosts (Idle Scans)** with detailed reasoning.
    * Provides comprehensive reports including source IP, scan type, timestamps, duration, unique targets, unique ports, used protocols, and TCP flags.
    * Supports adjustable thresholds for scan detection.

* **Plaintext Credential & File Operation Extraction:**
    * Extracts usernames and passwords transmitted in plaintext or easily decodable formats.
    * Detects sensitive file operations.
    * **Prioritized Reporting:** Urgent alerts for full plaintext username/password pairs, followed by other sensitive findings.
    * **Supported Protocols / Types:**
        * **FTP:** `USER` and `PASS` commands.
        * **HTTP Basic Authentication:** Base64-decoded credentials from `Authorization` headers.
        * **HTTP POST Forms:** Common username/password parameters from URL-encoded form data (e.g., `user=...&pass=...`).
        * **Telnet:** Heuristic detection of usernames and passwords following login prompts.
        * **POP3:** `USER` and `PASS` commands.
        * **IMAP:** `LOGIN` commands (plaintext) and `AUTHENTICATE PLAIN` (Base64-decoded).
        * **SMTP:** `AUTH LOGIN` (Base64-decoded parts) and `AUTH PLAIN` (Base64-decoded).
        * **SNMP:** Community Strings.
        * **TFTP:** Read (RRQ) and Write (WRQ) requests, extracting filenames and transfer modes.

* **JSON Export:**
    * Option to save all analysis reports (network scans, credential findings) into structured JSON files for further processing or archival.

* **Interactive User Interface:**
    * A simple, menu-driven command-line interface for easy navigation between analysis modes.

## How to Use

### Prerequisites

* Python 3.x installed.
* `scapy` library installed. You can install it via pip:
    ```bash
    pip install scapy
    ```

### Running the Script

1.  **Save the script:** Save the `pcap_analyzer.py` file to your local machine.
2.  **Prepare PCAP files:** Place your `.pcap` or `.pcapng` files in the same directory as the script, or in a subfolder (e.g., `captures/`).
3.  **Execute:** Open your terminal or command prompt, navigate to the script's directory, and run:
    ```bash
    python pcap_analyzer.py
    ```
4.  **Follow the menu:** The script will present an interactive menu.

    ```
    --- Please select an option ---
    1. Network Scan Analysis
    2. Credential & File Operations
    3. Exit
    Your choice (1, 2 or 3):
    ```

    * **Option 1 (Network Scan Analysis):** You will be prompted for a PCAP file path and can adjust scan detection thresholds.
    * **Option 2 (Credential & File Operations):** You will be prompted for a PCAP file path to extract sensitive information.
    * **Option 3 (Exit):** Terminates the script.

### Example PCAP Files for Testing

You can find various sample PCAP files on the [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) page. Recommended files for testing specific features include:

* **Network Scans:** `nmap-scan-2.pcap`, `nmap_zombie_scan.pcap`
* **FTP:** `ftp.pcap`
* **POP3:** `pop3.pcap`
* **IMAP:** `imap.pcap`
* **SMTP:** `smtp.pcap`
* **Telnet:** `telnet.pcap`
* **TFTP:** `tftp.pcap`
* **SNMP:** `snmp.pcap`
* **HTTP Basic Auth / POST:** These are rarely found in public samples due to security concerns. For reliable testing, you might need to create your own PCAP by performing unencrypted HTTP logins in a test environment.

## Disclaimer

This tool is intended for **educational purposes, cybersecurity labs, and ethical network analysis only**. Use it responsibly and only on networks where you have explicit permission. Unauthorized access or interception of network traffic is illegal and unethical.

---

## Author

Tobias Kastenhuber / LiRiX2

---
