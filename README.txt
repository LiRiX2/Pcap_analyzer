# PcapAnalyzer

An interactive Python-based network analysis tool designed for Security Analysts to efficiently identify scan activities and extract sensitive information from PCAP files. This tool is ideal for cybersecurity labs, blue team exercises, and network forensics.

✨ **Features**

* **Network Scan Detection & Classification:**
    * Identifies and classifies various network scan types (e.g., TCP Connect, SYN, FIN, XMAS, NULL, ACK Scans).
    * Detects and highlights **Suspected Zombie Hosts (Idle Scans)** with detailed reasoning.
    * Provides comprehensive reports including source IP, scan type, timestamps, duration, unique targets, unique ports, used protocols, and TCP flags.
    * Supports adjustable detection thresholds for fine-tuning.

* **Plaintext Credential & Sensitive File Operation Extraction:**
    * Extracts usernames and passwords transmitted in plaintext or easily decodable formats.
    * Detects sensitive file transfer operations.
    * **Prioritized Reporting:** Urgent alerts for full plaintext username/password pairs, followed by other sensitive findings.
    * **Supported Protocols / Types:**
        * **FTP:** `USER` and `PASS` commands.
        * **HTTP Basic Authentication:** Base64-decoded credentials.
        * **HTTP POST Forms:** Common username/password parameters from URL-encoded form data.
        * **Telnet:** Heuristic detection of credentials following login prompts.
        * **POP3:** `USER` and `PASS` commands.
        * **IMAP:** `LOGIN` (plaintext) and `AUTHENTICATE PLAIN` (Base64-decoded).
        * **SMTP:** `AUTH LOGIN` (Base64-decoded parts) and `AUTH PLAIN` (Base64-decoded).
        * **SNMP:** Community Strings.
        * **TFTP:** Read (RRQ) and Write (WRQ) requests (filenames & modes).

* **JSON Export:**
    * Option to save all analysis reports (network scans, credential findings) into structured JSON files for further processing or archival.

* **Interactive User Interface:**
    * A simple, menu-driven command-line interface for easy navigation between analysis modes.

---

🛠️ **Installation & Setup**

1.  **Install Python:** Make sure you have [Python 3.x](https://www.python.org/downloads/) installed on your system.

2.  **Install Dependencies:** Open your terminal or command prompt and install the required Python libraries:
    ```bash
    pip install scapy
    ```

---

🚀 **Usage**

1.  **Clone or Download the Project:** If you've cloned or downloaded the project from GitHub, navigate to the project's root directory in your terminal.

2.  **Run the Script:** Execute the main Python script:
    ```bash
    python pcap_analyzer.py
    ```

3.  **Follow the Menu:** The script will present an interactive menu to guide you through various analysis options.

---
-----

### Author

Tobias Kastenhuber/LiRiX2

-----

⚠️ **Disclaimer**

This tool is intended for **educational purposes, cybersecurity labs, and ethical network analysis only**. Use it responsibly and only on networks where you have explicit permission. Unauthorized access or interception of network traffic is illegal and unethical.
