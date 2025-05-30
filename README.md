# Simple Python Network Scanner

This is a basic, multi-threaded network scanner built in Python. It allows you to:
- Discover active hosts on a local network segment.
- Scan for open ports on a specified target IP address.

It serves as a foundational project for understanding network reconnaissance concepts in cybersecurity.

---

## Features

-   **Host Discovery:** Scans a given CIDR network range (e.g., `192.168.1.0/24`) for active hosts using basic connection attempts.
-   **Port Scanning:** Scans a target IP address for open ports. Supports custom port ranges (e.g., `1-1024`), specific ports (e.g., `22,80,443`), or defaults to common ports.
-   **Multi-threaded:** Uses Python's `threading` module to speed up scanning operations.
-   **User-friendly CLI:** Simple command-line interface for interaction.

---

## Prerequisites

Before running the scanner, ensure you have **Python 3** installed.
You also need the `ipaddress` library, which can be installed via pip.

---

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YourGitHubUsername/your-network-scanner.git](https://github.com/YourGitHubUsername/your-network-scanner.git)
    cd your-network-scanner
    ```
    (Remember to replace `YourGitHubUsername` and `your-network-scanner` with your actual GitHub username and repository name once created.)

2.  **Create and activate a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    # On Windows:
    # venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## Usage

To run the network scanner, execute the `network_scanner.py` script:

```bash
python network_scanner.py
