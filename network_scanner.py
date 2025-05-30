import socket
import ipaddress
import threading
import time

# --- Configuration ---
# Define a timeout for socket connections (in seconds)
SOCKET_TIMEOUT = 1.0
# Define a list of common ports to scan by default
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389, 8080]


# --- Helper Functions ---

def get_local_ip_and_gateway():
    """
    Attempts to get the local IP address and a potential default gateway.
    This is a basic attempt and might not work in all network configurations.
    """
    try:
        # Create a temporary socket to connect to an external address (doesn't actually send data)
        # This helps determine the local IP used for outgoing connections.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's DNS server
        local_ip = s.getsockname()[0]
        s.close()

        # For gateway, it's harder to get directly without parsing routing tables.
        # We'll just infer a common gateway based on the local IP.
        # E.g., if local_ip is 192.168.1.X, gateway is often 192.168.1.1
        ip_parts = local_ip.split('.')
        if len(ip_parts) == 4:
            gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
        else:
            gateway = "N/A (Could not infer)"

        print(f"[*] Local IP: {local_ip}")
        print(f"[*] Inferred Gateway: {gateway}")
        return local_ip, gateway
    except Exception as e:
        print(f"[!] Could not determine local IP or gateway: {e}")
        return "N/A", "N/A"


def is_host_active(ip_address, timeout=0.5):
    """
    Checks if a host is active by attempting to connect to a common port (e.g., 80 or 443).
    This is a basic check and not a true ICMP ping.
    """
    try:
        # Try connecting to a common HTTP port first
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip_address, 80))
        sock.close()
        if result == 0:
            return True

        # If port 80 fails, try HTTPS port 443
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip_address, 443))
        sock.close()
        if result == 0:
            return True

        return False
    except socket.error:
        return False


def scan_port(ip_address, port, open_ports):
    """
    Attempts to connect to a specific port on an IP address.
    If successful, the port is considered open.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        result = sock.connect_ex((ip_address, port))  # connect_ex returns an error indicator
        if result == 0:
            print(f"    [+] Port {port} is OPEN")
            open_ports.append(port)
        sock.close()
    except socket.error as e:
        # print(f"    [-] Port {port} scan error: {e}") # Uncomment for debugging
        pass  # Port is likely closed or filtered


# --- Main Scanning Functions ---

def host_scanner(network_cidr):
    """
    Scans a given CIDR network range for active hosts.
    Uses threading to speed up the process.
    """
    print(f"\n--- Host Scanning for {network_cidr} ---")
    active_hosts = []
    threads = []

    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError as e:
        print(f"[!] Invalid network CIDR: {e}")
        return

    print(f"[*] Scanning {network.num_addresses} possible hosts...")

    start_time = time.time()
    for ip in network.hosts():  # Iterate over usable hosts in the network
        ip_str = str(ip)
        thread = threading.Thread(target=lambda: (active_hosts.append(ip_str) if is_host_active(ip_str) else None))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    end_time = time.time()

    if active_hosts:
        print("\n--- Active Hosts Found ---")
        for host in sorted(active_hosts, key=lambda ip: ipaddress.IPv4Address(ip)):
            print(f"  [+] {host}")
    else:
        print("\n[!] No active hosts found in the specified network range.")
    print(f"[*] Host scan completed in {end_time - start_time:.2f} seconds.")


def port_scanner(target_ip, port_range_str=None):
    """
    Scans a target IP address for open ports within a specified range.
    Uses threading for concurrent port scanning.
    """
    print(f"\n--- Port Scanning for {target_ip} ---")
    open_ports = []
    threads = []

    ports_to_scan = []
    if port_range_str:
        try:
            if '-' in port_range_str:
                start_port, end_port = map(int, port_range_str.split('-'))
                ports_to_scan = range(start_port, end_port + 1)
            elif ',' in port_range_str:
                ports_to_scan = [int(p.strip()) for p in port_range_str.split(',')]
            else:
                ports_to_scan = [int(port_range_str)]
        except ValueError:
            print("[!] Invalid port range format. Using common ports.")
            ports_to_scan = COMMON_PORTS
    else:
        print("[*] No specific ports provided. Scanning common ports.")
        ports_to_scan = COMMON_PORTS

    if not ports_to_scan:
        print("[!] No ports to scan. Exiting port scan.")
        return

    print(f"[*] Scanning {len(ports_to_scan)} ports on {target_ip}...")

    start_time = time.time()
    for port in ports_to_scan:
        if 0 < port <= 65535:  # Ensure port is valid
            thread = threading.Thread(target=scan_port, args=(target_ip, port, open_ports))
            threads.append(thread)
            thread.start()
        else:
            print(f"[!] Skipping invalid port number: {port}")

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    end_time = time.time()

    if open_ports:
        print(f"\n--- Open Ports on {target_ip} ---")
        for port in sorted(open_ports):
            print(f"  [+] Port {port} is OPEN")
    else:
        print(f"\n[!] No open ports found on {target_ip} in the specified range.")
    print(f"[*] Port scan completed in {end_time - start_time:.2f} seconds.")


# --- Main Application Logic ---

def main():
    """
    Main function to run the network scanner.
    Provides a command-line interface for the user.
    """
    print("--- Simple Python Network Scanner ---")
    get_local_ip_and_gateway()

    while True:
        print("\nSelect an option:")
        print("1. Scan for active hosts on a network (e.g., 192.168.1.0/24)")
        print("2. Scan for open ports on a target IP (e.g., 192.168.1.1)")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == '1':
            network_cidr = input("Enter the network CIDR (e.g., 192.168.1.0/24): ").strip()
            if network_cidr:
                host_scanner(network_cidr)
            else:
                print("[!] Network CIDR cannot be empty.")
        elif choice == '2':
            target_ip = input("Enter the target IP address: ").strip()
            if target_ip:
                port_range_input = input(
                    "Enter port(s) to scan (e.g., 1-1024 or 80,443 or 22, leave empty for common ports): ").strip()
                port_scanner(target_ip, port_range_input if port_range_input else None)
            else:
                print("[!] Target IP cannot be empty.")
        elif choice == '3':
            print("Exiting program. Sayonara!")
            break
        else:
            print("[!] Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
