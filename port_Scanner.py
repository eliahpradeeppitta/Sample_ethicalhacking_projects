import socket
import argparse
from threading import Thread, Lock
from queue import Queue
import ipaddress

# --- Configuration ---
# Number of threads to run concurrently
NUM_THREADS = 100
# Timeout for socket connection attempts in seconds
SCAN_TIMEOUT = 1.0

# Queue to hold ports that need to be scanned
queue = Queue()
# Lock to ensure clean printing from multiple threads
screen_lock = Lock()

def is_valid_ip(ip):
    """Checks if the provided string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def scan_port(target_ip, port):
    """
    The core function that attempts to connect to a specific port on the target IP.
    This simulates the first two steps of the TCP 3-way handshake (SYN -> SYN-ACK).
    """
    try:
        # 1. Create a raw TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 2. Set the timeout for the connection attempt
        s.settimeout(SCAN_TIMEOUT)
        
        # 3. Attempt to connect (the 'SYN' part of the handshake)
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            # Connection successful (SYN-ACK received) - Port is OPEN
            
            # Use the screen lock before printing to prevent thread overlap
            with screen_lock:
                print(f"| [+] Port {port:5} is OPEN")
            
            # --- Intermediate Upgrade: Banner Grabbing ---
            # Try to grab the service banner if the port is open
            try:
                # Send a blank line or request (sometimes needed to trigger a banner)
                s.send(b'Hello\r\n')
                # Receive up to 4096 bytes of data (the service banner)
                banner = s.recv(4096).decode('utf-8', errors='ignore').strip()
                if banner:
                    with screen_lock:
                        # Print the banner on a new line for cleanliness
                        print(f"|     -> Banner: {banner[:100]}...")
                
            except socket.error:
                # Handle cases where the banner read fails
                pass 

        # The 'result' is non-zero (often 111 for connection refused or other error codes for filtered)
        # We don't print closed/filtered ports to keep the output clean.

    except socket.gaierror:
        # Handle invalid hostnames
        with screen_lock:
            print(f"| [!] Error resolving hostname: {target_ip}. Skipping.")
    except Exception as e:
        # Catch any unexpected errors during the scan
        with screen_lock:
            print(f"| [!] An unexpected error occurred on port {port}: {e}")
    finally:
        # Crucial: always close the socket
        s.close()


def worker():
    """
    Thread worker function. Each thread continuously grabs a port from the queue
    and calls the scan_port function until the queue is empty.
    """
    while True:
        # Get the next port from the queue
        port = queue.get()
        
        # Call the scanning logic
        # We assume the target_ip is passed to the main function, 
        # but for simplicity in this structure, we'll retrieve it if needed
        # In this multi-threaded design, we need to pass IP to the worker or rely on a global context.
        # Since 'queue' only holds 'port' numbers, we rely on the global scope for the 'target_ip'
        # which is populated in the 'main' function context (a safe pattern here).
        
        # NOTE: For this specific implementation, we rely on 'target_ip' being defined 
        # in the main function's execution scope before threading starts.
        global target_ip
        scan_port(target_ip, port)
        
        # Signal that the task is complete
        queue.task_done()


def main():
    """Parses arguments, initializes threads, and starts the scan."""
    global target_ip # Use the global IP variable for the worker function
    
    parser = argparse.ArgumentParser(description="A fast, multithreaded TCP Port Scanner with banner grabbing.")
    parser.add_argument("target", help="The target IP address or hostname to scan.")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-100) or comma-separated list (e.g., 22,80,443). Default is 1-1024.")
    
    args = parser.parse_args()
    target_ip = args.target

    if not is_valid_ip(target_ip) and not target_ip.isalpha():
        print(f"| [E] Invalid target specified: {target_ip}")
        return

    # 1. Prepare the list of ports
    ports_to_scan = []
    try:
        if '-' in args.ports:
            # Handle port range (e.g., 1-1024)
            start, end = map(int, args.ports.split('-'))
            ports_to_scan = range(start, end + 1)
        elif ',' in args.ports:
            # Handle comma-separated list (e.g., 22,80,443)
            ports_to_scan = [int(p.strip()) for p in args.ports.split(',')]
        else:
            # Handle single port
            ports_to_scan = [int(args.ports)]
    except ValueError:
        print("| [E] Invalid port format. Use N-M or N,M,L format.")
        return

    print(f"\n| --- Starting Scan ---")
    print(f"| Target: {target_ip}")
    print(f"| Ports: {len(ports_to_scan)}")
    print(f"| Threads: {NUM_THREADS}")
    print(f"| Timeout: {SCAN_TIMEOUT}s")
    print(f"| -----------------------\n")

    # 2. Initialize and start the worker threads
    for _ in range(NUM_THREADS):
        t = Thread(target=worker)
        # Daemon threads close when the main program finishes
        t.daemon = True
        t.start()

    # 3. Fill the queue with the ports to be scanned
    for port in ports_to_scan:
        queue.put(port)

    # 4. Wait for the queue to be fully processed (all ports scanned)
    queue.join()

    print("\n| --- Scan Complete ---")

if __name__ == "__main__":
    main()
