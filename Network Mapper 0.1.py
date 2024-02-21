import nmap
import socket
import csv
from threading import Thread
from queue import Queue

# Number of threads to use
NUM_THREADS = 5

# Queue for IPs to scan
ip_queue = Queue()
# Queue to collect scan results
results_queue = Queue()

def scan_ip():
    nm = nmap.PortScanner()
    while not ip_queue.empty():
        ip = ip_queue.get()
        try:
            nm.scan(hosts=ip, arguments='-p22,23 -sV')
            for proto in nm[ip].all_protocols():
                lport = list(nm[ip][proto].keys())
                if 22 in lport or 23 in lport:
                    try:
                        name = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        name = ip
                    results_queue.put((name, ip, "Network Device"))
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
        finally:
            ip_queue.task_done()

def export_to_csv():
    with open('network_topology.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Device Name', 'IP Address', 'Device Type'])
        while not results_queue.empty():
            device = results_queue.get()
            writer.writerow([device[0], device[1], device[2]])

def main():
    # Populate the IP queue here with your target IPs
    for i in range(1, 255):
        for b in range(1, 255):  # Example for a /24 subnet
            ip_queue.put(f'10.109.{i}.{b}')

    threads = []
    # Start threads
    for _ in range(NUM_THREADS):
        t = Thread(target=scan_ip)
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for the IP queue to be processed
    ip_queue.join()

    # Ensure all threads have finished execution
    for t in threads:
        t.join()

    # Export results to CSV
    export_to_csv()

if __name__ == "__main__":
    main()
