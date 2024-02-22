import nmap
import socket
import csv
from threading import Thread
from queue import Queue

# Number of threads, needs to add choseable options to gui layer
NUM_THREADS = 15

# the magic thingy
ip_queue = Queue()
# scan result waiting room
results_queue = Queue()

# big boy aint scared to code function
def scan_ip(total_ips):
    nm = nmap.PortScanner()
    while not ip_queue.empty():
        current_ip_number = total_ips - ip_queue.qsize() + 1
        ip = ip_queue.get()
        print(f"Scanning IP number {current_ip_number}/{total_ips}: {ip}")
        try:
            # sppose to be adding OS detection to the argument dosnt work perfectly yet, running scans
            nm.scan(hosts=ip, arguments='-p22,23 -sV -O')
            os_info = "Unknown"
            for proto in nm[ip].all_protocols():
                lport = list(nm[ip][proto].keys())
                if 22 in lport or 23 in lport:
                    try:
                        name = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        name = ip
                    #here i attempt to retrieve OS information if available, awaiting scan results for confirm
                    if 'osclass' in nm[ip] and nm[ip]['osclass']:
                        for osclass in nm[ip]['osclass']:
                            if 'osfamily' in osclass and osclass['osfamily']:
                                os_info = osclass['osfamily']
                                break
                    results_queue.put((name, ip, "Network Device", os_info))
        except Exception as e:
            print(f"Error scanning {ip}: {e}")
        finally: 
            ip_queue.task_done() #this is both cool and also ensure us that the process didnt just die midway

# export the results to CSV using black magic
def export_to_csv():
    with open('network_topology.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Device Name', 'IP Address', 'Device Type', 'Operating System'])
        while not results_queue.empty():
            device = results_queue.get()
            writer.writerow([device[0], device[1], device[2], device[3]])

# Main function to set up and start the scanning process
def main():
    total_ips = 0
    #  IP iratiation queue
    for i in range(1, 255):
        for b in range(1, 255):  # Example for a /24 subnet
            ip_queue.put(f'5.5.{i}.{b}')
            total_ips += 1

    threads = []
    # Start threads use more threads if pc isnt shit
    for _ in range(NUM_THREADS):
        t = Thread(target=lambda: scan_ip(total_ips))
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
