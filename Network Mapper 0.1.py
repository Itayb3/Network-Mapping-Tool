import nmap
import socket
import networkx as nx
import csv

def scan_network():
    # Initialize the network scanner
    nm = nmap.PortScanner()

    # Scan the network to discover devices
    nm.scan(hosts='192.168.1.0/24', arguments='-sn')

    # Get the list of discovered devices with names
    devices = {}
    for host in nm.all_hosts():
        try:
            name = socket.gethostbyaddr(host)[0]
        except socket.herror:
            name = host
        devices[host] = name

    return devices

def create_network_graph(devices):
    # Create an empty graph
    G = nx.Graph()

    # Add devices as nodes to the graph
    for ip, name in devices.items():
        G.add_node(name, ip=ip)

    # Add connections between devices (assuming connected devices)
    # You may need to adjust this based on how your network is structured
    G.add_edge('Router', 'Modem')
    G.add_edge('Router', 'Switch')

    return G

def export_network_topology_to_csv(G):
    # Export the network topology to a CSV file
    with open('C:\Users\ca8855176\Desktop\network_topology.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Source', 'Target'])
        for edge in G.edges():
            writer.writerow([edge[0], edge[1]])

def main():
    # Scan the network
    devices = scan_network()

    # Create the network graph
    G = create_network_graph(devices)

    # Export the network topology to CSV
    export_network_topology_to_csv(G)

if __name__ == "__main__":
    main()
