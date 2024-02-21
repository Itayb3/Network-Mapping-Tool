import csv
import networkx as nx
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import messagebox

def import_network_topology_from_csv():
    # Read network topology from the CSV file
    G = nx.Graph()
    with open('network_topology.csv', 'r') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip header
        for row in reader:
            G.add_edge(row[0], row[1])
    return G

def visualize_network_graph(G):
    # Create a Tkinter window
    root = tk.Tk()
    root.title("Network Topology")

    # Create a canvas
    canvas = tk.Canvas(root, width=800, height=600)
    canvas.pack()

    # Draw the network graph on the canvas
    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_size=700, node_color='skyblue', font_size=8, font_weight='bold', ax=canvas)

    # Run the Tkinter event loop
    root.mainloop()

def main():
    try:
        # Import the network topology from CSV
        G = import_network_topology_from_csv()

        # Visualize the network graph
        visualize_network_graph(G)
    except FileNotFoundError:
        messagebox.showerror("Error", "Network topology CSV file not found. Please run the script to export the network topology first.")

if __name__ == "__main__":
    main()
