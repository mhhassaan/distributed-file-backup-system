# coordinator.py (Updated for Replication)
import json
import os
import time # <-- Add time import
import threading # <-- Add threading import
from flask import Flask, request, jsonify
from itertools import cycle

app = Flask(__name__)

# --- Configuration ---
REPLICATION_FACTOR = 2
storage_nodes = {}
METADATA_DB = 'coordinator_metadata.json'

# --- Helper function to get a list of currently active nodes ---
def get_active_nodes():
    # A node is active if it has sent a heartbeat recently (e.g., within 30 seconds)
    current_time = time.time()
    return [node for node, stats in storage_nodes.items() if current_time - stats.get('last_seen', 0) < 30]

def read_metadata():
    if not os.path.exists(METADATA_DB):
        return {} # Use a dictionary for metadata: {filename: {hash: ..., locations: ...}}
    if os.path.getsize(METADATA_DB) == 0:
        return {}
    with open(METADATA_DB, 'r') as f:
        return json.load(f)

def write_metadata(data):
    with open(METADATA_DB, 'w') as f:
        json.dump(data, f, indent=4)

# --- API Endpoints ---

@app.route('/register', methods=['POST'])
def register_node():
    node_address = request.json.get('address')
    if node_address and node_address not in storage_nodes:
        storage_nodes[node_address] = {'last_seen': time.time()}
        print(f"Registered new storage node: {node_address}")
    return jsonify({"message": "Successfully registered"}), 200

@app.route('/get-storage-nodes', methods=['GET']) # <-- Renamed for clarity
def get_storage_nodes():
    """
    Assign a set of storage nodes for a new file backup.
    """
    active_nodes = get_active_nodes()
    if len(active_nodes) < REPLICATION_FACTOR:
        return jsonify({"error": "Not enough active storage nodes to meet replication factor."}), 503
    
    # Simple round-robin assignment for multiple nodes
    node_cycler = cycle(active_nodes)
    assigned_nodes = [next(node_cycler) for _ in range(REPLICATION_FACTOR)]
    
    return jsonify({"storage_node_urls": assigned_nodes})

@app.route('/log-backup', methods=['POST'])
def log_backup():
    """The client calls this after a successful upload to log the file's metadata."""
    data = request.json
    filename = data.get('filename')
    file_hash = data.get('hash')
    locations = data.get('locations')
    is_encrypted = data.get('encrypted', False) # <-- Get the new encryption flag

    metadata = read_metadata()
    metadata[filename] = {
        'hash': file_hash,
        'locations': locations,
        'encrypted': is_encrypted # <-- Store the flag in the metadata
    }
    write_metadata(metadata)
    print(f"Logged backup for {filename} (Encrypted: {is_encrypted}) at {locations}")
    return jsonify({"message": "Backup logged successfully."})

@app.route('/get-file-info/<filename>', methods=['GET'])
def get_file_info(filename):
    """Return the location, hash, and encryption status of a file."""
    metadata = read_metadata()
    file_info = metadata.get(filename)
    if not file_info:
        return jsonify({"error": "File not found."}), 404
    
    # We now also return the 'encrypted' flag
    response_data = {
        'hash': file_info['hash'],
        'locations': file_info['locations'],
        'encrypted': file_info.get('encrypted', False) # <-- Return the flag
    }
    return jsonify(response_data)

@app.route('/list-files', methods=['GET'])
def list_files():
    """A new endpoint to provide the list of files for the UI."""
    metadata = read_metadata()
    # Format the data for the UI template
    files_list = [{'name': name, 'hash': info['hash']} for name, info in metadata.items()]
    return jsonify(files_list)

# --- NEW: Heartbeat Mechanism ---
@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    """Receives heartbeats from storage nodes."""
    node_address = request.json.get('address')
    if node_address in storage_nodes:
        storage_nodes[node_address]['last_seen'] = time.time()
    return jsonify({"message": "Heartbeat received"}), 200

def health_check_thread():
    """A background thread to periodically print the status of nodes."""
    while True:
        print("\n--- Health Check ---")
        active_nodes = get_active_nodes()
        print(f"Active nodes: {active_nodes}")
        print("--------------------\n")
        time.sleep(15)

if __name__ == '__main__':
    # Start the health check thread
    checker = threading.Thread(target=health_check_thread, daemon=True)
    checker.start()
    app.run(host='0.0.0.0', port=5002, debug=True)

