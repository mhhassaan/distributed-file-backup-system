import json
import os
import requests  # <-- Added missing import
import time
import threading
from flask import Flask, request, jsonify
from itertools import cycle

app = Flask(__name__)

# --- Configuration ---
REPLICATION_FACTOR = 2
METADATA_DB_FILE = 'coordinator_metadata.json'

# --- In-Memory State Management ---
# These global variables are the "single source of truth" while the app is running.
storage_nodes = {}
METADATA = {}

def save_metadata_to_disk():
    """Saves the current in-memory METADATA to the JSON file."""
    with open(METADATA_DB_FILE, 'w') as f:
        json.dump(METADATA, f, indent=4)

def load_metadata_from_disk():
    """Loads metadata from the JSON file into memory at startup."""
    global METADATA
    if os.path.exists(METADATA_DB_FILE) and os.path.getsize(METADATA_DB_FILE) > 0:
        with open(METADATA_DB_FILE, 'r') as f:
            METADATA = json.load(f)
    else:
        METADATA = {}
    print("Metadata loaded into memory.")

def get_active_nodes():
    """Returns a list of storage nodes that have sent a recent heartbeat."""
    current_time = time.time()
    return [node for node, stats in storage_nodes.items() if current_time - stats.get('last_seen', 0) < 30]

# --- API Endpoints ---

@app.route('/register', methods=['POST'])
def register_node():
    node_address = request.json.get('address')
    if node_address and node_address not in storage_nodes:
        storage_nodes[node_address] = {'last_seen': time.time()}
        print(f"Registered new storage node: {node_address}")
    return jsonify({"message": "Successfully registered"}), 200

@app.route('/get-storage-nodes', methods=['GET'])
def get_storage_nodes():
    """Assigns a set of storage nodes for a new file backup."""
    active_nodes = get_active_nodes()
    if len(active_nodes) < REPLICATION_FACTOR:
        return jsonify({"error": "Not enough active nodes."}), 503
    
    node_cycler = cycle(active_nodes)
    assigned_nodes = [next(node_cycler) for _ in range(REPLICATION_FACTOR)]
    return jsonify({"storage_node_urls": assigned_nodes})

@app.route('/log-backup', methods=['POST'])
def log_backup():
    """
    Logs backup metadata. Now handles both single-hash files and chunked files.
    """
    global METADATA
    data = request.json
    filename = data.get('filename')

    # The client will now send a more detailed metadata payload
    METADATA[filename] = {
        'is_chunked': data.get('is_chunked', False),
        'hash': data.get('hash'), # Will be None for chunked files
        'chunk_hashes': data.get('chunk_hashes'), # Will be a list for chunked files
        'locations': data.get('locations'),
        'encrypted': data.get('encrypted', False)
    }
    save_metadata_to_disk()
    
    print(f"\n[DEBUG /log-backup] File logged. In-memory METADATA is now: {METADATA}\n")
    return jsonify({"message": "Backup logged successfully."})
@app.route('/get-file-info/<filename>', methods=['GET'])
def get_file_info(filename):
    """Retrieves file info directly from memory."""
    file_info = METADATA.get(filename)
    if not file_info:
        return jsonify({"error": "File not found."}), 404
    return jsonify(file_info)

@app.route('/list-files', methods=['GET'])
def list_files():
    """Provides the list of files to the UI, reading directly from memory."""
    print(f"\n[DEBUG /list-files] Client is requesting file list. Sending data from METADATA: {METADATA}\n")
    files_list = [{'name': name, **info} for name, info in METADATA.items()]
    return jsonify(files_list)

# FIXED: Added the missing @app.route decorator
@app.route('/delete-file', methods=['POST'])
def delete_file():
    """Orchestrates the deletion of a file and all its replicas."""
    global METADATA
    data = request.json
    filename = data.get('filename')
    if not filename or filename not in METADATA:
        return jsonify({"error": "File not found."}), 404

    file_info = METADATA[filename]
    file_hash = file_info['hash']
    locations = file_info['locations']

    for node_url in locations:
        try:
            requests.delete(f"{node_url}/delete/{file_hash}", timeout=5)
        except requests.exceptions.RequestException as e:
            print(f"Could not contact node {node_url} to delete file: {e}")

    # After attempting deletion, remove the metadata from memory
    del METADATA[filename]
    save_metadata_to_disk()
    
    print(f"Removed metadata for '{filename}'")
    return jsonify({"message": f"Deletion process for '{filename}' initiated."})

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    """Receives heartbeats from storage nodes."""
    node_address = request.json.get('address')
    if node_address in storage_nodes:
        storage_nodes[node_address]['last_seen'] = time.time()
    return jsonify({"message": "Heartbeat received"})

def health_check_thread():
    """A background thread to periodically print the status of active nodes."""
    while True:
        time.sleep(20)
        print("\n--- Health Check ---")
        print(f"Active nodes: {get_active_nodes()}")
        print("--------------------\n")

if __name__ == '__main__':
    load_metadata_from_disk()
    
    checker = threading.Thread(target=health_check_thread, daemon=True)
    checker.start()
    app.run(host='0.0.0.0', port=5002, debug=True)