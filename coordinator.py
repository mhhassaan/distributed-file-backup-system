import json
import os
import requests
import time
import threading
from flask import Flask, request, jsonify
from itertools import cycle

app = Flask(__name__)

# --- Configuration ---
REPLICATION_FACTOR = 4
METADATA_DB_FILE = 'coordinator_metadata.json'

# --- In-Memory State Management ---
storage_nodes = {}
METADATA = {}

def save_metadata_to_disk():
    with open(METADATA_DB_FILE, 'w') as f:
        json.dump(METADATA, f, indent=4)

def load_metadata_from_disk():
    global METADATA
    if os.path.exists(METADATA_DB_FILE) and os.path.getsize(METADATA_DB_FILE) > 0:
        with open(METADATA_DB_FILE, 'r') as f:
            METADATA = json.load(f)
    else:
        METADATA = {}
    print("Coordinator: Metadata loaded into memory.")

def get_active_nodes():
    current_time = time.time()
    return [node for node, stats in storage_nodes.items() if current_time - stats.get('last_seen', 0) < 30]

# --- API Endpoints ---
@app.route('/register', methods=['POST'])
def register_node():
    node_address = request.json.get('address')
    if node_address and node_address not in storage_nodes:
        storage_nodes[node_address] = {'last_seen': time.time()}
        print(f"Coordinator: Registered new storage node: {node_address}")
    return jsonify({"message": "Successfully registered"}), 200

@app.route('/get-storage-nodes', methods=['GET'])
def get_storage_nodes():
    active_nodes = get_active_nodes()
    if len(active_nodes) < REPLICATION_FACTOR:
        return jsonify({"error": "Not enough active nodes."}), 503
    node_cycler = cycle(active_nodes)
    assigned_nodes = [next(node_cycler) for _ in range(REPLICATION_FACTOR)]
    return jsonify({"storage_node_urls": assigned_nodes})

@app.route('/log-backup', methods=['POST'])
def log_backup():
    """
    Logs backup metadata. It now transparently stores the more detailed 
    metadata structure needed for striped replication.
    """
    global METADATA
    data = request.json
    filename = data.get('filename')

    # The data will contain either a 'hash' key (for small files)
    # or a 'chunk_map' and 'chunk_order' (for large, sharded files).
    METADATA[filename] = data
    save_metadata_to_disk()
    
    print(f"\n[DEBUG /log-backup] Logged metadata for '{filename}'.\n")
    return jsonify({"message": "Backup logged successfully."})

@app.route('/get-file-info/<filename>', methods=['GET'])
def get_file_info(filename):
    file_info = METADATA.get(filename)
    if not file_info:
        return jsonify({"error": "File not found."}), 404
    return jsonify(file_info)

@app.route('/list-files', methods=['GET'])
def list_files():
    files_list = [{'name': name, **info} for name, info in METADATA.items()]
    return jsonify(files_list)


@app.route('/delete-file', methods=['POST'])
def delete_file():
    """
    Orchestrates the deletion of a file and all its replicas.
    [FIXED] Now correctly handles both single-hash and chunked files.
    """
    global METADATA
    data = request.json
    filename = data.get('filename')
    if not filename or filename not in METADATA:
        return jsonify({"error": "File not found."}), 404

    file_info = METADATA[filename]
    locations = file_info['locations']
    
    # Determine the list of hashes to delete
    hashes_to_delete = []
    if file_info.get('is_chunked'):
        # For a large file, get the list of chunk hashes
        hashes_to_delete = file_info.get('chunk_hashes', [])
    else:
        # For a small file, get the single hash and put it in a list
        if file_info.get('hash'):
            hashes_to_delete.append(file_info['hash'])

    if not hashes_to_delete:
        print(f"Coordinator: No hashes found to delete for '{filename}'.")
    
    # Command each storage node to delete every chunk/file hash
    for file_hash in hashes_to_delete:
        for node_url in locations:
            try:
                # The storage node's delete endpoint is /delete/<hash>
                delete_url = f"{node_url}/delete/{file_hash}"
                requests.delete(delete_url, timeout=5)
                print(f"Coordinator: Commanded {node_url} to delete {file_hash}")
            except requests.exceptions.RequestException as e:
                print(f"Coordinator: Could not contact node {node_url} to delete file: {e}")

    # After attempting deletion on all nodes, remove the metadata
    del METADATA[filename]
    save_metadata_to_disk()
    
    print(f"Coordinator: Removed metadata for '{filename}'")
    return jsonify({"message": f"Deletion process for '{filename}' initiated."})

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    node_address = request.json.get('address')
    if node_address in storage_nodes:
        storage_nodes[node_address]['last_seen'] = time.time()
    return jsonify({"message": "Heartbeat received"})

def health_check_thread():
    while True:
        time.sleep(20)
        print(f"\n--- Health Check: Active nodes: {get_active_nodes()} ---")

if __name__ == '__main__':
    load_metadata_from_disk()
    checker = threading.Thread(target=health_check_thread, daemon=True)
    checker.start()
    app.run(host='0.0.0.0', port=5002, debug=False)