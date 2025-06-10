# storage_node.py (Updated for Heartbeats)
import os
import sys
import requests
import time # <-- Add time
import threading # <-- Add threading
from flask import Flask, request, send_from_directory, jsonify

app = Flask(__name__)
STORAGE_DIR = "storage_node_data"
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

# --- NEW: Registration Logic ---
COORDINATOR_URL = "http://127.0.0.1:5002"
MY_ADDRESS = "" # Will be set at runtime

def register_with_coordinator():
    """Announce this node's presence to the coordinator."""
    try:
        response = requests.post(f"{COORDINATOR_URL}/register", json={'address': MY_ADDRESS})
        response.raise_for_status()
        print(f"Successfully registered with coordinator at {COORDINATOR_URL}")
    except requests.exceptions.RequestException as e:
        print(f"Could not register with coordinator: {e}")
        # In a real system, you might want to exit or retry

# --- NEW: Heartbeat Thread ---
def send_heartbeat():
    """In a background thread, periodically send a heartbeat to the coordinator."""
    while True:
        try:
            requests.post(f"{COORDINATOR_URL}/heartbeat", json={'address': MY_ADDRESS})
            # This is the node pinging the coordinator 
        except requests.exceptions.RequestException:
            print("Coordinator seems to be down. Will retry...")
        time.sleep(10) # Send heartbeat every 10 seconds
# --- END NEW ---

@app.route('/store/<file_hash>', methods=['POST'])
def store_chunk(file_hash):
    file_path = os.path.join(STORAGE_DIR, file_hash)
    with open(file_path, 'wb') as f:
        f.write(request.data)
    print(f"Successfully stored file with hash: {file_hash}")
    return jsonify({"message": f"File {file_hash} stored successfully."}), 200

@app.route('/retrieve/<file_hash>', methods=['GET'])
def retrieve_chunk(file_hash):
    file_path = os.path.join(STORAGE_DIR, file_hash)
    if os.path.exists(file_path):
        print(f"Serving file with hash: {file_hash}")
        return send_from_directory(STORAGE_DIR, file_hash)
    else:
        return jsonify({"error": "File not found."}), 404
    
@app.route('/delete/<file_hash>', methods=['DELETE'])
def delete_chunk(file_hash):
    """
    Deletes a specific file chunk based on its hash.
    """
    try:
        file_path = os.path.join(STORAGE_DIR, file_hash)
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Successfully deleted file with hash: {file_hash}")
            return jsonify({"message": f"File {file_hash} deleted successfully."}), 200
        else:
            # It's not an error if the file is already gone
            return jsonify({"message": "File not found, but considered deleted."}), 200
    except Exception as e:
        print(f"Error deleting file {file_hash}: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5001
    MY_ADDRESS = f"http://127.0.0.1:{port}"
    
    register_with_coordinator()
    
    # Start the heartbeat thread
    heartbeat_thread = threading.Thread(target=send_heartbeat, daemon=True)
    heartbeat_thread.start()
    
    app.run(host='0.0.0.0', port=port, debug=False)