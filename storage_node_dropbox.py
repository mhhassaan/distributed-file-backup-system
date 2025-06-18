import os
import sys
import dropbox
import time
import threading
import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

DROPBOX_ACCESS_TOKEN = os.getenv("DROPBOX_ACCESS_TOKEN") #Token for Dropbox API, expires quickly, so make sure to update it in your .env file.
NODE_ID = "default_node" 


if not DROPBOX_ACCESS_TOKEN:
    print("FATAL: DROPBOX_ACCESS_TOKEN not found. Make sure you have created a .env file with the token.")
    sys.exit(1)

try:
    dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
    print("Cloud Node: Successfully connected to Dropbox account.")
except Exception as e:
    print(f"FATAL: Could not connect to Dropbox. Check your access token. Error: {e}")
    sys.exit(1)


@app.route('/store/<file_hash>', methods=['POST'])
def store_chunk(file_hash):
    """Receives data and uploads it to a node-specific folder in Dropbox."""
    try:
        path = f'/backups/{NODE_ID}/{file_hash}'
        dbx.files_upload(request.data, path, mode=dropbox.files.WriteMode('overwrite'))
        print(f"Cloud Node [{NODE_ID}]: Successfully stored {file_hash} in Dropbox at {path}.")
        return jsonify({"message": "File stored in Dropbox."}), 200
    except Exception as e:
        print(f"Cloud Node [{NODE_ID}]: Error storing file {file_hash}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/retrieve/<file_hash>', methods=['GET'])
def retrieve_chunk(file_hash):
    """Retrieves a file from a node-specific folder in Dropbox."""
    try:
        path = f'/backups/{NODE_ID}/{file_hash}'
        metadata, res = dbx.files_download(path=path)
        print(f"Cloud Node [{NODE_ID}]: Successfully retrieved {file_hash} from Dropbox.")
        return res.content, 200
    except dropbox.exceptions.ApiError as e:
        print(f"Cloud Node [{NODE_ID}]: API Error retrieving file {file_hash}: {e}")
        return jsonify({"error": "File not found in Dropbox."}), 404
    except Exception as e:
        print(f"Cloud Node [{NODE_ID}]: Generic Error retrieving file {file_hash}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/delete/<file_hash>', methods=['DELETE'])
def delete_chunk(file_hash):
    """Deletes a file from a node-specific folder in Dropbox."""
    try:
        path = f'/backups/{NODE_ID}/{file_hash}'
        dbx.files_delete_v2(path)
        print(f"Cloud Node [{NODE_ID}]: Successfully deleted {file_hash} from Dropbox.")
        return jsonify({"message": "File deleted."}), 204
    except Exception as e:
        print(f"Cloud Node [{NODE_ID}]: Error deleting file {file_hash}: {e}")
        return jsonify({"error": str(e)}), 500


COORDINATOR_URL = "http://127.0.0.1:5002"
MY_ADDRESS = ""

def register_with_coordinator():
    try:
        requests.post(f"{COORDINATOR_URL}/register", json={'address': MY_ADDRESS}, timeout=5)
        print(f"Cloud Node: Successfully registered with coordinator at {COORDINATOR_URL}")
    except requests.exceptions.RequestException as e:
        print(f"Cloud Node: Could not register with coordinator: {e}")

@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    return jsonify({"message": "Heartbeat received"}), 200

def send_heartbeat():
    while True:
        try:
            requests.post(f"{COORDINATOR_URL}/heartbeat", json={'address': MY_ADDRESS}, timeout=5)
        except requests.exceptions.RequestException:
            print("Cloud Node: Coordinator seems to be down. Will retry...")
        time.sleep(10)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python storage_node_dropbox.py <port> <node_id>")
        sys.exit(1)
        
    port = int(sys.argv[1])
    NODE_ID = sys.argv[2] # Get the Node ID from the command line
    MY_ADDRESS = f"http://127.0.0.1:{port}"
    
    print(f"--- Starting Cloud Node with ID: '{NODE_ID}' on port {port} ---")
    
    register_with_coordinator()
    
    heartbeat_thread = threading.Thread(target=send_heartbeat, daemon=True)
    heartbeat_thread.start()
    
    app.run(host='0.0.0.0', port=port, debug=False)