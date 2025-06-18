import os
import sys
import dropbox
import time
import threading
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

DROPBOX_ACCESS_TOKEN = "sl.u.AFxWrtC_1UUgdWARJJkFRYHfinbKo1EwaVyVQ8o02hV_nBZd20KfsGnVYKRa547BV7699xPhgPn9BVa4WluEhy5eemayT3sg93t9ZU_VsMSruF_sKxaLajkTrO7IumkTnMkH7FcoyXoEfITEVsLTytjenVH2s8G6vR1CZ0GInFcjyU9LzWrIrg-WA_dyTPjNJJ_0AxJqjubvITxzfhPcMy7DKqccaVulBu_M25zOVzSGhvWzHo8a9mOsWXi9hYezLKUeS6VLsZ5-f4pWwFF8yAuwlDSb2ig87GaWbEZDpy75SjlFexf8e5J7IO6eW--B4-66heyFBTkfE6jyYkGit0aQT341qdlYDRQJCHHZnGdTz3tGLtfd-_dZVazz2w2o5cpVq697shm4hUSYe2ww3RGxYmHwbrYknvdLQncfY2JfbOCAAkSej670f1kfApua8DhClZPyxo4nJ6W3d9ZkTS3USAaGpYDMi6rRkMdYfo7TJKzg4O5ORQ3NuVHhHlbHOT3h8788jYy0WDSQFf22u_h4zJjtROoCZbB9uSFONkLqgiD1qq-9cB5yt6eBl2Ei9ZN4ls_woSeZZFKy-SmYIclfAz6sCoBhd0IhIZPPXZg2dKXjwcYEkjKSeq7xJcNAG-40WOa1omqXNdDIEY2tq26R13G5UrF2w3NEXN1y_uf6RTiJaUFh3VyHf7gLqVm8GguhcKbZ0-4-alIIXq2KO-98TeP-JynnhG5Uol9Mn-ZiRFsJxIS4T6KKMWbBb6aR6uKm75QbgZG1Tt_VVL-HuV4Xx8BUD_WqbF6bsL8uaNCmtkOJ8cpG4eCrXuxDq3zOXksjkuuOrWbYTlJZMZEIyc-2gO2vYdh34IxqOTMF3X_heDU_cGrgqjXw-W8DXa2sdokV_Zac86XdOTaHlpCYVWQe2IFyjqkCOhY70aO9E_AZlKf4KwCsl5a6j6phhApU-5kwU5uGKj5ZkHrk26v4HpEEhHANGJKAGNZcalRVqh2CVSWFVoq_teX0VvEWC7TKEYPJ4UqQlGC7q_iJbCNdeew_iI5_h1fi0XukOgRe4gT2de5HN58iPGlQJzsYSHS_HHzU4zEYrqTE_maY73_Ccq6FNpTsLvnON8NH8QJ_z_WBTrGLTABeo6Y5WqTCQJziliTVK9lYobn9JoOKmgtPq1il9z3g2stq_YVCS4Wg2GBhiBd1zFZUJCzFpWfiCWwT7B83_rZXIujKsZmbFSDJwXgPTMaS69jMOgvALVrSMxpQlrYFdeP-5Xk1vKS7KAYXtIschVRqLCIw3LHmF0yi9OxFc-YD8ZF0huJjeqisSf5zb08zyQbZsG1fTSAMBeRiP9WuKoV6E2MHr_WTbfMWno6-JGZv9biypkbT0EhiVbRv8ADTIIkJ29KuWOlWZaL002ZPPf0OYiJxu0kJdpONN3HDFxtM1NdohkqOCLBQsXcrDQZFMlAHYiZN0krAiEXcr4c"
NODE_ID = "default_node" 


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