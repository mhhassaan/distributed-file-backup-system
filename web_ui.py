# web_ui.py (Updated)
import os
import json
import requests
import hashlib
import io
from flask import Flask, request, render_template, redirect, url_for, send_file
from cryptography.fernet import Fernet

app = Flask(__name__)


# --- Configuration ---
COORDINATOR_URL = "http://127.0.0.1:5002" # <-- We now talk to the coordinator
ENCRYPTION_KEY = b'fBNnPtgoyrcbKzhtIwB2ThfWoCmBdopq8m9ty2EWyko='
BACKUP_FOLDER = 'files_to_backup'  # The folder we will monitor for changes
CLIENT_HASH_DB = 'client_local_hashes.json' # Local file to store hashes 

# --- Helper functions for the local hash database ---
def read_local_hashes():
    if not os.path.exists(CLIENT_HASH_DB) or os.path.getsize(CLIENT_HASH_DB) == 0:
        return {}
    with open(CLIENT_HASH_DB, 'r') as f:
        return json.load(f)

def write_local_hashes(hashes):
    with open(CLIENT_HASH_DB, 'w') as f:
        json.dump(hashes, f, indent=4)

@app.route('/')
def index():
    """Render the main page by fetching the file list from the coordinator."""
    try:
        response = requests.get(f"{COORDINATOR_URL}/list-files")
        response.raise_for_status()
        files = response.json()
    except requests.exceptions.RequestException:
        files = [] # If coordinator is down, show an empty list
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if not file:
        return "No file selected", 400

    file_data = file.read()
    original_filename = file.filename
    file_hash = hashlib.sha256(file_data).hexdigest()

    # 1. Ask Coordinator for storage nodes (plural)
    try:
        response = requests.get(f"{COORDINATOR_URL}/get-storage-nodes") # <-- Updated endpoint
        response.raise_for_status()
        storage_node_urls = response.json()['storage_node_urls'] # <-- Expecting a list
    except requests.exceptions.RequestException as e:
        return f"Could not get storage nodes from coordinator: {e}", 500

    # 2. Encrypt and upload to ALL assigned storage nodes
    fernet = Fernet(ENCRYPTION_KEY)
    encrypted_data = fernet.encrypt(file_data)
    
    successful_locations = []
    for node_url in storage_node_urls:
        try:
            upload_url = f"{node_url}/store/{file_hash}"
            requests.post(upload_url, data=encrypted_data).raise_for_status()
            successful_locations.append(node_url)
            print(f"Successfully uploaded to {node_url}")
        except requests.exceptions.RequestException as e:
            print(f"Failed to upload to {node_url}: {e}")
    
    if not successful_locations:
        return "File upload failed on all storage nodes.", 500

    # 3. Log the successful backup locations with the Coordinator
    try:
        log_data = {'filename': original_filename, 'hash': file_hash, 'locations': successful_locations}
        requests.post(f"{COORDINATOR_URL}/log-backup", json=log_data).raise_for_status()
    except requests.exceptions.RequestException as e:
        return f"Uploaded file but could not log with coordinator: {e}", 500

    return redirect(url_for('index'))


@app.route('/restore/<filename>')
def restore_file(filename):
    # 1. Ask Coordinator for the file's locations and hash
    try:
        response = requests.get(f"{COORDINATOR_URL}/get-file-info/{filename}")
        response.raise_for_status()
        file_info = response.json()
        locations = file_info['locations']
        file_hash = file_info['hash']
        is_encrypted = file_info.get('encrypted', False) # <-- Get the flag from coordinator
        
    except requests.exceptions.RequestException as e:
        return f"Could not get file info from coordinator: {e}", 500

    # 2. Try downloading from each location until one succeeds
    encrypted_data = None
    for node_url in locations:
        try:
            print(f"Attempting to download from {node_url}...")
            download_url = f"{node_url}/retrieve/{file_hash}"
            response = requests.get(download_url, timeout=5)
            response.raise_for_status()
            encrypted_data = response.content
            print("Download successful!")
            break 
        except requests.exceptions.RequestException as e:
            print(f"Failed to download from {node_url}: {e}. Trying next replica.")

    if encrypted_data is None:
        return "Could not restore file. All replicas are offline.", 500
    
     # *** NEW: Conditional Decryption ***
    # The client must be able to decrypt its backed-up files 
    if is_encrypted:
        print(f"Decrypting '{filename}'...")
        fernet = Fernet(ENCRYPTION_KEY)
        decrypted_data = fernet.decrypt(encrypted_data)
    else:
        print(f"'{filename}' was not encrypted. Skipping decryption.")
        decrypted_data = encrypted_data # The data is already in its original form


    # 3. Decrypt and verify
    fernet = Fernet(ENCRYPTION_KEY)
    decrypted_data = fernet.decrypt(encrypted_data)
    if hashlib.sha256(decrypted_data).hexdigest() != file_hash:
        return "File integrity check failed!", 500
        
    # 4. THE MISSING LINE: Return the decrypted file to the browser
    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=filename
    )

@app.route('/sync', methods=['POST'])
def sync_folder():
    """
    Scans the backup folder, detects changes, and uploads only new/modified files.
    """
    print("\n--- Starting Synchronization Process ---")
    
    # Create backup folder if it doesn't exist
    if not os.path.exists(BACKUP_FOLDER):
        os.makedirs(BACKUP_FOLDER)


    # *** NEW: Check if the encryption checkbox was ticked ***
    encryption_enabled = 'encrypt' in request.form
    print(f"Encryption enabled for this sync: {encryption_enabled}")
    
    # 1. Load the last known hashes from our local file 
    local_hashes = read_local_hashes()
    files_in_folder = os.listdir(BACKUP_FOLDER)
    
    # 2. Iterate through files and check for changes
    for filename in files_in_folder:
        filepath = os.path.join(BACKUP_FOLDER, filename)
        if not os.path.isfile(filepath):
            continue

        # 3. Calculate current file hash 
        with open(filepath, 'rb') as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()

        # 4. Compare with stored hash to detect changes 
        if local_hashes.get(filename) == current_hash:
            print(f"'{filename}' is unchanged. Skipping.")
            continue # Skip to the next file
        
        # If file is new or modified, start the backup process
        print(f"'{filename}' is new or modified. Backing up...")
        if backup_single_file(filepath, filename, encryption_enabled):
             # Update local hash on successful backup
            local_hashes[filename] = current_hash
        else:
            print(f"Failed to backup '{filename}'. Will retry on next sync.")

    # 5. Save the updated hashes back to the local file
    write_local_hashes(local_hashes)
    print("--- Synchronization Process Finished ---\n")
    return redirect(url_for('index'))

def backup_single_file(filepath, filename, encrypt_file):
    """Refactored backup logic for a single file."""
    with open(filepath, 'rb') as f:
        file_data = f.read()
    file_hash = hashlib.sha256(file_data).hexdigest()

    try:
        # Ask Coordinator for nodes
        response = requests.get(f"{COORDINATOR_URL}/get-storage-nodes")
        response.raise_for_status()
        storage_node_urls = response.json()['storage_node_urls']

        # Encrypt and upload to all nodes 
        fernet = Fernet(ENCRYPTION_KEY)
        encrypted_data = fernet.encrypt(file_data)
        
        successful_locations = []
        for node_url in storage_node_urls:
            upload_url = f"{node_url}/store/{file_hash}"
            requests.post(upload_url, data=encrypted_data).raise_for_status()
            successful_locations.append(node_url)
        
        # Log backup with Coordinator 
        # log_data = {'filename': filename, 'hash': file_hash, 'locations': successful_locations}
        # requests.post(f"{COORDINATOR_URL}/log-backup", json=log_data).raise_for_status()

        # *** NEW: Conditional Encryption ***
        # Per the proposal, we apply encryption on the client side before transmission 
        if encrypt_file:
            print(f"Applying AES encryption for '{filename}'...")
            fernet = Fernet(ENCRYPTION_KEY)
            data_to_upload = fernet.encrypt(file_data)
        else:
            print(f"Uploading '{filename}' without encryption...")
            data_to_upload = file_data # Upload the raw data

        # ... (upload loop is the same, but uses data_to_upload) ...
        for node_url in storage_node_urls:
            upload_url = f"{node_url}/store/{file_hash}"
            requests.post(upload_url, data=data_to_upload).raise_for_status()
            successful_locations.append(node_url)
        
        # Log backup with Coordinator, including encryption status
        log_data = {
            'filename': filename, 
            'hash': file_hash, 
            'locations': successful_locations,
            'encrypted': encrypt_file # <-- Send the encryption status
        }
        requests.post(f"{COORDINATOR_URL}/log-backup", json=log_data).raise_for_status()
        
        print(f"Successfully backed up '{filename}'")
        return True
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during backup of {filename}: {e}")
        return False
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)