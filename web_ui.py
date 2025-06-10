import os
import json
import requests
import hashlib
import io
import base64
from flask import Flask, request, render_template, redirect, url_for, send_file, flash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey # Correct exception for decryption failures

app = Flask(__name__)
# A secret key is required for flashing messages to the user
app.secret_key = os.urandom(24) 

# --- Configuration ---
COORDINATOR_URL = "http://127.0.0.1:5002"
BACKUP_FOLDER = 'files_to_backup'
CLIENT_HASH_DB = 'client_local_hashes.json'
SALT = b'pdc-project-salt' # Static salt for the key derivation function

# --- Key Derivation Helper Function ---
def derive_key(password: str) -> bytes:
    """Derives a valid Fernet key from a user password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# --- Local Hash DB Helper Functions ---
def read_local_hashes():
    """Reads the client's local cache of file hashes."""
    if not os.path.exists(CLIENT_HASH_DB) or os.path.getsize(CLIENT_HASH_DB) == 0:
        return {}
    with open(CLIENT_HASH_DB, 'r') as f:
        return json.load(f)

def write_local_hashes(hashes):
    """Writes to the client's local cache of file hashes."""
    with open(CLIENT_HASH_DB, 'w') as f:
        json.dump(hashes, f, indent=4)

# --- Reusable Backup Logic ---
def backup_single_file(file_data, filename, encrypt_file, password):
    """
    Handles the entire backup process for a single file's data.
    This function is now used by both single upload and folder sync.
    """
    file_hash = hashlib.sha256(file_data).hexdigest()

    try:
        # 1. Ask Coordinator for storage nodes
        response = requests.get(f"{COORDINATOR_URL}/get-storage-nodes")
        response.raise_for_status()
        storage_node_urls = response.json()['storage_node_urls']

        # 2. Conditionally encrypt the data based on user choice
        if encrypt_file:
            print(f"Applying AES encryption for '{filename}'...")
            key = derive_key(password)
            fernet = Fernet(key)
            data_to_upload = fernet.encrypt(file_data)
        else:
            print(f"Uploading '{filename}' without encryption...")
            data_to_upload = file_data

        # 3. Upload data to all assigned replica nodes
        successful_locations = []
        for node_url in storage_node_urls:
            upload_url = f"{node_url}/store/{file_hash}"
            requests.post(upload_url, data=data_to_upload).raise_for_status()
            successful_locations.append(node_url)
        
        # 4. Log the successful backup with the Coordinator
        log_data = {
            'filename': filename, 
            'hash': file_hash, 
            'locations': successful_locations,
            'encrypted': encrypt_file
        }
        requests.post(f"{COORDINATOR_URL}/log-backup", json=log_data).raise_for_status()
        
        print(f"Successfully backed up '{filename}'")
        return True
    except requests.exceptions.RequestException as e:
        print(f"An error occurred during backup of {filename}: {e}")
        return False

# --- Flask Routes ---

@app.route('/')
def index():
    """Renders the main page with the list of backed-up files from the coordinator."""
    try:
        response = requests.get(f"{COORDINATOR_URL}/list-files")
        response.raise_for_status()
        files = response.json()
    except requests.exceptions.RequestException:
        files = []
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles the single file upload form."""
    if 'file' not in request.files or request.files['file'].filename == '':
        flash("No file selected for upload.", "error")
        return redirect(url_for('index'))

    file = request.files['file']
    filename = file.filename
    file_data = file.read()

    encryption_enabled = 'encrypt' in request.form
    password = request.form.get('password', '')

    if encryption_enabled and not password:
        flash("Encryption was selected, but no password was provided.", "error")
        return redirect(url_for('index'))

    # Call our reusable backup function
    if backup_single_file(file_data, filename, encryption_enabled, password):
        # On success, update the local hash cache so the sync feature is aware of this file
        local_hashes = read_local_hashes()
        local_hashes[filename] = hashlib.sha256(file_data).hexdigest()
        write_local_hashes(local_hashes)
        flash(f"'{filename}' was uploaded successfully!", "success")
    else:
        flash(f"Failed to upload '{filename}'.", "error")

    return redirect(url_for('index'))

@app.route('/sync', methods=['POST'])
def sync_folder():
    """Handles the folder sync form for incremental backups."""
    encryption_enabled = 'encrypt' in request.form
    password = request.form.get('password', '')

    if encryption_enabled and not password:
        flash("Encryption was selected, but no password was provided.", "error")
        return redirect(url_for('index'))
    
    print("\n--- Starting Synchronization Process ---")
    if not os.path.exists(BACKUP_FOLDER):
        os.makedirs(BACKUP_FOLDER)

    local_hashes = read_local_hashes()
    files_in_folder = os.listdir(BACKUP_FOLDER)
    
    for filename in files_in_folder:
        filepath = os.path.join(BACKUP_FOLDER, filename)
        if not os.path.isfile(filepath):
            continue

        with open(filepath, 'rb') as f:
            file_data = f.read()
        current_hash = hashlib.sha256(file_data).hexdigest()

        if local_hashes.get(filename) == current_hash:
            print(f"'{filename}' is unchanged. Skipping.")
            continue
        
        print(f"'{filename}' is new or modified. Backing up...")
        # Call our reusable backup function, passing the file data
        if backup_single_file(file_data, filename, encryption_enabled, password):
             local_hashes[filename] = current_hash
        else:
            print(f"Failed to backup '{filename}'. Will retry on next sync.")

    write_local_hashes(local_hashes)
    print("--- Synchronization Process Finished ---\n")
    flash("Synchronization process completed.", "success")
    return redirect(url_for('index'))

@app.route('/restore/<filename>')
def restore_file(filename):
    """Handles restoring a file, with or without password decryption."""
    try:
        # 1. Get file info from coordinator
        response = requests.get(f"{COORDINATOR_URL}/get-file-info/{filename}")
        response.raise_for_status()
        file_info = response.json()
        locations = file_info['locations']
        file_hash = file_info['hash']
        is_encrypted = file_info.get('encrypted', False)
        
        password = request.args.get('password', '')
        if is_encrypted and not password:
            flash("File is encrypted, but no password was provided for restore.", "error")
            return redirect(url_for('index'))
            
    except requests.exceptions.RequestException as e:
        flash(f"Could not get file info from coordinator: {e}", "error")
        return redirect(url_for('index'))

    # 2. Try downloading from each replica location
    downloaded_data = None
    for node_url in locations:
        try:
            download_url = f"{node_url}/retrieve/{file_hash}"
            response = requests.get(download_url, timeout=5)
            response.raise_for_status()
            downloaded_data = response.content
            print(f"Download successful from {node_url}")
            break 
        except requests.exceptions.RequestException as e:
            print(f"Failed to download from {node_url}: {e}. Trying next replica.")

    if downloaded_data is None:
        flash("Could not restore file. All replicas are offline.", "error")
        return redirect(url_for('index'))
    
    # 3. Conditionally decrypt the downloaded data
    if is_encrypted:
        try:
            key = derive_key(password)
            fernet = Fernet(key)
            decrypted_data = fernet.decrypt(downloaded_data)
        except InvalidToken:
            flash("Decryption failed! The password may be incorrect.", "error")
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"An unknown decryption error occurred: {e}", "error")
            return redirect(url_for('index'))
    else:
        decrypted_data = downloaded_data
    
    # 4. Verify data integrity and send file to user
    if hashlib.sha256(decrypted_data).hexdigest() != file_hash:
        flash("File integrity check failed after download. Data may be corrupt.", "error")
        return redirect(url_for('index'))
        
    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=filename
    )

@app.route('/delete/<filename>', methods=['POST'])
def delete_backup(filename):
    """Initiates the deletion of a backup by calling the coordinator."""
    try:
        # 1. Command the coordinator to orchestrate the deletion of the file everywhere
        print(f"Sending delete request to coordinator for: {filename}")
        response = requests.post(f"{COORDINATOR_URL}/delete-file", json={'filename': filename})
        response.raise_for_status() # This will raise an error if the coordinator fails

        # 2. If the coordinator succeeds, remove the file from the client's local hash cache as well
        local_hashes = read_local_hashes()
        if filename in local_hashes:
            del local_hashes[filename]
            write_local_hashes(local_hashes)
            print(f"Removed '{filename}' from local hash cache.")
        
        flash(f"Successfully deleted the backup for '{filename}'.", "success")

    except requests.exceptions.RequestException as e:
        flash(f"Error communicating with coordinator during deletion: {e}", "error")
        print(f"Error during deletion of {filename}: {e}")

    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)