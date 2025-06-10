import os
import json
import requests
import hashlib
import io
import base64
from flask import Flask, request, render_template, redirect, url_for, send_file, flash, after_this_request
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
CHUNK_THRESHOLD = 30 * 1024 * 1024  # 30 MB
CHUNK_SIZE = 4 * 1024 * 1024       # 4 MB

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
def backup_single_file(filepath, filename, encrypt_file, password):
    """
    Handles the backup process. Uses chunking for files larger than CHUNK_THRESHOLD.
    """
    try:
        file_size = os.path.getsize(filepath)
        
        # 1. Ask Coordinator for storage nodes first
        response = requests.get(f"{COORDINATOR_URL}/get-storage-nodes")
        response.raise_for_status()
        storage_node_urls = response.json()['storage_node_urls']

        # Determine if encryption will be used
        fernet = Fernet(derive_key(password)) if encrypt_file and password else None
        
        log_data = {
            'filename': filename,
            'locations': storage_node_urls,
            'encrypted': encrypt_file
        }

        # --- LOGIC FOR SMALL FILES ---
        if file_size < CHUNK_THRESHOLD:
            print(f"'{filename}' is a small file. Processing as a single block.")
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            file_hash = hashlib.sha256(file_data).hexdigest()
            data_to_upload = fernet.encrypt(file_data) if fernet else file_data
            
            for node_url in storage_node_urls:
                requests.post(f"{node_url}/store/{file_hash}", data=data_to_upload).raise_for_status()

            log_data.update({'is_chunked': False, 'hash': file_hash})

        # --- LOGIC FOR LARGE FILES (CHUNKING) ---
        else:
            print(f"'{filename}' is a large file. Starting chunking process...")
            chunk_hashes = []
            with open(filepath, 'rb') as f:
                while True:
                    chunk_data = f.read(CHUNK_SIZE)
                    if not chunk_data:
                        break # End of file
                    
                    chunk_hash = hashlib.sha256(chunk_data).hexdigest()
                    chunk_hashes.append(chunk_hash)
                    
                    data_to_upload = fernet.encrypt(chunk_data) if fernet else chunk_data
                    
                    print(f"  Uploading chunk {len(chunk_hashes)} ({len(data_to_upload)} bytes) with hash {chunk_hash[:8]}...")
                    for node_url in storage_node_urls:
                        requests.post(f"{node_url}/store/{chunk_hash}", data=data_to_upload).raise_for_status()
            
            log_data.update({'is_chunked': True, 'chunk_hashes': chunk_hashes})

        # Log the final metadata with the coordinator
        requests.post(f"{COORDINATOR_URL}/log-backup", json=log_data).raise_for_status()
        print(f"Successfully backed up '{filename}'")
        return True
    
    except Exception as e:
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
    if 'file' not in request.files or not request.files['file'].filename:
        flash("No file selected.", "error")
        return redirect(url_for('index'))
        
    file = request.files['file']
    filename = file.filename
    # We must save the uploaded file temporarily to get a filepath for chunking
    temp_filepath = os.path.join("temp_uploads", filename)
    os.makedirs("temp_uploads", exist_ok=True)
    file.save(temp_filepath)

    password = request.form.get('password', '')
    encryption_enabled = 'encrypt' in request.form
    if encryption_enabled and not password:
        flash("Encryption selected, but no password provided.", "error")
        os.remove(temp_filepath) # Clean up temp file
        return redirect(url_for('index'))

    # Call the backup function with the filepath
    if backup_single_file(temp_filepath, filename, encryption_enabled, password):
        # Update local hash cache using the temp file
        with open(temp_filepath, 'rb') as f:
            local_hashes = read_local_hashes()
            local_hashes[filename] = hashlib.sha256(f.read()).hexdigest()
            write_local_hashes(local_hashes)
        flash(f"'{filename}' uploaded successfully!", "success")
    else:
        flash(f"Failed to upload '{filename}'.", "error")

    os.remove(temp_filepath) # Clean up the temporary file
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
    """Handles restoring both single-block and chunked files with proper cleanup."""
    try:
        response = requests.get(f"{COORDINATOR_URL}/get-file-info/{filename}")
        response.raise_for_status()
        file_info = response.json()
        password = request.args.get('password', '')
        if file_info.get('encrypted') and not password:
            flash("File is encrypted, but no password was provided.", "error")
            return redirect(url_for('index'))
    except requests.exceptions.RequestException as e:
        flash(f"Could not get file info from coordinator: {e}", "error")
        return redirect(url_for('index'))

    locations = file_info['locations']
    is_encrypted = file_info.get('encrypted', False)
    fernet = Fernet(derive_key(password)) if is_encrypted else None

    # Create a temporary file for reassembly
    temp_dir = "temp_uploads"
    os.makedirs(temp_dir, exist_ok=True)
    temp_restore_path = os.path.join(temp_dir, filename)

    try:
        with open(temp_restore_path, 'wb') as output_file:
            if not file_info.get('is_chunked'):
                # --- SINGLE FILE RESTORE ---
                file_hash = file_info['hash']
                downloaded_data = None
                for node_url in locations:
                    try:
                        response = requests.get(f"{node_url}/retrieve/{file_hash}", timeout=5)
                        response.raise_for_status()
                        downloaded_data = response.content
                        break
                    except requests.exceptions.RequestException:
                        continue
                if downloaded_data is None: raise Exception("All replicas failed.")
                decrypted_data = fernet.decrypt(downloaded_data) if fernet else downloaded_data
                output_file.write(decrypted_data)
            else:
                # --- CHUNKED FILE RESTORE ---
                for i, chunk_hash in enumerate(file_info['chunk_hashes']):
                    chunk_data = None
                    for node_url in locations:
                        try:
                            response = requests.get(f"{node_url}/retrieve/{chunk_hash}", timeout=5)
                            response.raise_for_status()
                            chunk_data = response.content
                            break
                        except requests.exceptions.RequestException:
                            continue
                    if chunk_data is None: raise Exception(f"Failed to download chunk {i+1}.")
                    decrypted_chunk = fernet.decrypt(chunk_data) if fernet else chunk_data
                    output_file.write(decrypted_chunk)

        # This registers a function to be called AFTER the main response is sent.
        @after_this_request
        def cleanup(response):
            try:
                os.remove(temp_restore_path)
                print(f"Cleaned up temporary file: {temp_restore_path}")
            except Exception as error:
                app.logger.error("Error removing or closing downloaded file handle: %s", error)
            return response

        # Now, send the fully reassembled file from disk
        return send_file(temp_restore_path, as_attachment=True, download_name=filename)
    
    except Exception as e:
        flash(f"An error occurred during restore: {e}", "error")
        # Clean up the partial file if an error occurred during assembly
        if os.path.exists(temp_restore_path):
            os.remove(temp_restore_path)
        return redirect(url_for('index'))

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