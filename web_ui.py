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
from cryptography.exceptions import InvalidKey # [FIXED] Using the correct exception for decryption

app = Flask(__name__)
app.secret_key = os.urandom(24) 

# --- Configuration ---
COORDINATOR_URL = "http://127.0.0.1:5002"
BACKUP_FOLDER = 'files_to_backup'
CLIENT_HASH_DB = 'client_local_hashes.json'
SALT = b'pdc-project-salt'
CHUNK_THRESHOLD = 30 * 1024 * 1024
CHUNK_SIZE = 4 * 1024 * 1024

# --- Helper Functions ---
def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=SALT, iterations=480000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def read_local_hashes():
    if not os.path.exists(CLIENT_HASH_DB) or os.path.getsize(CLIENT_HASH_DB) == 0:
        return {}
    with open(CLIENT_HASH_DB, 'r') as f:
        return json.load(f)

def write_local_hashes(hashes):
    with open(CLIENT_HASH_DB, 'w') as f:
        json.dump(hashes, f, indent=4)

# --- Reusable Core Logic ---
def backup_single_file(filepath, filename, encrypt_file, password):
    try:
        file_size = os.path.getsize(filepath)
        response = requests.get(f"{COORDINATOR_URL}/get-storage-nodes")
        response.raise_for_status()
        storage_node_urls = response.json()['storage_node_urls']
        fernet = Fernet(derive_key(password)) if encrypt_file and password else None
        log_data = {'filename': filename, 'locations': storage_node_urls, 'encrypted': encrypt_file}

        if file_size < CHUNK_THRESHOLD:
            with open(filepath, 'rb') as f:
                file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
            data_to_upload = fernet.encrypt(file_data) if fernet else file_data
            for node_url in storage_node_urls:
                requests.post(f"{node_url}/store/{file_hash}", data=data_to_upload).raise_for_status()
            log_data.update({'is_chunked': False, 'hash': file_hash})
        else:
            chunk_hashes = []
            with open(filepath, 'rb') as f:
                while True:
                    chunk_data = f.read(CHUNK_SIZE)
                    if not chunk_data: break
                    chunk_hash = hashlib.sha256(chunk_data).hexdigest()
                    chunk_hashes.append(chunk_hash)
                    data_to_upload = fernet.encrypt(chunk_data) if fernet else chunk_data
                    for node_url in storage_node_urls:
                        requests.post(f"{node_url}/store/{chunk_hash}", data=data_to_upload).raise_for_status()
            log_data.update({'is_chunked': True, 'chunk_hashes': chunk_hashes})

        requests.post(f"{COORDINATOR_URL}/log-backup", json=log_data).raise_for_status()
        print(f"Successfully backed up '{filename}'")
        return True
    except Exception as e:
        print(f"An error occurred during backup of {filename}: {e}")
        return False

# --- [NEW] The missing delete helper function ---
def delete_single_file(filename):
    """Handles the logic for deleting a file from the entire system."""
    try:
        print(f"Sending delete request to coordinator for: {filename}")
        response = requests.post(f"{COORDINATOR_URL}/delete-file", json={'filename': filename})
        response.raise_for_status()
        local_hashes = read_local_hashes()
        if filename in local_hashes:
            del local_hashes[filename]
            write_local_hashes(local_hashes)
            print(f"Removed '{filename}' from local hash cache.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error during deletion of {filename}: {e}")
        return False

# --- Flask Routes ---

@app.route('/')
def index():
    files = []
    try:
        response = requests.get(f"{COORDINATOR_URL}/list-files")
        response.raise_for_status()
        files = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Could not reach coordinator to list files: {e}")
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files or not request.files['file'].filename:
        flash("No file selected.", "error")
        return redirect(url_for('index'))
    file = request.files['file']
    filename = file.filename
    temp_filepath = os.path.join("temp_uploads", filename)
    os.makedirs("temp_uploads", exist_ok=True)
    file.save(temp_filepath)
    password = request.form.get('password', '')
    encryption_enabled = 'encrypt' in request.form
    if encryption_enabled and not password:
        flash("Encryption selected, but no password provided.", "error")
        os.remove(temp_filepath)
        return redirect(url_for('index'))
    if backup_single_file(temp_filepath, filename, encryption_enabled, password):
        with open(temp_filepath, 'rb') as f:
            local_hashes = read_local_hashes()
            local_hashes[filename] = hashlib.sha256(f.read()).hexdigest()
            write_local_hashes(local_hashes)
        flash(f"'{filename}' uploaded successfully!", "success")
    else:
        flash(f"Failed to upload '{filename}'.", "error")
    os.remove(temp_filepath)
    return redirect(url_for('index'))

@app.route('/sync', methods=['POST'])
def sync_folder():
    encryption_enabled = 'encrypt' in request.form
    password = request.form.get('password', '')
    if encryption_enabled and not password:
        flash("Encryption was selected, but no password was provided.", "error")
        return redirect(url_for('index'))
    if not os.path.exists(BACKUP_FOLDER):
        os.makedirs(BACKUP_FOLDER)
    local_hashes = read_local_hashes()
    for filename in os.listdir(BACKUP_FOLDER):
        filepath = os.path.join(BACKUP_FOLDER, filename)
        if not os.path.isfile(filepath): continue
        with open(filepath, 'rb') as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
        if local_hashes.get(filename) == current_hash:
            continue
        if backup_single_file(filepath, filename, encryption_enabled, password):
             local_hashes[filename] = current_hash
        else:
            print(f"Failed to backup '{filename}'. Will retry on next sync.")
    write_local_hashes(local_hashes)
    flash("Synchronization process completed.", "success")
    return redirect(url_for('index'))

@app.route('/restore/<filename>')
def restore_file(filename):
    try:
        response = requests.get(f"{COORDINATOR_URL}/get-file-info/{filename}")
        response.raise_for_status()
        file_info = response.json()
        password = request.args.get('password', '')
        if file_info.get('encrypted') and not password:
            flash("File is encrypted, but no password was provided for restore.", "error")
            return redirect(url_for('index'))
    except requests.exceptions.RequestException as e:
        flash(f"Could not get file info from coordinator: {e}", "error")
        return redirect(url_for('index'))
    
    locations = file_info['locations']
    is_encrypted = file_info.get('encrypted', False)
    fernet = Fernet(derive_key(password)) if is_encrypted else None
    temp_dir = "temp_uploads"
    os.makedirs(temp_dir, exist_ok=True)
    temp_restore_path = os.path.join(temp_dir, filename)

    try:
        with open(temp_restore_path, 'wb') as output_file:
            if not file_info.get('is_chunked'):
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

        @after_this_request
        def cleanup(response):
            try:
                os.remove(temp_restore_path)
                print(f"Cleaned up temporary file: {temp_restore_path}")
            except Exception as error:
                app.logger.error("Error removing temporary file: %s", error)
            return response

        return send_file(temp_restore_path, as_attachment=True, download_name=filename)
    
    except Exception as e:
        flash(f"An error occurred during restore: {e}", "error")
        if os.path.exists(temp_restore_path):
            os.remove(temp_restore_path)
        return redirect(url_for('index'))

@app.route('/delete/<filename>', methods=['POST'])
def delete_backup(filename):
    """Route to initiate deletion from the UI."""
    if delete_single_file(filename):
        flash(f"Successfully deleted the backup for '{filename}'.", "success")
    else:
        flash(f"An error occurred during deletion of '{filename}'.", "error")
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Since the background watcher is removed, running in debug mode is fine.
    app.run(host='0.0.0.0', port=5000, debug=True)