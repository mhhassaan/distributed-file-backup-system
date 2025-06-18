import os
import json
import requests
import hashlib
import io
import base64
import threading
import time
from flask import Flask, request, render_template, redirect, url_for, send_file, flash, after_this_request
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Configuration ---
REPLICATION_FACTOR = 2
COORDINATOR_URL = "http://127.0.0.1:5002"
CLIENT_HASH_DB = 'client_local_hashes.json'
WATCHED_FOLDERS_DB = 'watched_folders.json'
SALT = b'pdc-project-salt'
CHUNK_THRESHOLD = 12 * 1024 * 1024 #12MB
CHUNK_SIZE = 4 * 1024 * 1024  #4MB


# --- All Helper and Core Logic Functions ---
# (derive_key, read/write_local_hashes, read/write_watched_folders, 
# backup_single_file, delete_single_file, AutoSyncHandler, start_watcher).

def derive_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=SALT, iterations=480000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))
def read_local_hashes():
    if not os.path.exists(CLIENT_HASH_DB) or os.path.getsize(CLIENT_HASH_DB) == 0: return {}
    with open(CLIENT_HASH_DB, 'r') as f: return json.load(f)
def write_local_hashes(hashes):
    with open(CLIENT_HASH_DB, 'w') as f: json.dump(hashes, f, indent=4)
def read_watched_folders():
    if not os.path.exists(WATCHED_FOLDERS_DB): return []
    try:
        with open(WATCHED_FOLDERS_DB, 'r') as f: return json.load(f)
    except json.JSONDecodeError: return []
def write_watched_folders(folders):
    with open(WATCHED_FOLDERS_DB, 'w') as f: json.dump(folders, f, indent=4)

def backup_single_file(filepath, filename, encrypt_file, password, source_info={}):
    """
    Handles backup for any file.
    - Uses full replication for small files.
    - Uses striped replication for large (chunked) files.
    """
    try:
        file_size = os.path.getsize(filepath)
        
        response = requests.get(f"{COORDINATOR_URL}/get-storage-nodes")
        response.raise_for_status()
        all_nodes = response.json()['storage_node_urls']

        fernet = Fernet(derive_key(password)) if encrypt_file and password else None
        
        base_log_data = {'filename': filename, 'encrypted': encrypt_file}
        base_log_data.update(source_info)

        # --- LOGIC FOR SMALL FILES ---
        if file_size < CHUNK_THRESHOLD:
            if len(all_nodes) < REPLICATION_FACTOR:
                raise Exception(f"Not enough active nodes ({len(all_nodes)}) to meet replication factor ({REPLICATION_FACTOR}).")
            
            with open(filepath, 'rb') as f: file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
            data_to_upload = fernet.encrypt(file_data) if fernet else file_data
            
            replica_nodes = all_nodes[:REPLICATION_FACTOR]
            for node_url in replica_nodes:
                requests.post(f"{node_url}/store/{file_hash}", data=data_to_upload).raise_for_status()

            final_log = {**base_log_data, 'is_chunked': False, 'hash': file_hash, 'locations': replica_nodes}

        # --- LOGIC FOR LARGE FILES (Striped Replication) ---
        else:
            print(f"'{filename}' is a large file. Starting striped replication...")
            
            num_groups = len(all_nodes) // REPLICATION_FACTOR
            if num_groups == 0:
                raise Exception(f"Not enough active nodes ({len(all_nodes)}) to meet replication factor ({REPLICATION_FACTOR}).")
            
            node_groups = [all_nodes[i:i + REPLICATION_FACTOR] for i in range(0, num_groups * REPLICATION_FACTOR, REPLICATION_FACTOR)]

            chunk_map = {}
            chunk_order = []
            
            with open(filepath, 'rb') as f:
                chunk_index = 0
                while True:
                    chunk_data = f.read(CHUNK_SIZE)
                    if not chunk_data: break
                    chunk_hash = hashlib.sha256(chunk_data).hexdigest()
                    chunk_order.append(chunk_hash)
                    target_group = node_groups[chunk_index % num_groups]
                    data_to_upload = fernet.encrypt(chunk_data) if fernet else chunk_data
                    
                    for node_url in target_group:
                        requests.post(f"{node_url}/store/{chunk_hash}", data=data_to_upload).raise_for_status()
                    
                    chunk_map[chunk_hash] = target_group
                    chunk_index += 1
            
            # [FIX] The 'locations' key was missing here. We add a list of all participating nodes.
            final_log = {**base_log_data, 'is_chunked': True, 'chunk_order': chunk_order, 'chunk_map': chunk_map, 'locations': all_nodes}

        # Log the final, detailed metadata with the coordinator
        requests.post(f"{COORDINATOR_URL}/log-backup", json=final_log).raise_for_status()
        print(f"Successfully backed up '{filename}'")
        return True
        
    except Exception as e:
        print(f"An error occurred during backup of {filename}: {e}")
        return False
    
def delete_single_file(filename):
    """Handles the logic for deleting a file from the entire system."""
    print("\n--- [DELETE PROCESS] Starting delete_single_file function ---")
    try:
        url = f"{COORDINATOR_URL}/delete-file"
        print(f"[*] Contacting coordinator to delete '{filename}' at URL: {url}")
        
        response = requests.post(url, json={'filename': filename}, timeout=10)
        
        print(f"[*] Coordinator responded with status code: {response.status_code}")
        response.raise_for_status() # This will raise an error if status is not 2xx

        print(f"[*] Coordinator reported success. Updating local hash cache...")
        local_hashes = read_local_hashes()
        if filename in local_hashes:
            del local_hashes[filename]
            write_local_hashes(local_hashes)
            print(f"[*] Removed '{filename}' from local hash cache.")
        
        print("--- [DELETE PROCESS] Finished successfully. ---")
        return True

    except requests.exceptions.RequestException as e:
        print(f"[!] ERROR during deletion of {filename}: {e}")
        print("--- [DELETE PROCESS] Finished with an error. ---")
        return False
class AutoSyncHandler(FileSystemEventHandler):
    def get_folder_config(self, filepath):
        watched_folders = read_watched_folders()
        for folder_config in watched_folders:
            try:
                if os.path.normcase(os.path.abspath(filepath)).startswith(os.path.normcase(os.path.abspath(folder_config['path']))):
                    return folder_config
            except FileNotFoundError: continue
        return None
    def process(self, event, action_type):
        if event.is_directory: return
        filepath = event.src_path.replace('\0', '')
        filename = os.path.basename(filepath)
        config = self.get_folder_config(filepath)
        if not config: return
        print(f"\n[Watcher] Detected {action_type} for: {filename} in '{config['path']}'")
        if action_type == 'delete':
            delete_single_file(filename)
        else:
            try:
                time.sleep(1) 
                with open(filepath, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                local_hashes = read_local_hashes()
                if local_hashes.get(filename) == current_hash: return
                source_info = {'source_type': 'sync', 'source_path': config['path']}
                if backup_single_file(filepath, filename, config['encrypt'], config.get('password', ''), source_info):
                    local_hashes[filename] = current_hash
                    write_local_hashes(local_hashes)
            except Exception as e: print(f"[Watcher] Error processing {filepath}: {e}")
    def on_created(self, event): self.process(event, 'creation')
    def on_modified(self, event): self.process(event, 'modification')
    def on_deleted(self, event): self.process(event, 'delete')

def start_watcher():
    observer = Observer()
    watched_folders = read_watched_folders()
    if not watched_folders: print("--- No folders to watch. Watcher is idle. ---")
    else:
        for folder in watched_folders:
            if os.path.isdir(folder['path']):
                observer.schedule(AutoSyncHandler(), folder['path'], recursive=True)
                print(f"--- Watching folder: '{folder['path']}' ---")
    observer.start()
    try:
        while True: time.sleep(3600)
    except KeyboardInterrupt: observer.stop()
    observer.join()


# --- Flask Routes ---

@app.route('/')
def index():
    """Renders the main page, now with categorized file lists."""
    files = []
    try:
        response = requests.get(f"{COORDINATOR_URL}/list-files")
        response.raise_for_status()
        files = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Could not reach coordinator to list files: {e}")
    
    watched_folders = read_watched_folders()
    single_files, synced_folders = [], {}
    for file_info in files:
        if file_info.get('source_type') == 'sync':
            path = file_info.get('source_path', 'Unknown Synced Folder')
            if path not in synced_folders:
                synced_folders[path] = []
            synced_folders[path].append(file_info)
        else:
            single_files.append(file_info)
            
    # [FIX #1] Pass the CORRECT categorized variables to the template
    return render_template('index.html', single_files=single_files, synced_folders=synced_folders, watched_folders=watched_folders)

# [FIX #2] ADD THE MISSING /force-sync ROUTE
@app.route('/force-sync', methods=['POST'])
def force_sync():
    """Manually triggers a sync of all watched folders."""
    print("\n--- MANUAL SYNC TRIGGERED ---")
    watched_folders = read_watched_folders()
    if not watched_folders:
        flash("No folders are being watched to sync.", "warning")
        return redirect(url_for('index'))

    for folder_config in watched_folders:
        folder_path = folder_config['path']
        if not os.path.isdir(folder_path): continue
        
        local_hashes = read_local_hashes()
        for filename in os.listdir(folder_path):
            filepath = os.path.join(folder_path, filename)
            if not os.path.isfile(filepath): continue
            
            try:
                with open(filepath, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                
                if local_hashes.get(filename) == current_hash:
                    continue
                
                source_info = {'source_type': 'sync', 'source_path': folder_path}
                if backup_single_file(filepath, filename, folder_config['encrypt'], folder_config.get('password', ''), source_info):
                    local_hashes[filename] = current_hash
                    write_local_hashes(local_hashes)
            except Exception as e:
                print(f"Error processing {filepath} during manual sync: {e}")

    flash("Manual synchronization of all watched folders is complete.", "success")
    return redirect(url_for('index'))

@app.route('/add-folder', methods=['POST'])
def add_folder():
    folder_path, password, encryption_enabled = request.form.get('folder_path'), request.form.get('password', ''), 'encrypt' in request.form
    if not folder_path or not os.path.isdir(folder_path):
        flash("Invalid folder path provided.", "error")
    elif encryption_enabled and not password:
        flash("Encryption selected, but no password was provided.", "error")
    else:
        watched_folders = read_watched_folders()
        if not any(os.path.exists(f['path']) and os.path.samefile(f['path'], folder_path) for f in watched_folders):
            watched_folders.append({"path": folder_path, "encrypt": encryption_enabled, "password": password})
            write_watched_folders(watched_folders)
            flash("Folder added. Please RESTART the server for the new watcher to take effect.", "success")
        else:
            flash("This folder is already being watched.", "warning")
    return redirect(url_for('index'))

@app.route('/remove-folder', methods=['POST'])
def remove_folder():
    folder_path_to_remove = request.form.get('folder_path')
    watched_folders = read_watched_folders()
    updated_folders = [f for f in watched_folders if not (os.path.exists(f['path']) and os.path.samefile(f['path'], folder_path_to_remove))]
    if len(updated_folders) < len(watched_folders):
        write_watched_folders(updated_folders)
        flash("Folder removed. Please RESTART the server for this change to take effect.", "success")
    else:
        flash("Folder not found in watchlist.", "warning")
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files or not request.files['file'].filename:
        flash("No file selected.", "error")
        return redirect(url_for('index'))
    file, filename = request.files['file'], request.files['file'].filename
    temp_filepath = os.path.join("temp_uploads", filename); os.makedirs("temp_uploads", exist_ok=True); file.save(temp_filepath)
    password, encryption_enabled = request.form.get('password', ''), 'encrypt' in request.form
    if encryption_enabled and not password:
        flash("Encryption selected, but no password provided.", "error")
        os.remove(temp_filepath)
        return redirect(url_for('index'))
    source_info = {'source_type': 'single'}
    if backup_single_file(temp_filepath, filename, encryption_enabled, password, source_info):
        with open(temp_filepath, 'rb') as f:
            local_hashes = read_local_hashes()
            local_hashes[filename] = hashlib.sha256(f.read()).hexdigest()
            write_local_hashes(local_hashes)
        flash(f"'{filename}' uploaded successfully!", "success")
    else:
        flash(f"Failed to upload '{filename}'.", "error")
    os.remove(temp_filepath)
    return redirect(url_for('index'))

@app.route('/restore/<filename>')
def restore_file(filename):
    """Handles restoring both single-block and chunked/striped files."""
    try:
        response = requests.get(f"{COORDINATOR_URL}/get-file-info/{filename}"); response.raise_for_status()
        file_info = response.json(); password = request.args.get('password', '')
        if file_info.get('encrypted') and not password:
            flash("File is encrypted, but no password was provided.", "error")
            return redirect(url_for('index'))
    except requests.exceptions.RequestException as e:
        flash(f"Could not get file info from coordinator: {e}", "error")
        return redirect(url_for('index'))

    is_encrypted = file_info.get('encrypted', False)
    fernet = Fernet(derive_key(password)) if is_encrypted else None
    temp_dir = "temp_uploads"; os.makedirs(temp_dir, exist_ok=True); temp_restore_path = os.path.join(temp_dir, filename)

    try:
        with open(temp_restore_path, 'wb') as output_file:
            if not file_info.get('is_chunked'):
                # --- SINGLE FILE RESTORE ---
                file_hash = file_info['hash']
                locations = file_info['locations']
                downloaded_data = None
                for node_url in locations:
                    # ... (fault-tolerant download logic) ...
                    if downloaded_data is None: raise Exception("All replicas failed.")
                decrypted_data = fernet.decrypt(downloaded_data) if fernet else downloaded_data
                output_file.write(decrypted_data)
            else:
                # --- CHUNKED/STRIPED FILE RESTORE ---
                print(f"Restoring striped file: {filename}")
                chunk_map = file_info['chunk_map']
                for i, chunk_hash in enumerate(file_info['chunk_order']):
                    # 1. For each chunk, find its specific locations from the map
                    chunk_locations = chunk_map.get(chunk_hash)
                    if not chunk_locations: raise Exception(f"Locations for chunk {i+1} not found in metadata.")
                    
                    print(f"  Downloading chunk {i+1} from {chunk_locations}...")
                    chunk_data = None
                    # 2. Fault-tolerant download from its specific replica set
                    for node_url in chunk_locations:
                        try:
                            response = requests.get(f"{node_url}/retrieve/{chunk_hash}", timeout=5); response.raise_for_status()
                            chunk_data = response.content; break
                        except requests.exceptions.RequestException: continue
                    if chunk_data is None: raise Exception(f"Failed to download chunk {i+1} from all locations.")
                    
                    decrypted_chunk = fernet.decrypt(chunk_data) if fernet else chunk_data
                    output_file.write(decrypted_chunk)

        @after_this_request
        def cleanup(response):
            try: os.remove(temp_restore_path)
            except Exception as error: app.logger.error("Error removing temp file: %s", error)
            return response
        return send_file(temp_restore_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        flash(f"An error occurred during restore: {e}", "error")
        if os.path.exists(temp_restore_path): os.remove(temp_restore_path)
        return redirect(url_for('index'))

@app.route('/delete/<filename>', methods=['POST'])
def delete_backup(filename):
    """Route to initiate deletion from the UI."""
    print(f"\n--- [DELETE ROUTE] Received delete request for '{filename}' from UI ---")
    if delete_single_file(filename):
        flash(f"Successfully deleted the backup for '{filename}'.", "success")
    else:
        flash(f"An error occurred during deletion of '{filename}'.", "error")
    return redirect(url_for('index'))

if __name__ == '__main__':
    watcher_thread = threading.Thread(target=start_watcher, daemon=True)
    watcher_thread.start()
    app.run(host='0.0.0.0', port=5000, debug=False)