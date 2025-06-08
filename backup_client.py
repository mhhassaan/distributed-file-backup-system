# backup_client.py
import sys
import requests
import hashlib
from cryptography.fernet import Fernet
import os

STORAGE_NODE_URL = "http://127.0.0.1:5001"
# --- PASTE THE KEY YOU GENERATED HERE ---
# The encryption key is stored on the client 
ENCRYPTION_KEY = b'fBNnPtgoyrcbKzhtIwB2ThfWoCmBdopq8m9ty2EWyko='

def backup_file(file_path):
    """
    Hashes, encrypts, and sends a file to the storage node.
    """
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return

    # 1. Read the file content
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # 2. Hash the original file content using SHA-256 
    file_hash = hashlib.sha256(file_data).hexdigest()
    print(f"File hash: {file_hash}")

    # 3. Encrypt the file on the client before sending it 
    # We use AES as specified in the proposal 
    fernet = Fernet(ENCRYPTION_KEY)
    encrypted_data = fernet.encrypt(file_data)
    print("File encrypted successfully.")

    # 4. Send the encrypted file to the storage node 
    try:
        url = f"{STORAGE_NODE_URL}/store/{file_hash}"
        response = requests.post(url, data=encrypted_data, headers={'Content-Type': 'application/octet-stream'})
        response.raise_for_status() # Raise an exception for bad status codes
        print("File uploaded successfully to storage node.")
        print(response.json())
    except requests.exceptions.RequestException as e:
        print(f"Error uploading file: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python backup_client.py <path_to_file>")
        sys.exit(1)
    
    file_to_backup = sys.argv[1]
    backup_file(file_to_backup)