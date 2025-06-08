# restore_client.py
import sys
import requests
import hashlib
from cryptography.fernet import Fernet

STORAGE_NODE_URL = "http://127.0.0.1:5001"
# --- PASTE THE SAME KEY YOU GENERATED HERE ---
ENCRYPTION_KEY = b'fBNnPtgoyrcbKzhtIwB2ThfWoCmBdopq8m9ty2EWyko='


def restore_file(file_hash, output_path):
    """
    Retrieves, decrypts, and verifies a file from the storage node.
    """
    # 1. Retrieve the encrypted file from the storage node 
    try:
        url = f"{STORAGE_NODE_URL}/retrieve/{file_hash}"
        response = requests.get(url)
        response.raise_for_status()
        encrypted_data = response.content
        print("Encrypted file downloaded successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading file: {e}")
        return

    # 2. Decrypt the file using the local key 
    fernet = Fernet(ENCRYPTION_KEY)
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        print("File decrypted successfully.")
    except Exception as e:
        print(f"Decryption failed: {e}")
        return

    # 3. Verify the hash of the decrypted content
    restored_hash = hashlib.sha256(decrypted_data).hexdigest()
    if restored_hash == file_hash:
        print("Success! File integrity verified.")
        # 4. Save the restored file
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        print(f"File restored successfully to '{output_path}'")
    else:
        print("Error: File integrity check failed. The file may be corrupt.")
        print(f"Expected hash: {file_hash}")
        print(f"Actual hash:   {restored_hash}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python restore_client.py <file_hash> <output_filename>")
        sys.exit(1)
    
    hash_to_restore = sys.argv[1]
    output_file_path = sys.argv[2]
    restore_file(hash_to_restore, output_file_path)