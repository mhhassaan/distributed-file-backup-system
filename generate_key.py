from cryptography.fernet import Fernet
key = Fernet.generate_key()
print("Your AES encryption key (keep this safe!):")
print(key.decode())