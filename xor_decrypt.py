import os
import sys
from datetime import datetime
import struct
import hashlib

def expand_key(base_key, needed_size):
    """Expand the base key to the needed size using a secure hash function."""
    expanded = []
    current_hash = base_key
    
    while len(expanded) < needed_size:
        current_hash = hashlib.sha256(current_hash).digest()
        expanded.extend(current_hash)
    
    return bytes(expanded[:needed_size])

def xor_decrypt(encrypted_data, key):
    """XOR each byte of encrypted data with the corresponding byte of the expanded key."""
    return bytes(a ^ b for a, b in zip(encrypted_data, key))

def main():
    if len(sys.argv) != 3:
        print("Usage: python xor_decrypt.py <encrypted_file> <key_file>")
        return

    encrypted_file = sys.argv[1]
    key_file = sys.argv[2]

    # Check if both files exist
    if not os.path.exists(encrypted_file):
        print(f"Error: Encrypted file '{encrypted_file}' not found.")
        return
    if not os.path.exists(key_file):
        print(f"Error: Key file '{key_file}' not found.")
        return

    try:
        # Read the encrypted file
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()

        # Read the base key file (32 bytes)
        with open(key_file, 'rb') as f:
            base_key = f.read()

        # Expand the key to match the encrypted data size
        expanded_key = expand_key(base_key, len(encrypted_data))

        # Perform XOR decryption
        decrypted_data = xor_decrypt(encrypted_data, expanded_key)

        # Extract file extension information
        # First 4 bytes contain the length of the extension
        ext_length = struct.unpack('<I', decrypted_data[:4])[0]
        
        # Next ext_length bytes contain the extension
        extension = decrypted_data[4:4+ext_length].decode('utf-8')
        
        # The rest is the actual file data
        file_data = decrypted_data[4+ext_length:]

        # Generate output filename with original extension
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        decrypted_file = f"decrypted_{timestamp}{extension}"

        # Save decrypted data
        with open(decrypted_file, 'wb') as f:
            f.write(file_data)

        print(f"Decryption successful!")
        print(f"Decrypted file saved as: {decrypted_file}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
