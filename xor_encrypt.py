import os
import sys
from datetime import datetime
import struct
import hashlib

def generate_base_key(size=32):
    """Generate a fixed-size random base key (default 32 bytes/256 bits)."""
    return os.urandom(size)

def expand_key(base_key, needed_size):
    """Expand the base key to the needed size using a secure hash function."""
    expanded = []
    current_hash = base_key
    
    while len(expanded) < needed_size:
        current_hash = hashlib.sha256(current_hash).digest()
        expanded.extend(current_hash)
    
    return bytes(expanded[:needed_size])

def xor_encrypt(data, key):
    """XOR each byte of data with the corresponding byte of the expanded key."""
    return bytes(a ^ b for a, b in zip(data, key))

def main():
    if len(sys.argv) != 2:
        print("Usage: python xor_encrypt.py <input_file>")
        return

    input_file = sys.argv[1]
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found.")
        return

    try:
        # Get the file extension
        file_extension = os.path.splitext(input_file)[1]
        # Convert extension to bytes and get its length
        ext_bytes = file_extension.encode('utf-8')
        ext_length = len(ext_bytes)

        # Read the input file in binary mode
        with open(input_file, 'rb') as f:
            data = f.read()

        # Generate base key (32 bytes)
        base_key = generate_base_key()
        
        # Calculate total size needed for encryption
        total_size = len(data) + ext_length + 4  # +4 for storing extension length
        
        # Expand the key to match the needed size
        expanded_key = expand_key(base_key, total_size)

        # Prepare the data with extension information
        full_data = struct.pack('<I', ext_length) + ext_bytes + data
        
        # Perform XOR encryption
        encrypted_data = xor_encrypt(full_data, expanded_key)

        # Generate output filename based on timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        encrypted_file = f"encrypted_{timestamp}.bin"
        key_file = f"key_{timestamp}.bin"

        # Save encrypted data
        with open(encrypted_file, 'wb') as f:
            f.write(encrypted_data)

        # Save the base key (only 32 bytes)
        with open(key_file, 'wb') as f:
            f.write(base_key)

        print(f"Encryption successful!")
        print(f"Encrypted file saved as: {encrypted_file}")
        print(f"Key file saved as: {key_file} (32 bytes)")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
