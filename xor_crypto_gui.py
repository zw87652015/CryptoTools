import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from ttkthemes import ThemedTk
import os
import hashlib
import struct
from datetime import datetime

class XORCryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("XOR Crypto Tool")
        self.root.geometry("600x450")
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure('TButton', padding=5)
        self.style.configure('TFrame', padding=10)
        self.style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'))
        self.style.configure('TNotebook.Tab', padding=(10, 4))
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header
        header_label = ttk.Label(
            main_frame, 
            text="XOR Encryption/Decryption Tool",
            style='Header.TLabel'
        )
        header_label.pack(pady=(0, 20))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create encryption tab
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_frame, text='Encryption')
        
        # Create decryption tab
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_frame, text='Decryption')
        
        # Setup encryption tab
        self.setup_encrypt_tab()
        
        # Setup decryption tab
        self.setup_decrypt_tab()
        
        # Status frame (shared between tabs)
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding=10)
        status_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        self.status_text = tk.Text(status_frame, height=8, wrap=tk.WORD)
        self.status_text.pack(fill=tk.BOTH, expand=True)
        
    def setup_encrypt_tab(self):
        # File selection frame for encryption
        file_frame = ttk.LabelFrame(self.encrypt_frame, text="Select File to Encrypt", padding=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Input file selection for encryption
        input_frame = ttk.Frame(file_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        self.encrypt_input_path = tk.StringVar()
        ttk.Label(input_frame, text="Input File:").pack(side=tk.LEFT)
        ttk.Entry(input_frame, textvariable=self.encrypt_input_path).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(input_frame, text="Browse", command=self.browse_encrypt_input).pack(side=tk.LEFT)
        
        # Encrypt button
        ttk.Button(self.encrypt_frame, text="Encrypt File", command=self.encrypt).pack(pady=20)
        
    def setup_decrypt_tab(self):
        # File selection frame for decryption
        file_frame = ttk.LabelFrame(self.decrypt_frame, text="Select Files to Decrypt", padding=10)
        file_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Input encrypted file selection
        input_frame = ttk.Frame(file_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        self.decrypt_input_path = tk.StringVar()
        ttk.Label(input_frame, text="Encrypted File:").pack(side=tk.LEFT)
        ttk.Entry(input_frame, textvariable=self.decrypt_input_path).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(input_frame, text="Browse", command=self.browse_decrypt_input).pack(side=tk.LEFT)
        
        # Key file selection
        key_frame = ttk.Frame(file_frame)
        key_frame.pack(fill=tk.X, pady=5)
        
        self.key_path = tk.StringVar()
        ttk.Label(key_frame, text="Key File:").pack(side=tk.LEFT)
        ttk.Entry(key_frame, textvariable=self.key_path).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(key_frame, text="Browse", command=self.browse_key).pack(side=tk.LEFT)
        
        # Decrypt button
        ttk.Button(self.decrypt_frame, text="Decrypt File", command=self.decrypt).pack(pady=20)
        
    def browse_encrypt_input(self):
        filename = filedialog.askopenfilename(title="Select File to Encrypt")
        if filename:
            self.encrypt_input_path.set(filename)
            
    def browse_decrypt_input(self):
        filename = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if filename:
            self.decrypt_input_path.set(filename)
            
    def browse_key(self):
        filename = filedialog.askopenfilename(title="Select Key File", filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if filename:
            self.key_path.set(filename)
            
    def update_status(self, message):
        self.status_text.insert(tk.END, f"{message}\n")
        self.status_text.see(tk.END)
        self.root.update()
        
    def generate_base_key(self, size=32):
        return os.urandom(size)

    def expand_key(self, base_key, needed_size):
        expanded = []
        current_hash = base_key
        while len(expanded) < needed_size:
            current_hash = hashlib.sha256(current_hash).digest()
            expanded.extend(current_hash)
        return bytes(expanded[:needed_size])

    def xor_crypt(self, data, key):
        return bytes(a ^ b for a, b in zip(data, key))
            
    def encrypt(self):
        input_file = self.encrypt_input_path.get()
        if not input_file:
            messagebox.showerror("Error", "Please select a file to encrypt")
            return
            
        try:
            # Get file extension
            file_extension = os.path.splitext(input_file)[1]
            ext_bytes = file_extension.encode('utf-8')
            ext_length = len(ext_bytes)
            
            # Read input file
            self.update_status(f"Reading input file: {input_file}")
            with open(input_file, 'rb') as f:
                data = f.read()
                
            # Generate and expand key
            self.update_status("Generating encryption key...")
            base_key = self.generate_base_key()
            total_size = len(data) + ext_length + 4
            expanded_key = self.expand_key(base_key, total_size)
            
            # Prepare and encrypt data
            self.update_status("Encrypting data...")
            full_data = struct.pack('<I', ext_length) + ext_bytes + data
            encrypted_data = self.xor_crypt(full_data, expanded_key)
            
            # Save files
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            encrypted_file = f"encrypted_{timestamp}.bin"
            key_file = f"key_{timestamp}.bin"
            
            with open(encrypted_file, 'wb') as f:
                f.write(encrypted_data)
            with open(key_file, 'wb') as f:
                f.write(base_key)
                
            self.update_status(f"Encryption successful!")
            self.update_status(f"Encrypted file: {encrypted_file}")
            self.update_status(f"Key file: {key_file}")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status(f"Error: {str(e)}")
            
    def decrypt(self):
        input_file = self.decrypt_input_path.get()
        key_file = self.key_path.get()
        
        if not input_file or not key_file:
            messagebox.showerror("Error", "Please select both encrypted file and key file")
            return
            
        try:
            # Read files
            self.update_status(f"Reading encrypted file: {input_file}")
            with open(input_file, 'rb') as f:
                encrypted_data = f.read()
                
            self.update_status(f"Reading key file: {key_file}")
            with open(key_file, 'rb') as f:
                base_key = f.read()
                
            # Expand key and decrypt
            self.update_status("Decrypting data...")
            expanded_key = self.expand_key(base_key, len(encrypted_data))
            decrypted_data = self.xor_crypt(encrypted_data, expanded_key)
            
            # Extract file extension
            ext_length = struct.unpack('<I', decrypted_data[:4])[0]
            extension = decrypted_data[4:4+ext_length].decode('utf-8')
            file_data = decrypted_data[4+ext_length:]
            
            # Save decrypted file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            decrypted_file = f"decrypted_{timestamp}{extension}"
            
            with open(decrypted_file, 'wb') as f:
                f.write(file_data)
                
            self.update_status(f"Decryption successful!")
            self.update_status(f"Decrypted file: {decrypted_file}")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status(f"Error: {str(e)}")

def main():
    root = ThemedTk(theme="arc")  # You can choose different themes: 'arc', 'clearlooks', 'radiance', etc.
    app = XORCryptoGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
