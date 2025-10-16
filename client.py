import socket
import os
import hashlib
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# --- CONFIGURATION ---
# This key MUST be the same in both server.py and client.py
ENCRYPTION_KEY = b'ct_3FcTzNnC2d5s-jZldd_I2zXBp8-Y1BGd-rX2D-7U='
cipher_suite = Fernet(ENCRYPTION_KEY)

def hash_password(password):
    """Hashes the password using SHA-256 for authentication."""
    return hashlib.sha256(password.encode()).hexdigest()

def hash_file_data(data):
    """Calculates SHA-256 hash of file data for integrity check."""
    return hashlib.sha256(data).hexdigest()

# --- CLIENT GUI ---
class ClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Transfer Client")
        master.geometry("500x350")

        # Main frame
        main_frame = tk.Frame(master, padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Server info frame
        server_frame = ttk.LabelFrame(main_frame, text="Connection Details")
        server_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(server_frame, text="Server IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.ip_entry = tk.Entry(server_frame)
        self.ip_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        self.ip_entry.insert(0, "127.0.0.1")

        tk.Label(server_frame, text="Port:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.port_entry = tk.Entry(server_frame)
        self.port_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        self.port_entry.insert(0, "9999")
        server_frame.columnconfigure(1, weight=1)

        # Auth frame
        auth_frame = ttk.LabelFrame(main_frame, text="Authentication")
        auth_frame.pack(fill=tk.X, pady=5)

        tk.Label(auth_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.user_entry = tk.Entry(auth_frame)
        self.user_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        self.user_entry.insert(0, "admin")

        tk.Label(auth_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.pass_entry = tk.Entry(auth_frame, show="*")
        self.pass_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        self.pass_entry.insert(0, "password")
        auth_frame.columnconfigure(1, weight=1)

        # File selection
        file_frame = ttk.LabelFrame(main_frame, text="File to Send")
        file_frame.pack(fill=tk.X, pady=5)
        
        self.file_path_label = tk.Label(file_frame, text="No file selected", anchor=tk.W, relief=tk.GROOVE, padx=5)
        self.file_path_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)
        
        self.select_button = tk.Button(file_frame, text="Browse...", command=self.select_file)
        self.select_button.pack(side=tk.RIGHT, padx=5, pady=5)
        self.file_path = ""

        # Send button and status
        self.send_button = tk.Button(main_frame, text="Send Secure File", command=self.send_file_action)
        self.send_button.pack(pady=10, fill=tk.X)
        
        self.status_label = tk.Label(main_frame, text="Status: Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)
        
    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.file_path_label.config(text=os.path.basename(self.file_path))
        else:
            self.file_path_label.config(text="No file selected")
            
    def set_status(self, message, color="black"):
        self.status_label.config(text=f"Status: {message}", fg=color)
        self.master.update_idletasks()

    def lock_ui(self):
        self.send_button.config(state=tk.DISABLED)
        self.select_button.config(state=tk.DISABLED)

    def unlock_ui(self):
        self.send_button.config(state=tk.NORMAL)
        self.select_button.config(state=tk.NORMAL)

    def send_file_action(self):
        server_ip = self.ip_entry.get()
        try:
            server_port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Port must be a number.")
            return

        username = self.user_entry.get()
        password = self.pass_entry.get()
        
        if not all([server_ip, server_port, username, password]):
            messagebox.showwarning("Missing Information", "Please fill in all connection and authentication fields.")
            return
            
        if not self.file_path:
            messagebox.showwarning("No File", "Please select a file to send.")
            return

        self.lock_ui()
        self.set_status("Initiating transfer...")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # 1. Connect to server
                self.set_status(f"Connecting to {server_ip}:{server_port}...")
                s.connect((server_ip, server_port))

                # 2. Authenticate
                self.set_status("Authenticating...")
                password_h = hash_password(password)
                s.sendall(f"{username}:{password_h}".encode())
                
                auth_response = s.recv(1024)
                if auth_response != b"AUTH_SUCCESS":
                    raise Exception("Authentication Failed. Check username/password.")

                self.set_status("Authentication successful. Preparing file...")

                # 3. Read and process file
                with open(self.file_path, 'rb') as f:
                    file_data = f.read()
                
                # 4. Hash and encrypt
                file_hash = hash_file_data(file_data)
                encrypted_data = cipher_suite.encrypt(file_data)
                
                # 5. Send metadata
                filename = os.path.basename(self.file_path)
                metadata = f"{filename}:{len(encrypted_data)}:{file_hash}"
                s.sendall(metadata.encode())
                
                # 6. Send encrypted file data
                self.set_status(f"Transmitting {filename}...")
                s.sendall(encrypted_data)
                
                # 7. Wait for server confirmation
                self.set_status("Waiting for server confirmation...")
                final_status = s.recv(1024)
                
                if final_status == b"TRANSFER_SUCCESS":
                    self.set_status("Transfer completed successfully!", "green")
                    messagebox.showinfo("Success", f"File '{filename}' was sent and verified successfully.")
                elif final_status == b"TRANSFER_FAIL_INTEGRITY":
                     self.set_status("Transfer failed: Integrity check mismatch.", "red")
                     messagebox.showerror("Transfer Failed", "The server reported an integrity check failure. The file may be corrupt.")
                else:
                    raise Exception(f"Received unknown status from server: {final_status.decode()}")

        except Exception as e:
            self.set_status(f"Error: {e}", "red")
            messagebox.showerror("Error", f"An error occurred: {e}")
        finally:
            self.unlock_ui()

def main():
    root = tk.Tk()
    app = ClientGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
