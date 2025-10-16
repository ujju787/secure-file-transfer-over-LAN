import socket
import threading
import sqlite3
import hashlib
import os
from datetime import datetime
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog

# --- CONFIGURATION ---
HOST = '0.0.0.0'  # Listen on all available network interfaces
PORT = 9989
DB_NAME = "secure_file_transfer.db"
RECEIVED_FILES_DIR = "received_files"

# --- SECURITY ---
# This key MUST be the same in both server.py and client.py
# In a real-world scenario, this should be managed securely, not hardcoded.
# You can generate a new key using: Fernet.generate_key()
ENCRYPTION_KEY = b'ct_3FcTzNnC2d5s-jZldd_I2zXBp8-Y1BGd-rX2D-7U='
cipher_suite = Fernet(ENCRYPTION_KEY)

# --- DATABASE HELPER FUNCTIONS ---
def log_transfer(client_ip, username, filename, file_size, status, notes=""):
    """Logs a file transfer event to the database."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO transfer_logs (client_ip, username, filename, file_size, status, notes) VALUES (?, ?, ?, ?, ?, ?)",
            (client_ip, username, filename, file_size, status, notes)
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def verify_user(username, password_hash):
    """Verifies user credentials against the database."""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result and result[0] == password_hash:
            return True
        return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()

def hash_data(data):
    """Calculates SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()

# --- SERVER GUI ---
class ServerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Transfer Server")
        master.geometry("600x480")
        
        self.log_area = scrolledtext.ScrolledText(master, state='disabled', wrap=tk.WORD, bg="#0b0101", fg="#fafafa")
        self.log_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        self.status_bar = tk.Label(master, text="Status: Stopped", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.start_button = tk.Button(master, text="Start Server", command=self.start_server_thread)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.stop_button = tk.Button(master, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, padx=10, pady=5)

        self.server_socket = None
        self.is_running = False

    def log(self, message):
        """Adds a message to the GUI log area."""
        self.master.after(0, self._log, message)

    def _log(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
        self.log_area.config(state='disabled')
        self.log_area.yview(tk.END)

    def update_status(self, message):
        self.master.after(0, self._update_status, message)
        
    def _update_status(self, message):
        self.status_bar.config(text=f"Status: {message}")

    def start_server_thread(self):
        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        threading.Thread(target=self.start_server, daemon=True).start()

    def start_server(self):
        # Create directory for received files if it doesn't exist
        os.makedirs(RECEIVED_FILES_DIR, exist_ok=True)
        self.log(f"'{RECEIVED_FILES_DIR}' directory is ready.")

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen(5)
            self.log(f"Server started. Listening on {HOST}:{PORT}")
            self.update_status(f"Listening on {HOST}:{PORT}")

            while self.is_running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    if not self.is_running:
                        break
                    self.log(f"Accepted connection from {addr[0]}:{addr[1]}")
                    handler_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                    handler_thread.daemon = True
                    handler_thread.start()
                except OSError:
                    # This exception occurs when the socket is closed while accept() is blocking
                    break

        except Exception as e:
            self.log(f"Server startup error: {e}")
            messagebox.showerror("Server Error", f"Could not start server: {e}")
        finally:
            self.log("Server has shut down.")
            self.update_status("Stopped")

    def stop_server(self):
        self.log("Stopping server...")
        self.is_running = False
        if self.server_socket:
            # Create a dummy connection to unblock the accept() call
            try:
                # Use a non-blocking socket to connect to self to unblock .accept()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect((HOST if HOST != '0.0.0.0' else '127.0.0.1', PORT))
            except Exception as e:
                self.log(f"Dummy connection error during shutdown: {e}")
            finally:
                 self.server_socket.close()
        
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.update_status("Stopped")

    def handle_client(self, client_socket, addr):
        username = "N/A"
        try:
            # 1. Authentication
            creds = client_socket.recv(1024).decode()
            username, password_hash = creds.split(":")
            
            if verify_user(username, password_hash):
                client_socket.sendall(b"AUTH_SUCCESS")
                self.log(f"User '{username}' authenticated successfully from {addr[0]}.")
            else:
                client_socket.sendall(b"AUTH_FAIL")
                self.log(f"Authentication failed for user '{username}' from {addr[0]}.")
                return

            # 2. Receive metadata
            metadata_str = client_socket.recv(1024).decode()
            filename, file_size_str, client_hash = metadata_str.split(":")
            file_size = int(file_size_str)
            self.log(f"Receiving '{filename}' ({file_size} bytes) from '{username}'.")

            # 3. Receive encrypted file data
            encrypted_data = b""
            bytes_received = 0
            while bytes_received < file_size:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                encrypted_data += chunk
                bytes_received += len(chunk)
            
            if bytes_received != file_size:
                raise Exception("File data did not match expected size.")

            # 4. Decrypt file
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            self.log(f"File '{filename}' decrypted successfully.")

            # 5. Verify integrity
            server_hash = hash_data(decrypted_data)
            if server_hash == client_hash:
                self.log(f"Integrity check PASSED for '{filename}'. Hashes match.")
                
                # Save the file
                save_path = os.path.join(RECEIVED_FILES_DIR, os.path.basename(filename))
                with open(save_path, 'wb') as f:
                    f.write(decrypted_data)
                
                log_transfer(addr[0], username, filename, len(decrypted_data), "Success", "Integrity check passed.")
                client_socket.sendall(b"TRANSFER_SUCCESS")
                self.log(f"Successfully saved '{filename}' to '{save_path}'.")

            else:
                self.log(f"Integrity check FAILED for '{filename}'. Hashes do not match.")
                log_transfer(addr[0], username, filename, len(decrypted_data), "Failed", "Integrity check failed (hash mismatch).")
                client_socket.sendall(b"TRANSFER_FAIL_INTEGRITY")

        except ConnectionResetError:
            self.log(f"Client {addr[0]} disconnected abruptly.")
            log_transfer(addr[0], username, "N/A", 0, "Failed", "Client disconnected abruptly.")
        except Exception as e:
            self.log(f"An error occurred with client {addr[0]}: {e}")
            try:
                log_transfer(addr[0], username, "N/A", 0, "Failed", f"Server error: {e}")
                client_socket.sendall(b"SERVER_ERROR")
            except:
                pass # Client might already be disconnected
        finally:
            client_socket.close()
            self.log(f"Connection with {addr[0]} closed.")

def on_closing(root, app):
    if app.is_running:
        if messagebox.askokcancel("Quit", "The server is still running. Do you want to stop it and quit?"):
            app.stop_server()
            root.destroy()
    else:
        root.destroy()


def main():
    root = tk.Tk()
    app = ServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root, app))
    root.mainloop()

if __name__ == "__main__":
    main()
