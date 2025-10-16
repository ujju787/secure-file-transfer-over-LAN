# Secure File Transfer System for LAN

This project is a client-server application developed in Python that provides a secure channel for transferring files across a Local Area Network (LAN). It addresses the security vulnerabilities of standard file-sharing methods by implementing user authentication, strong AES encryption for data confidentiality, and SHA-256 hashing for data integrity.

---

## ✨ Key Features

* **Client-Server Architecture**: Uses TCP sockets for reliable, connection-oriented communication.
* **User Authentication**: Only registered and authorized users can connect and transfer files.
* **AES-256 Encryption**: All file content is encrypted on the client-side before being sent over the network, making it unreadable to packet sniffers.
* **SHA-256 Integrity Check**: The server verifies a hash of the received file to ensure it has not been tampered with or corrupted during transit.
* **Graphical User Interface (GUI)**: Both the client and server have simple, intuitive interfaces built with Python's `tkinter` library.
* **Transaction Logging**: The server maintains a database log of all transfer attempts, including user, file details, and status.

---

## 🛠️ Technology Stack

* **Programming Language**: Python 3.x
* **Core Libraries**:
    * `socket`: For network communication (TCP sockets).
    * `threading`: To allow the server to handle multiple clients without freezing the GUI.
    * `tkinter`: For building the graphical user interfaces.
    * `cryptography`: For implementing AES encryption/decryption.
    * `hashlib`: For SHA-256 hashing functions.
* **Database**: `sqlite3` (A lightweight, file-based SQL database).

---

## 🚀 How to Set Up and Run the Project

Follow these steps carefully to get the application running.

### Step 1: Prerequisites

* Make sure you have **Python 3.6 or newer** installed on your system.
* You will need two machines on the same LAN to test the network transfer. Alternatively, you can run both the client and server on the same machine.

### Step 2: Install Required Library

The only external library needed is `cryptography`. Open your terminal or command prompt and install it using `pip`:

```bash
pip install cryptography
```

### Step 3: Initialize the Database

Before running the server, you must set up the database. This script creates `secure_file_transfer.db` and populates it with the necessary tables and a default user.

In your terminal, run the `database.py` script:

```bash
python database.py
```

This creates a default user with the following credentials:
> **Username**: `admin`
>
> **Password**: `password`

### Step 4: Run the Server

The server must be running before any clients can connect.

1.  Open a new terminal and run the `server.py` script:
    ```bash
    python server.py
    ```
2.  A GUI window titled "Secure File Transfer Server" will appear.
3.  Click the **"Start Server"** button.
4.  The log area will show `Server started. Listening on 0.0.0.0:9999`.
5.  A directory named `received_files` will be created automatically to store transferred files.

### Step 5: Run the Client and Transfer a File

Now, use the client application to send a file.

1.  Open another terminal and run the `client.py` script:
    ```bash
    python client.py
    ```
2.  A GUI window titled "Secure File Transfer Client" will appear.
3.  Fill in the details:
    * **Server IP**: Use `127.0.0.1` if running on the same machine. Otherwise, enter the server's local IP address (e.g., `192.168.1.10`).
    * **Port**: `9999`
    * **Username**: `admin`
    * **Password**: `password`
4.  Click **"Browse..."** to choose a file.
5.  Click **"Send Secure File"** to begin the transfer.

### Step 6: Verify the Transfer

* **Client**: A success message box should appear.
* **Server**: The log area will show details of the successful transfer and integrity check.
* **File System**: Check the `received_files` directory. The transferred file should be present, decrypted, and identical to the original.

---

## 📈 Limitations and Future Improvements

* **Hardcoded Encryption Key**: For simplicity, the AES key is hardcoded. A production system should implement a secure key exchange mechanism like Diffie-Hellman.
* **Single File Transfers**: The application currently supports transferring only one file at a time. It could be extended to handle directories.
* **Basic User Management**: Users must be added manually to the database. A future version could include an admin panel for user management within the server GUI.