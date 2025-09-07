# 💬 Chat Application

A secure end-to-end encrypted (E2EE) chat system with multi-client support, file sharing, and GUI. Built in progressive stages, the project demonstrates the evolution from a simple plaintext chat server to a secure, encrypted, multi-client system with file transfer capabilities.

---

## 📂 Project Files

### 1. Basic Relay Chat
- **`server.py`** – Multi-client relay server (plaintext).  
- **`client.py`** – Basic client that connects and exchanges unencrypted messages.

### 2. Secure Single-Client Chat
- **`enserver.py`** – Secure server (one client) using **ECDH + AES-CFB**.  
- **`enclient.py`** – Secure client for `enserver.py`.

### 3. Secure Multi-Client Chat
- **`mulenserver.py`** – Extends secure server for **multiple clients**, each with its own AES key.  
- **`milenclient.py`** – Secure multi-client companion.

### 4. File-Sharing Chat (Unencrypted)
- **`fileserver.py`** – Adds file-sharing, but messages/files are **plaintext**.  
- **`fileclient.py`** – Companion for unencrypted file-sharing.

### 5. Secure File-Sharing Chat (Encrypted)
- **`enfileserver.py`** – Secure server with **E2EE chat + file sharing**.  
- **`enfileclient.py`** – Secure GUI client with encrypted chat + file transfers.  


- **`requirements.txt`** – Python dependencies for running/building the project.  
- **`howItWorks.md`** – Explanation of encryption, handshake, and file-sharing workflow.

---

## 🔗 Project Progression
```text
Basic Chat
   │
   ├─> Secure Single-Client Chat
   │
   ├─> Secure Multi-Client Chat
   │
   ├─> File-Sharing Chat (Unencrypted)
   │
   └─> Secure File-Sharing Chat (Encrypted + GUI)

---
```
## How to Use

### Server side
1.Install the requirements given in the requirements.txt 
2.Run the enfileserver.py in the server Device


### Client side
1.Get the server ip 
2.Modify the host='server-ip'
3.Run this command to generate an .exe file
```bash
pyinstaller --onefile enfileclient.py
```
Just the copy the .exe file from the dict directory and use it any client device you want.


