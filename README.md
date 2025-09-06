# 📂 Project Files

This repository contains multiple stages of a chat system, each with its own server–client pair. The system has been progressively extended from basic chat to secure multi-client communication, and finally to file-sharing functionality.

---

## 1. Basic Relay Chat

### `server.py`
A simple multi-client chat server.  
- Accepts multiple client connections.  
- Relays messages from any client to all others (broadcast).  
- Messages are transmitted in **plaintext** (no encryption).  

### `client.py`
Connects to the basic server.  
- Sends user input directly to the server.  
- Receives and prints messages broadcast by the server.  

---

## 2. Secure Single-Client Chat

### `enserver.py`
A secure chat server supporting **one client**.  
- Uses **ECDH (Elliptic Curve Diffie–Hellman)** for key exchange.  
- Derives a shared **AES session key**.  
- Encrypts all communication with **AES-CFB**.  

### `enclient.py`
Companion client for `enserver.py`.  
- Performs handshake with the server.  
- Exchanges encrypted messages securely.  

---

## 3. Secure Multi-Client Chat

### `mulenserver.py`
Extension of `enserver.py` for **multiple clients**.  
- Each client establishes its **own AES key** with the server.  
- Server decrypts incoming messages from a client and re-encrypts them for every other client.  
- Ensures all network traffic remains encrypted.  

### `milenclient.py`
Companion client for `mulenserver.py`.  
- Handles encrypted sending and receiving for multiple participants.  

---

## 4. File-Sharing Chat (Unencrypted)

### `fileserver.py`
Extends `server.py` with **file-sharing capability**.  
- Supports multiple clients.  
- Broadcasts messages as well as shared files.  
- **Files are transmitted in plaintext** (no encryption).  

### `fileclient.py`
Companion client for `fileserver.py`.  
- Can send and receive both chat messages and files.  

---

## 5. Secure File-Sharing Chat (Encrypted)

### `enfileserver.py`
Extends `enserver.py` for **secure file transfer**.  
- Uses **ECDH + AES-CFB** for encryption.  
- Supports file sharing alongside messages.  
- Ensures all traffic, including files, is encrypted.  

### `enfileclient.py`
Companion client for `enfileserver.py`.  
- Connects securely and handles encrypted chat and file transfers.  

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
   └─> Secure File-Sharing Chat (Encrypted)
