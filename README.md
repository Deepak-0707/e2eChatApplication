# 📂 Project Files

This repository currently contains three stages of the chat system, each with its own server–client pair.

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
A secure chat server that supports **only one client**.  
- Uses **ECDH (Elliptic Curve Diffie–Hellman)** for key exchange.  
- Derives a shared **AES session key**.  
- Encrypts all client–server communication using **AES-CFB**.  

### `enclient.py`
Companion client for `enserver.py`.  
- Performs handshake with the server.  
- Exchanges encrypted messages securely.  
- Limited to a single active connection.  

---

## 3. Secure Multi-Client Chat

### `mulenserver.py`
Extension of `enserver.py` to handle **multiple clients simultaneously**.  
- Each client establishes its **own AES key** with the server via ECDH.  
- When Client 1 sends a message:  
  - The server receives it **encrypted with Client 1’s key**.  
  - Server **decrypts** using Client 1’s key.  
  - Server then **re-encrypts** the plaintext for every other client using their keys.  
- This ensures all network traffic remains encrypted, even though the server acts as a trusted relay.  

### `milenclient.py`
Companion client for `mulenserver.py`.  
- Connects securely to the multi-client server.  
- Handles both encrypted sending and receiving.  
- Allows group chat with multiple participants, each secured with their own key.  
