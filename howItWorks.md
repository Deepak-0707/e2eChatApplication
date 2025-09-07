## 🧩 How It Works

1. **Handshake (ECDH + AES Key Exchange)**
   - Server generates an ECC key pair.
   - Client generates its own ECC key pair.
   - They exchange public keys.
   - Using ECDH + HKDF, both derive a **shared AES key**.

2. **Secure Communication**
   - Messages are encrypted with AES (CFB mode).
   - Each message is framed with a length header, then sent.

3. **File Transfer**
   - Client sends a file header (`FIL`) with name + size.
   - File chunks (`CHN`) are encrypted and sent sequentially.
   - Server stores file → re-encrypts → broadcasts to all clients.

4. **Multi-client Broadcast**
   - Server re-encrypts every message/file separately for each client.
   - Ensures true **end-to-end encryption** per client connection.
