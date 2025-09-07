import socket
import threading
import struct
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = "localhost"
PORT = 12345

# --- framing helpers ---
def send_frame(sock, payload: bytes):
    sock.sendall(struct.pack("!I", len(payload)) + payload)

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def recv_frame(sock):
    hdr = recv_exact(sock, 4)
    if not hdr:
        return None
    (length,) = struct.unpack("!I", hdr)
    return recv_exact(sock, length)

# --- crypto helpers (ECDH + HKDF + AES-CFB) ---
SERVER_PRIV = ec.generate_private_key(ec.SECP384R1())
SERVER_PUB_BYTES = SERVER_PRIV.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def derive_shared_key(priv, peer_pub_bytes):
    peer_pub = serialization.load_pem_public_key(peer_pub_bytes)
    shared = priv.exchange(ec.ECDH(), peer_pub)
    # Derive 32-byte AES key
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake-data'
    ).derive(shared)

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    #iv=b"\x00" * 16 # --- For Testing purpose ---
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    print(f"[DEBUG] Sending ciphertext: {ct.hex()}")
    return iv + ct

def aes_decrypt(key: bytes, iv_ct: bytes) -> bytes:
    iv, ct = iv_ct[:16], iv_ct[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()

# --- client management ---
# clients: {conn: {"username": str, "key": bytes}}
clients = {}
clients_lock = threading.Lock()

def broadcast(sender_conn, message_text: str):
    """
    Re-encrypt the same plaintext message for each recipient using its own key,
    then send as a length-prefixed frame.
    """
    payload = message_text.encode()
    with clients_lock:
        for conn, meta in list(clients.items()):
            # don't echo back to sender (mimics original behavior)
            if conn is sender_conn:
                continue
            try:
                ct = aes_encrypt(meta["key"], payload)
                send_frame(conn, ct)
            except Exception:
                # drop client on any send/IO error
                try:
                    conn.close()
                except:
                    pass
                clients.pop(conn, None)

def handle_client(conn, addr):
    try:
        # 1) Send server public key (raw PEM) as frame
        send_frame(conn, SERVER_PUB_BYTES)

        # 2) Receive client's public key (PEM) as frame
        client_pub = recv_frame(conn)
        if client_pub is None:
            return

        # 3) derive per-connection AES key
        aes_key = derive_shared_key(SERVER_PRIV, client_pub)

        # 4) receive first encrypted frame which should contain the username
        first_frame = recv_frame(conn)
        if first_frame is None:
            return
        try:
            username = aes_decrypt(aes_key, first_frame).decode(errors="ignore")
        except Exception:
            return

        # store client meta
        with clients_lock:
            clients[conn] = {"username": username, "key": aes_key}

        print(f"{username} joined from {addr}")
        # announce to others
        broadcast(conn, f"📢 {username} has joined the chat!")

        # main loop: receive encrypted frames, decrypt, then broadcast plaintext
        while True:
            frame = recv_frame(conn)
            if frame is None:
                break
            print(f"[DEBUG] Raw data received:{frame.hex()}")
            try:
                msg = aes_decrypt(aes_key, frame).decode(errors="ignore")
            except Exception:
                break
            print(f"{username}: {msg}")
            broadcast(conn, f"{username}: {msg}")

    except Exception as e:
        print(f"[!] Error with client {addr}: {e}")
    finally:
        # cleanup
        left_user = None
        with clients_lock:
            left_user = clients.pop(conn, None)
        try:
            conn.close()
        except:
            pass
        if left_user:
            broadcast(None, f"📢 {left_user['username']} has left the chat.")
            print(f"{left_user['username']} disconnected")

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print("Server is running and relaying messages (secure).")
    try:
        while True:
            conn, addr = server_socket.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
