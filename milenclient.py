import socket
import threading
import struct
import sys
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

# --- crypto helpers ---
def derive_shared_key(priv, peer_pub_bytes):
    peer_pub = serialization.load_pem_public_key(peer_pub_bytes)
    shared = priv.exchange(ec.ECDH(), peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake-data'
    ).derive(shared)

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    #iv=b"\x00" * 16 # --- For Testing Purpose ---
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    print(f"[DEBUG] Sending ciphertext:{ct.hex()}")
    return iv + ct

def aes_decrypt(key: bytes, iv_ct: bytes) -> bytes:
    iv, ct = iv_ct[:16], iv_ct[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()

def receiver_loop(sock, aes_key):
    while True:
        frame = recv_frame(sock)
        if frame is None:
            print("\n[Disconnected from server]")
            os._exit(0)
        try:
            msg = aes_decrypt(aes_key, frame).decode(errors="ignore")
        except Exception:
            print("\n[Decrypt error]")
            os._exit(1)
        print("\r" + " " * 80 + "\r", end="")
        print(msg)
        print("> ", end="", flush=True)

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # 1) receive server public key (PEM) as frame
    server_pub = recv_frame(s)
    if server_pub is None:
        print("Failed to receive server public key.")
        return

    # 2) generate our ECDH keypair and send public key
    priv = ec.generate_private_key(ec.SECP384R1())
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    send_frame(s, pub_bytes)

    # 3) derive AES key
    aes_key = derive_shared_key(priv, server_pub)
    print("[*] Secure channel established.")

    # 4) send username encrypted as first frame (server expects this)
    username = input("Enter your username: ").strip() or "anonymous"
    send_frame(s, aes_encrypt(aes_key, username.encode()))

    # 5) start receiver thread
    threading.Thread(target=receiver_loop, args=(s, aes_key), daemon=True).start()

    # 6) send loop
    try:
        while True:
            msg = input("> ").rstrip("\n")
            if not msg:
                continue
            send_frame(s, aes_encrypt(aes_key, msg.encode()))
    except (KeyboardInterrupt, SystemExit):
        s.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
