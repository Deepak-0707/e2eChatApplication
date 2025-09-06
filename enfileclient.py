import socket
import threading
import struct
import os
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = "localhost"
PORT = 12345
CHUNK_SIZE = 4096

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
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake-data').derive(shared)

import os
def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    #iv = b"\x00" * 16  #---For testing only---
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    '''print(f"[DEBUG] Encrypting plaintext: {plaintext}")
    print(f"[DEBUG] Sending ciphertext: {(iv + ct).hex()}")'''
    return iv + ct

def aes_decrypt(key: bytes, iv_ct: bytes) -> bytes:
    #print(f"[DEBUG] Raw data received: {iv_ct.hex()}")
    iv, ct = iv_ct[:16], iv_ct[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    dec = cipher.decryptor()
    pt = dec.update(ct) + dec.finalize()
    #print(f"[DEBUG] Decrypted plaintext: {pt}")
    return pt
    

# --- incoming file state per server stream ---
incoming = {}  # expects a single server; this maps to current receiving file state with keys: filename, filesize, received, fobj

def receiver_loop(sock, aes_key):
    while True:
        enc_frame = recv_frame(sock)
        if enc_frame is None:
            print("\n[Disconnected from server]")
            os._exit(0)
        try:
            plain = aes_decrypt(aes_key, enc_frame)
        except Exception:
            print("\n[Decrypt error]")
            os._exit(1)

        msg_type = plain[:3].decode()
        payload = plain[3:]

        if msg_type == "MSG":
            print(payload.decode())
        elif msg_type == "FIL":
            fn_len = struct.unpack("!H", payload[:2])[0]
            filename = payload[2:2+fn_len].decode()
            filesize = struct.unpack("!Q", payload[2+fn_len:2+fn_len+8])[0]
            os.makedirs("downloads", exist_ok=True)
            outpath = os.path.join("downloads", filename)
            fobj = open(outpath, "wb")
            incoming["state"] = {"filename": filename, "filesize": filesize, "received": 0, "fobj": fobj, "outpath": outpath}
            print(f"[FILE START] Receiving {filename} ({filesize} bytes)")
        elif msg_type == "CHN":
            st = incoming.get("state")
            if st is None:
                # no header seen -> ignore
                continue
            chunk = payload
            st["fobj"].write(chunk)
            st["received"] += len(chunk)
            if st["received"] >= st["filesize"]:
                st["fobj"].close()
                print(f"[FILE COMPLETE] Saved downloads/{st['filename']} ({st['filesize']} bytes)")
                incoming.pop("state", None)
        else:
            # unknown
            continue

def send_text(sock, aes_key, text):
    plain = b"MSG" + text.encode()
    send_frame(sock, aes_encrypt(aes_key, plain))

def send_file(sock, aes_key, filepath):
    if not os.path.exists(filepath):
        print("[!] File not found")
        return
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    # send header
    header = b"FIL" + struct.pack("!H", len(filename)) + filename.encode() + struct.pack("!Q", filesize)
    send_frame(sock, aes_encrypt(aes_key, header))

    # send chunks
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            chunk_plain = b"CHN" + chunk
            send_frame(sock, aes_encrypt(aes_key, chunk_plain))
    print(f"[SENT FILE] {filename} ({filesize} bytes)")

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # 1) receive server pub
    server_pub = recv_frame(s)
    if server_pub is None:
        print("Failed to get server public key")
        return

    # 2) generate own key and send pub
    priv = ec.generate_private_key(ec.SECP384R1())
    pub_bytes = priv.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    send_frame(s, pub_bytes)

    # 3) derive aes key
    aes_key = derive_shared_key(priv, server_pub)
    print("[*] Secure channel established.")

    # 4) send username encrypted as first frame
    username = input("Enter your username: ").strip() or "anonymous"
    send_frame(s, aes_encrypt(aes_key, username.encode()))

    # 5) start receiver thread
    threading.Thread(target=receiver_loop, args=(s, aes_key), daemon=True).start()

    try:
        while True:
            line = input("> ").rstrip("\n")
            if not line:
                continue
            if line.startswith("/sendfile "):
                path = line.split(" ", 1)[1].strip().strip('"')
                send_file(s, aes_key, path)
            else:
                send_text(s, aes_key, line)
    except (KeyboardInterrupt, SystemExit):
        s.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
