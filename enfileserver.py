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
SERVER_PRIV = ec.generate_private_key(ec.SECP384R1())
SERVER_PUB_BYTES = SERVER_PRIV.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def derive_shared_key(priv, peer_pub_bytes):
    peer_pub = serialization.load_pem_public_key(peer_pub_bytes)
    shared = priv.exchange(ec.ECDH(), peer_pub)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake-data').derive(shared)

import os
def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    #iv = b"\x00" * 16   # for deterministic testing (commented)
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


# --- client state ---
# clients: conn -> {"username": str, "key": bytes}
clients = {}
clients_lock = threading.Lock()

# uploads in progress from clients: conn -> {filename, filesize, bytes_received, fobj, save_path}
uploads = {}
uploads_lock = threading.Lock()

def broadcast_encrypted(sender_conn, plaintext: bytes):
    """
    Re-encrypt plaintext for each recipient and send as frames.
    plaintext is the full plaintext frame (e.g. b"MSGusername: text" or b"FIL...header..." etc.)
    """
    with clients_lock:
        for conn, meta in list(clients.items()):
            if conn is sender_conn:
                continue
            try:
                ct = aes_encrypt(meta["key"], plaintext)
                send_frame(conn, ct)
            except Exception:
                try:
                    conn.close()
                except:
                    pass
                clients.pop(conn, None)

def rebroadcast_file_from_disk(sender_conn, save_path, filename, filesize):
    """
    After fully saving file on disk, re-send header + chunks encrypted per-recipient.
    """
    # Build header plaintext
    header = b"FIL" + struct.pack("!H", len(filename)) + filename.encode() + struct.pack("!Q", filesize)

    with clients_lock:
        recipients = [(c, m["key"]) for c, m in clients.items() if c is not sender_conn]

    for conn, key in recipients:
        try:
            # send encrypted header
            send_frame(conn, aes_encrypt(key, header))
        except Exception:
            try:
                conn.close()
            except:
                pass
            with clients_lock:
                clients.pop(conn, None)

    # send chunks per recipient
    with open(save_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            chunk_plain = b"CHN" + chunk
            # encrypt chunk for each recipient and send
            with clients_lock:
                for conn, meta in list(clients.items()):
                    if conn is sender_conn:
                        continue
                    try:
                        ct = aes_encrypt(meta["key"], chunk_plain)
                        send_frame(conn, ct)
                    except Exception:
                        try:
                            conn.close()
                        except:
                            pass
                        clients.pop(conn, None)

def handle_client(conn, addr):
    try:
        # 1) send server public key
        send_frame(conn, SERVER_PUB_BYTES)

        # 2) receive client public key
        client_pub = recv_frame(conn)
        if client_pub is None:
            return

        # 3) derive AES key
        aes_key = derive_shared_key(SERVER_PRIV, client_pub)

        # 4) receive encrypted username frame
        enc_username_frame = recv_frame(conn)
        if enc_username_frame is None:
            return
        try:
            username = aes_decrypt(aes_key, enc_username_frame).decode(errors="ignore")
        except Exception:
            return

        with clients_lock:
            clients[conn] = {"username": username, "key": aes_key}

        print(f"{username} joined from {addr}")
        # announce (plaintext frame broadcasted encrypted to others)
        broadcast_encrypted(conn, b"MSG" + f"📢 {username} has joined!".encode())

        # main loop
        while True:
            enc_frame = recv_frame(conn)
            if enc_frame is None:
                break

            # decrypt using sender's key
            try:
                plain = aes_decrypt(aes_key, enc_frame)
            except Exception:
                # decryption error -> drop connection
                break

            msg_type = plain[:3].decode()
            payload = plain[3:]

            if msg_type == "MSG":
                text = payload.decode(errors="ignore")
                print(f"{username}: {text}")
                # rebroadcast plaintext (message) encrypted for everyone else
                broadcast_encrypted(conn, b"MSG" + f"{username}: {text}".encode())

            elif msg_type == "FIL":
                # header: [2-byte fn_len][filename][8-byte filesize]
                fn_len = struct.unpack("!H", payload[:2])[0]
                filename = payload[2:2+fn_len].decode()
                filesize = struct.unpack("!Q", payload[2+fn_len:2+fn_len+8])[0]

                # Prepare to receive chunks
                os.makedirs("server_files", exist_ok=True)
                save_path = os.path.join("server_files", filename)
                fobj = open(save_path, "wb")

                with uploads_lock:
                    uploads[conn] = {"filename": filename, "filesize": filesize, "bytes_received": 0, "fobj": fobj, "save_path": save_path}

                print(f"[FILE START] {username} -> {filename} ({filesize} bytes)")

                # Note: do NOT broadcast header yet. Wait until fully received.

            elif msg_type == "CHN":
                # chunk payload
                with uploads_lock:
                    st = uploads.get(conn)
                if st is None:
                    # unexpected chunk -> ignore
                    continue
                chunk = payload  # raw bytes
                st["fobj"].write(chunk)
                st["bytes_received"] += len(chunk)

                if st["bytes_received"] >= st["filesize"]:
                    # finished
                    st["fobj"].close()
                    filename = st["filename"]
                    filesize = st["filesize"]
                    save_path = st["save_path"]
                    with uploads_lock:
                        uploads.pop(conn, None)
                    print(f"[FILE COMPLETE] {username} uploaded {filename} ({filesize} bytes). Saved: {save_path}")
                    # Now rebroadcast stored file to others (re-encrypt per recipient)
                    rebroadcast_file_from_disk(conn, save_path, filename, filesize)

            else:
                # unknown type - ignore
                continue

    except Exception as e:
        print(f"[!] Error with {addr}: {e}")
    finally:
        # cleanup
        with clients_lock:
            meta = clients.pop(conn, None)
        try:
            conn.close()
        except:
            pass
        if meta:
            broadcast_encrypted(None, b"MSG" + f"📢 {meta['username']} has left.".encode())
            print(f"{meta['username']} disconnected")

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()
    print(f"[*] Secure multi-client server running on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    finally:
        s.close()

if __name__ == "__main__":
    main()
