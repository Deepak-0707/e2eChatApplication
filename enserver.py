import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# --- Utility: AES encrypt/decrypt ---
def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    #iv=b"\x00"*16  ----For Testing purpose----
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    print(f"[DEBUG] Sending ciphertext: {ciphertext.hex()}")
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(actual_ciphertext) + decryptor.finalize()

# --- ECDH Key Exchange ---
def derive_shared_key(private_key, peer_public_bytes):
    peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake-data'
    ).derive(shared_secret)
    return derived_key

# --- Server Logic ---
HOST, PORT = "127.0.0.1", 65432
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(1)
print("[*] Server listening...")

conn, addr = server_socket.accept()
print(f"[*] Connected by {addr}")

# Generate ECDH key pair
server_private_key = ec.generate_private_key(ec.SECP384R1())
server_public_key = server_private_key.public_key()

# Send public key
server_public_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
conn.sendall(server_public_bytes)

# Receive client public key
client_public_bytes = conn.recv(1024)

# Derive shared AES key
aes_key = derive_shared_key(server_private_key, client_public_bytes)
print("[*] AES key established!")

# Secure messaging
while True:
    data = conn.recv(4096)
    print(f"[DEBUG] Raw data received: {data.hex()}")  # <-- encrypted data
    msg = decrypt_message(aes_key, data).decode()
    if not data:
        break
    msg = decrypt_message(aes_key, data).decode()
    print(f"[Client]: {msg}")

    reply = input("Server: ")
    conn.sendall(encrypt_message(aes_key, reply))

conn.close()
