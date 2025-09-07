import sys
import socket
import threading
import struct
import os
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextBrowser, QLineEdit,
    QPushButton, QFileDialog, QLabel, QMessageBox, QInputDialog
)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QTextCursor

# --- Crypto ---
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = "192.168.29.20"
PORT = 5555
CHUNK_SIZE = 4096

# --- Framing helpers ---
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

# --- Crypto helpers ---
def derive_shared_key(priv, peer_pub_bytes):
    peer_pub = serialization.load_pem_public_key(peer_pub_bytes)
    shared = priv.exchange(ec.ECDH(), peer_pub)
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake-data'
    ).derive(shared)

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return iv + ct

def aes_decrypt(key: bytes, iv_ct: bytes) -> bytes:
    iv, ct = iv_ct[:16], iv_ct[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()

# --- Signals ---
class SignalBus(QObject):
    new_message = pyqtSignal(str, str)  # sender, message

signals = SignalBus()

# --- Chat Client GUI ---
class ChatClient(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Chat")
        self.setGeometry(300, 100, 500, 650)
        self.setStyleSheet("""
            QWidget {
                background-color: #2c2f33;
                color: white;
                font-family: Arial;
            }
            QLineEdit {
                border-radius: 15px;
                padding: 8px;
                background: #40444b;
                color: white;
            }
            QPushButton {
                border-radius: 15px;
                padding: 8px;
                background: #5865f2;
                color: white;
            }
            QPushButton:hover {
                background: #4752c4;
            }
        """)

        # Layout
        layout = QVBoxLayout()

        # Header
        self.header = QLabel("🔒 Secure Chat")
        self.header.setStyleSheet("font-size:18px; font-weight:bold; padding:10px;")
        layout.addWidget(self.header, alignment=Qt.AlignmentFlag.AlignCenter)

        # Chat area
        self.chat_area = QTextBrowser()
        self.chat_area.setOpenExternalLinks(True)
        self.chat_area.setStyleSheet("background: #23272a; border:none; padding:10px; font-size:14px;")
        layout.addWidget(self.chat_area)

        # Input area
        input_layout = QHBoxLayout()
        self.input_box = QLineEdit()
        self.input_box.setPlaceholderText("Type a message...")
        input_layout.addWidget(self.input_box)

        self.file_btn = QPushButton("📎")
        input_layout.addWidget(self.file_btn)

        self.send_btn = QPushButton("➡")
        input_layout.addWidget(self.send_btn)

        layout.addLayout(input_layout)
        self.setLayout(layout)

        # Networking
        self.sock = None
        self.aes_key = None
        self.username = None

        # Events
        self.send_btn.clicked.connect(self.send_message)
        self.file_btn.clicked.connect(self.send_file)
        self.input_box.returnPressed.connect(self.send_message)
        signals.new_message.connect(self.display_message)

        # Start connection
        self.connect_to_server()

    def connect_to_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))

            # Handshake
            server_pub = recv_frame(self.sock)
            priv = ec.generate_private_key(ec.SECP384R1())
            pub_bytes = priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            send_frame(self.sock, pub_bytes)
            self.aes_key = derive_shared_key(priv, server_pub)

            # Username
            self.username, ok = QInputDialog.getText(self, "Username", "Enter your username:")
            if not self.username.strip():
                self.username = "anonymous"
            send_frame(self.sock, aes_encrypt(self.aes_key, self.username.encode()))

            # Start receiver
            threading.Thread(target=self.receiver_loop, daemon=True).start()
            signals.new_message.emit("System", f"[*] Connected securely as {self.username}")

        except Exception as e:
            QMessageBox.critical(self, "Connection Error", str(e))
            sys.exit(1)

    def receiver_loop(self):
        incoming = {}
        while True:
            enc_frame = recv_frame(self.sock)
            if enc_frame is None:
                signals.new_message.emit("System", "[Disconnected from server]")
                os._exit(0)
            try:
                plain = aes_decrypt(self.aes_key, enc_frame)
            except Exception:
                signals.new_message.emit("System", "[Decrypt error]")
                os._exit(1)

            msg_type = plain[:3].decode()
            payload = plain[3:]

            if msg_type == "MSG":
                signals.new_message.emit("Other", payload.decode(errors="ignore"))
            elif msg_type == "FIL":
                fn_len = struct.unpack("!H", payload[:2])[0]
                filename = payload[2:2+fn_len].decode()
                filesize = struct.unpack("!Q", payload[2+fn_len:2+fn_len+8])[0]
                os.makedirs("downloads", exist_ok=True)
                outpath = os.path.join("downloads", filename)
                fobj = open(outpath, "wb")
                incoming["state"] = {
                    "filename": filename, "filesize": filesize,
                    "received": 0, "fobj": fobj, "outpath": outpath
                }
                signals.new_message.emit("System", f"[FILE START] Receiving {filename} ({filesize} bytes)")
            elif msg_type == "CHN":
                st = incoming.get("state")
                if st:
                    st["fobj"].write(payload)
                    st["received"] += len(payload)
                    if st["received"] >= st["filesize"]:
                        st["fobj"].close()
                        signals.new_message.emit("System",
                            f"[FILE COMPLETE] Saved downloads/{st['filename']} ({st['filesize']} bytes)")
                        incoming.pop("state", None)

    def send_message(self):
        text = self.input_box.text().strip()
        if not text:
            return
        self.input_box.clear()
        plain = b"MSG" + text.encode()
        send_frame(self.sock, aes_encrypt(self.aes_key, plain))
        signals.new_message.emit("You", text)

    def send_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file to send")
        if not path:
            return
        filename = os.path.basename(path)
        filesize = os.path.getsize(path)

        header = b"FIL" + struct.pack("!H", len(filename)) + filename.encode() + struct.pack("!Q", filesize)
        send_frame(self.sock, aes_encrypt(self.aes_key, header))

        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                chunk_plain = b"CHN" + chunk
                send_frame(self.sock, aes_encrypt(self.aes_key, chunk_plain))

        signals.new_message.emit("You", f"[SENT FILE] {filename} ({filesize} bytes)")

    def display_message(self, sender, msg):
        timestamp = datetime.now().strftime("%H:%M")

        if sender == "You":
            bubble = f'''
            <div style="background:#3ba55c; color:white; padding:8px; border-radius:10px; margin:5px; text-align:right;">
                {msg}
                <div style="font-size:10px; color:lightgray; text-align:right;">{timestamp}</div>
            </div>'''
        elif sender == "System":
            bubble = f'''
            <div style="color:gray; text-align:center; font-style:italic;">
                {msg} - {timestamp}
            </div>'''
        else:  # Other
            bubble = f'''
            <div style="background:#40444b; color:white; padding:8px; border-radius:10px; margin:5px; text-align:left;">
                {msg}
                <div style="font-size:10px; color:lightgray; text-align:left;">{timestamp}</div>
            </div>'''

        self.chat_area.append(bubble)
        self.chat_area.moveCursor(QTextCursor.MoveOperation.End)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    client = ChatClient()
    client.show()
    sys.exit(app.exec())
