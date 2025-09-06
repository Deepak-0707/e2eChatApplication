import socket
import threading
import struct
import os

# ---------- Protocol Helpers ----------
def send_frame(sock, data: bytes):
    sock.sendall(struct.pack("!I", len(data)) + data)

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

# ---------- File Transfer ----------
def send_file(sock, filepath):
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    # Build header
    header = b"FIL"
    header += struct.pack("!H", len(filename))
    header += filename.encode()
    header += struct.pack("!Q", filesize)

    with open(filepath, "rb") as f:
        filedata = f.read()

    payload = header + filedata
    send_frame(sock, payload)
    print(f"[SENT FILE] {filename} ({filesize} bytes)")

def save_file(payload):
    fn_len = struct.unpack("!H", payload[:2])[0]
    filename = payload[2:2+fn_len].decode()
    filesize = struct.unpack("!Q", payload[2+fn_len:2+fn_len+8])[0]
    filedata = payload[2+fn_len+8:]

    os.makedirs("downloads", exist_ok=True)
    outpath = os.path.join("downloads", filename)
    with open(outpath, "wb") as f:
        f.write(filedata)
    print(f"[RECEIVED FILE] Saved as downloads/{filename} ({filesize} bytes)")

# ---------- Receiver ----------
def receive_loop(sock):
    while True:
        frame = recv_frame(sock)
        if not frame:
            print("[Disconnected]")
            os._exit(0)

        msg_type = frame[:3].decode()
        payload = frame[3:]

        if msg_type == "MSG":
            print(payload.decode())
        elif msg_type == "FIL":
            save_file(payload)

# ---------- Main ----------
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", 12345))

    username = input("Enter username: ")
    send_frame(sock, username.encode())

    threading.Thread(target=receive_loop, args=(sock,), daemon=True).start()

    while True:
        msg = input("> ")
        if msg.startswith("/sendfile "):
            filepath = msg.split(" ", 1)[1]
            if os.path.exists(filepath):
                send_file(sock, filepath)
            else:
                print("[!] File not found.")
        else:
            send_frame(sock, b"MSG" + msg.encode())

if __name__ == "__main__":
    main()
