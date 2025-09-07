import socket
import threading
import struct
import os

clients = {}

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

# ---------- Broadcast ----------
def broadcast(sender, data: bytes):
    for conn in list(clients.keys()):
        if conn is sender:
            continue
        try:
            send_frame(conn, data)
        except:
            conn.close()
            clients.pop(conn, None)

# ---------- Handle Client ----------
def handle_client(conn, addr):
    username = recv_frame(conn).decode()
    clients[conn] = username
    print(f"{username} joined from {addr}")
    broadcast(conn, b"MSG" + f"📢 {username} has joined!".encode())

    while True:
        frame = recv_frame(conn)
        if not frame:
            break

        msg_type = frame[:3].decode()
        payload = frame[3:]

        if msg_type == "MSG":
            text = payload.decode()
            print(f"{username}: {text}")
            broadcast(conn, b"MSG" + f"{username}: {text}".encode())

        elif msg_type == "FIL":
            fn_len = struct.unpack("!H", payload[:2])[0]
            filename = payload[2:2+fn_len].decode()
            filesize = struct.unpack("!Q", payload[2+fn_len:2+fn_len+8])[0]
            filedata = payload[2+fn_len+8:]

            # Save file on server
            os.makedirs("server_files", exist_ok=True)
            save_path = os.path.join("server_files", filename)
            with open(save_path, "wb") as f:
                f.write(filedata)
            print(f"[FILE] {username} uploaded {filename} ({filesize} bytes)")

            # Now rebroadcast to all other clients
            broadcast(conn, frame)

    left_user = clients.pop(conn, "Unknown")
    broadcast(None, b"MSG" + f"📢 {left_user} has left.".encode())
    conn.close()

# ---------- Main ----------
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 12345))
    server.listen()
    print("[*] Server running...")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
