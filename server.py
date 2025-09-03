import socket
import threading

clients = {} 
def handle_client(conn, addr):
    username = conn.recv(1024).decode()
    clients[conn] = username
    print(f"{username} joined from {addr}")
    broadcast(f"📢 {username} has joined the chat!")
    while True:
        try:
            data = conn.recv(1024).decode()
            if not data:
                break
            print(f"{username}: {data}")
            broadcast(f"{username}: {data}")
        except:
            break
    conn.close()
    left_user = clients.pop(conn, "Unknown")
    broadcast(f"📢 {left_user} has left the chat.")
def broadcast(message):
    for client in list(clients.keys()):
        try:
            client.send(message.encode())
        except:
            client.close()
            del clients[client]
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 12345))
server_socket.listen()
print("Server is running and relaying messages...")
while True:
    conn, addr = server_socket.accept()
    thread = threading.Thread(target=handle_client, args=(conn, addr))
    thread.start()
