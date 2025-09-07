import socket
import threading

def receive_messages(client_socket):
    while True:
        try:
            data = client_socket.recv(1024).decode()
            if not data:
                break
            print("\r" + " " * 80 + "\r", end="")
            print(data)  
        except:
            break

def send_messages(client_socket, username):
    while True:
        msg = input("")
        if msg.strip() == "":
            continue  
        client_socket.send(msg.encode())
        print("\r"+ "" * 80 +"\r", end="")

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 12345))
username = input("Enter your username: ")
client_socket.send(username.encode())

threading.Thread(target=receive_messages, args=(client_socket,),daemon=True).start()
threading.Thread(target=send_messages, args=(client_socket, username),daemon=True).start()

while True:
    pass