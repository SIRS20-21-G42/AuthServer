import socket
import threading


def listen():
    """
    Start listening in the background
    """
    listener = threading.Thread(target=listen_forever, args=())
    listener.start()
    return listener


TCP_IP = '0.0.0.0'
TCP_PORT = 1337


def listen_forever():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((TCP_IP, TCP_PORT))
    s.listen()
    while True:
        conn, addr = s.accept()
        handle_connection(conn)


def handle_connection(conn):
    try:
        received = conn.recv(10)
        print("Received:", received.decode("utf-8").strip())
        conn.send(b"goodbye")
        conn.close()
    except socket.error as e:
        print("There was an error:", e)
