import socket
import json


def receive_json(conn):
    data = b""

    while True:
        chunk = conn.recv(4096)

        if not chunk:
            break

        data += chunk

        if b"\n" in data:
            break

    return json.loads(data.decode("utf-8").strip())


def send_json(conn, message: dict):
    data = json.dumps(message).encode("utf-8") + b"\n"
    conn.sendall(data)


def send_message(host: str, port: int, message: dict) -> dict:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        send_json(s, message)
        response = receive_json(s)

    return response


def start_server(host: str, port: int, handler_function):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()

        print(f"Executor server listening on {host}:{port}")

        while True:
            conn, addr = s.accept()

            with conn:
                request = receive_json(conn)
                response = handler_function(request)
                send_json(conn, response)