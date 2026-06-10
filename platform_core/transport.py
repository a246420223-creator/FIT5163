"""
Networking helpers: JSON-framed TCP socket transport.

All messages are serialised as a single JSON object followed by a newline
(\n) so the receiver knows where the frame ends.  This is intentionally
minimal — real production code would use TLS here, but for this demo the
security is provided by the SecureEnvelope layer above.
"""

import json
import socket

# Hard limits that prevent a slow or malicious peer from hanging the process.
SOCKET_TIMEOUT_SECONDS = 15
MAX_MESSAGE_BYTES = 1024 * 1024  # 1 MB — large enough for any realistic envelope


def receive_json(conn: socket.socket) -> dict:
    """Read bytes from *conn* until a newline is found, then decode as JSON."""
    data = b""

    while True:
        chunk = conn.recv(4096)

        if not chunk:
            break

        data += chunk

        if len(data) > MAX_MESSAGE_BYTES:
            raise ValueError(
                f"Incoming message size exceeded {MAX_MESSAGE_BYTES} bytes -- rejecting."
            )

        if b"\n" in data:
            break

    return json.loads(data.decode("utf-8").strip())


def send_json(conn: socket.socket, message: dict) -> None:
    """Serialise *message* as JSON and write it to *conn* with a trailing newline."""
    data = json.dumps(message).encode("utf-8") + b"\n"
    conn.sendall(data)


def send_message(host: str, port: int, message: dict) -> dict:
    """Open a TCP connection, send *message*, wait for a reply, then close."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(SOCKET_TIMEOUT_SECONDS)
        s.connect((host, port))
        send_json(s, message)
        return receive_json(s)


def start_server(host: str, port: int, handler_function) -> None:
    """
    Listen for incoming connections on *host*:*port*.

    For each connection:
      1. Read one JSON frame.
      2. Pass the decoded dict to *handler_function*.
      3. Write the returned dict back as a JSON frame.

    Transport-level errors (size exceeded, JSON decode failure, timeout) are
    caught here so a single bad connection cannot bring down the server.
    Security-level errors (tampered message, bad signature, etc.) are expected
    to be caught inside *handler_function* and returned as safe error dicts.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Allow rapid restart without "Address already in use".
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen()

        print(f"[Server] Executor listening on {host}:{port}")

        while True:
            conn, addr = s.accept()

            with conn:
                conn.settimeout(SOCKET_TIMEOUT_SECONDS)

                try:
                    request = receive_json(conn)
                    response = handler_function(request)
                    send_json(conn, response)

                except (ValueError, json.JSONDecodeError) as exc:
                    # Malformed frame — send a generic error so the peer does
                    # not hang waiting for a reply, then move on.
                    try:
                        send_json(conn, {"status": "error", "reason": "Malformed request."})
                    except Exception:
                        pass

                except socket.timeout:
                    # Peer stopped sending — nothing to reply to.
                    pass

                except Exception:
                    # Unexpected error — do not expose internals to peer.
                    try:
                        send_json(conn, {"status": "error", "reason": "Internal server error."})
                    except Exception:
                        pass
