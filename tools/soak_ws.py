#!/usr/bin/env python3
"""soak_ws.py — one long-lived WebSocket client for the rook soak.

Hand-rolled on the standard library so the soak's only pip dependency is
the h2 module the burst tool needs. Connects over TLS, sends a masked text
frame every --interval seconds, expects the echo back, and reconnects when
the connection ends — rook's websocket_max_lifetime deliberately rotates
tunnels, so a clean close is part of the test, not a failure. Every event
is one stdout line for the soak log.

Usage: soak_ws.py --host smoke.rookserver.app --port 443 --path /ws \
           --interval 5 --duration 3600
"""

import argparse
import base64
import os
import socket
import ssl
import struct
import sys
import time


def log(message):
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), message, flush=True)


def read_exactly(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("connection closed mid-frame")
        data += chunk
    return data


def send_text(sock, payload):
    # Client frames must be masked (RFC 6455 §5.3).
    mask = os.urandom(4)
    body = payload.encode()
    length = len(body)
    if length < 126:
        header = struct.pack("!BB", 0x81, 0x80 | length)
    elif length < 65536:
        header = struct.pack("!BBH", 0x81, 0x80 | 126, length)
    else:
        header = struct.pack("!BBQ", 0x81, 0x80 | 127, length)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(body))
    sock.sendall(header + mask + masked)


def recv_frame(sock):
    """Returns (opcode, payload). Raises on close/EOF."""
    first, second = read_exactly(sock, 2)
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        (length,) = struct.unpack("!H", read_exactly(sock, 2))
    elif length == 127:
        (length,) = struct.unpack("!Q", read_exactly(sock, 8))
    payload = read_exactly(sock, length) if length else b""
    return opcode, payload


def send_pong(sock, payload):
    # Control-frame reply to a server ping; masked like any client frame.
    mask = os.urandom(4)
    header = struct.pack("!BB", 0x8A, 0x80 | len(payload))
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(header + mask + masked)


def recv_echo(sock):
    """Read until the echoed text frame, answering control frames."""
    while True:
        opcode, payload = recv_frame(sock)
        if opcode == 0x8:
            return None  # close
        if opcode == 0x9:
            send_pong(sock, payload)  # ping -> pong
            continue
        if opcode == 0xA:
            continue  # pong
        if opcode != 0x1:
            raise ConnectionError(f"unexpected opcode {opcode}")
        return payload


def handshake(sock, host, path):
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(request.encode())
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("connection closed during handshake")
        response += chunk
    status = response.split(b"\r\n", 1)[0]
    if b" 101 " not in status:
        raise ConnectionError(f"upgrade refused: {status.decode(errors='replace')}")


def run_session(host, port, path, interval, deadline, dial):
    context = ssl.create_default_context()
    raw = socket.create_connection((dial, port), timeout=10)
    with context.wrap_socket(raw, server_hostname=host) as sock:
        handshake(sock, host, path)
        log("connected")
        echoes = 0
        while time.time() < deadline:
            send_text(sock, "soak")
            if recv_echo(sock) is None:
                log("closed by peer (clean rotation)")
                return echoes
            echoes += 1
            time.sleep(interval)
        return echoes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", default="/ws")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--connect", default="127.0.0.1",
                        help="address to dial; SNI/Host stay --host")
    parser.add_argument("--duration", type=int, default=3600)
    args = parser.parse_args()

    deadline = time.time() + args.duration
    sessions = 0
    echoes = 0
    while time.time() < deadline:
        try:
            echoes += run_session(
                args.host, args.port, args.path, args.interval, deadline, args.connect)
            sessions += 1
        except (ConnectionError, OSError, ssl.SSLError) as error:
            # A refused reconnect mid-soak is worth one line; the verdict
            # still comes from rook's own metrics.
            log(f"session error: {error}")
            time.sleep(5)
    log(f"done sessions={sessions} echoes={echoes}")


if __name__ == "__main__":
    sys.exit(main())
