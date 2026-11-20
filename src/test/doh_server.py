#!/usr/bin/env python3
"""Local DNS-over-HTTPS (RFC 8484) server used by dnsperf tests.

Implements a minimal, dependency-light HTTP/2 DoH endpoint using the
``h2`` library.  Every received DNS message is answered with a synthetic
NOERROR response that keeps the question section and the original query
id, so dnsperf can match and complete the outstanding queries.

Optional special paths make it possible to exercise the client's HTTP
status code and content-type handling:

  /http-error   -> answers every request with HTTP 500
  /not-dns      -> answers with HTTP 200 but a non-DNS content type

The number of handled requests is tracked per connection and printed on
stderr when the server terminates.
"""

import argparse
import base64
import signal
import socket
import ssl
import struct
import sys
import threading
from urllib.parse import urlparse, parse_qs

try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.exceptions
except ImportError:
    sys.stderr.write("python3 h2 module is required, install python3-h2\n")
    sys.exit(2)


DNS_RA = 0x0080


def build_dns_response(query):
    """Return a minimal NOERROR response for the given DNS query bytes."""
    if len(query) < 12:
        return query
    txid, flags, qd = struct.unpack("!HHH", query[:6])
    # Reflect the question section back, answer/authority/additional stay 0.
    response_flags = (flags | 0x8000 | DNS_RA) & ~0x0010
    header = struct.pack("!HHHHHH", txid, response_flags, qd, 0, 0, 0)
    return header + query[12:]


def extract_dns_message(headers, body):
    """Extract the DNS message from a GET or POST DoH request."""
    headers = {name.lower(): value for name, value in headers}
    method = headers.get(":method")
    if method == "POST":
        return bytes(body)
    if method == "GET":
        path = headers.get(":path", "/")
        query = parse_qs(urlparse(path).query)
        encoded = query.get("dns", [None])[0]
        if encoded is None:
            return None
        padding = "=" * (-len(encoded) % 4)
        return base64.urlsafe_b64decode(encoded + padding)
    return None


class DoHConnection:
    """One HTTP/2 DoH connection backed by an h2.H2Connection."""

    def __init__(self, tls_sock, stats):
        self.sock = tls_sock
        self.stats = stats
        config = h2.config.H2Configuration(
            client_side=False, header_encoding="utf-8")
        self.conn = h2.connection.H2Connection(config=config)
        self.request_headers = {}
        self.bodies = {}
        self.pending = []

    def sendall(self, data):
        while data:
            sent = self.sock.send(data)
            if sent == 0:
                raise ConnectionError("socket closed")
            data = data[sent:]

    def respond(self, stream_id, body, status="200",
                content_type="application/dns-message"):
        self.conn.send_headers(stream_id, [
            (":status", status),
            ("content-type", content_type),
            ("content-length", str(len(body))),
        ])
        try:
            self.conn.send_data(stream_id, body, end_stream=True)
        except h2.exceptions.FlowControlError:
            self.pending.append((stream_id, body))
        self.sendall(self.conn.data_to_send())

    def flush_pending(self):
        remaining = []
        for stream_id, body in self.pending:
            try:
                self.conn.send_data(stream_id, body, end_stream=True)
            except h2.exceptions.FlowControlError:
                remaining.append((stream_id, body))
        self.pending = remaining
        self.sendall(self.conn.data_to_send())

    def handle_request(self, stream_id, headers):
        header_map = {name.lower(): value for name, value in headers}
        path = header_map.get(":path", "/")
        message = extract_dns_message(
            headers, self.bodies.pop(stream_id, b""))
        if message is None:
            self.respond(stream_id, b"", status="400")
            self.stats["errors"] += 1
            return

        self.stats["requests"] += 1
        if path.startswith("/http-error"):
            self.respond(stream_id, b"error", status="500")
            self.stats["http_error"] += 1
        elif path.startswith("/not-dns"):
            self.respond(stream_id, b"not dns",
                         content_type="text/plain")
            self.stats["not_dns"] += 1
        else:
            self.respond(stream_id, build_dns_response(message))
            self.stats["dns"] += 1

    def serve(self):
        self.conn.initiate_connection()
        self.sendall(self.conn.data_to_send())
        while True:
            data = self.sock.recv(65535)
            if not data:
                break
            events = self.conn.receive_data(data)
            for event in events:
                if isinstance(event, h2.events.RequestReceived):
                    self.request_headers[event.stream_id] = event.headers
                    self.bodies[event.stream_id] = b""
                elif isinstance(event, h2.events.DataReceived):
                    self.bodies[event.stream_id] += event.data
                    self.conn.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    headers = self.request_headers.pop(event.stream_id, [])
                    self.handle_request(event.stream_id, headers)
                elif isinstance(event, h2.events.WindowUpdated):
                    self.flush_pending()
                elif isinstance(event, (h2.events.ConnectionTerminated,
                                        h2.events.StreamReset)):
                    self.sendall(self.conn.data_to_send())
                    return
            self.sendall(self.conn.data_to_send())


def handle_client(sock, certfile, keyfile, stats):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    if hasattr(context, "set_alpn_protocols"):
        context.set_alpn_protocols(["h2"])
    else:
        context.set_alpn_protos(["h2"])
    try:
        tls_sock = context.wrap_socket(sock, server_side=True)
    except (ssl.SSLError, OSError):
        sock.close()
        return

    if tls_sock.selected_alpn_protocol() != "h2":
        tls_sock.close()
        return

    try:
        DoHConnection(tls_sock, stats).serve()
    except (ConnectionError, OSError, ssl.SSLError,
            h2.exceptions.ProtocolError):
        pass
    finally:
        try:
            tls_sock.close()
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description="Local DoH test server")
    parser.add_argument("address", help="bind address")
    parser.add_argument("port", type=int, help="bind port")
    parser.add_argument("keyfile", help="TLS private key")
    parser.add_argument("certfile", help="TLS certificate")
    args = parser.parse_args()

    stats = {"requests": 0, "dns": 0, "http_error": 0,
             "not_dns": 0, "errors": 0}
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.address, args.port))
    server.listen(16)

    def report(_signum, _frame):
        sys.stderr.write(
            "doh_server: requests=%d dns=%d http_error=%d "
            "not_dns=%d errors=%d\n" % (
                stats["requests"], stats["dns"], stats["http_error"],
                stats["not_dns"], stats["errors"]))
        sys.exit(0)

    signal.signal(signal.SIGTERM, report)
    signal.signal(signal.SIGINT, report)

    while True:
        try:
            client, _address = server.accept()
        except OSError:
            break
        thread = threading.Thread(
            target=handle_client,
            args=(client, args.certfile, args.keyfile, stats),
            daemon=True)
        thread.start()


if __name__ == "__main__":
    main()
