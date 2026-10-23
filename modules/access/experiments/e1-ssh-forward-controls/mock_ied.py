#!/usr/bin/env python3
"""Mock line-oriented IED service for experiment E1. Not a device simulator.

It accepts any line, answers "READ ..." and "WRITE ..." alike, and records
every connection and every line it receives to a JSON-lines log so the
experiment can prove what did or did not reach the "device".

Usage: mock_ied.py <bind_host> <bind_port> <name> <log_path>
"""
import json
import socketserver
import sys
import time


def main() -> None:
    host, port, name, log_path = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

    def log(record: dict) -> None:
        record.update({"ied": name, "t": time.time()})
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            peer = "%s:%d" % self.client_address
            log({"event": "connect", "peer": peer})
            for raw in self.rfile:
                line = raw.decode("utf-8", "replace").strip()
                log({"event": "line", "peer": peer, "line": line})
                verb = line.split(" ", 1)[0].upper()
                reply = {"READ": "OK DATA", "WRITE": "OK WRITTEN"}.get(verb, "ERR UNKNOWN")
                self.wfile.write((reply + "\n").encode())
            log({"event": "disconnect", "peer": peer})

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((host, port), Handler) as srv:
        srv.daemon_threads = True
        srv.serve_forever()


if __name__ == "__main__":
    main()
