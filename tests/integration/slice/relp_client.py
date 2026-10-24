"""A minimal RELP sender, used only to test relp_receiver.py itself. The slice
tests send through the product's forwarder, never through this."""

import socket
import ssl


class Client:
    def __init__(self, port, tls=None, cert=None, key=None, server_name="localhost"):
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        if tls:
            ctx = ssl.create_default_context(cafile=tls.ca)
            if cert:
                ctx.load_cert_chain(cert, key)
            s = ctx.wrap_socket(s, server_hostname=server_name)
        self.s = s
        self.buf = b""
        self.txnr = 0

    def send(self, command, data=b""):
        self.txnr += 1
        frame = b"%d %s %d" % (self.txnr, command.encode(), len(data))
        frame += (b" " + data if data else b"") + b"\n"
        self.s.sendall(frame)
        return self.txnr

    def raw(self, b):
        self.s.sendall(b)

    def _more(self):
        try:
            chunk = self.s.recv(65536)
        except (ConnectionError, ssl.SSLError, OSError):
            chunk = b""
        self.buf += chunk
        return bool(chunk)

    def _token(self):
        while True:
            for i, c in enumerate(self.buf):
                if c in b" \n":
                    tok, sep = self.buf[:i], self.buf[i:i + 1]
                    self.buf = self.buf[i + 1:]
                    return tok, sep
            if not self._more():
                return None, None

    def response(self):
        """One response frame as (txnr, command, data), or None on close."""
        txnr, _ = self._token()
        if txnr is None:
            return None
        command, _ = self._token()
        n, sep = self._token()
        if command is None or n is None:
            return None
        if sep == b"\n":
            return int(txnr), command.decode(), b""
        ln = int(n)
        while len(self.buf) < ln + 1:
            if not self._more():
                return None
        data, self.buf = self.buf[:ln], self.buf[ln + 1:]
        return int(txnr), command.decode(), data

    def open(self):
        self.send("open", b"relp_version=0\nrelp_software=a6-test\ncommands=syslog")
        return self.response()

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass
