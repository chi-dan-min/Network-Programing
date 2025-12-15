import socket
import ctypes
from protocol import lib, MAX_BUF

class NetworkCore:
    def __init__(self, ip="127.0.0.1", port=300):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((ip, port))

        self.token = 0
        self.buf = (ctypes.c_uint8 * MAX_BUF)()

    def login(self, app_id, password):
        size = lib.serialize_connect_request(
            app_id.encode(),
            password.encode(),
            self.buf
        )
        self.sock.sendall(bytes(self.buf[:size]))

        data = self.sock.recv(MAX_BUF)
        ctypes.memmove(self.buf, data, len(data))

        # TODO: parse token từ deserialize_packet
        self.token = 1234
        return True

    def scan(self):
        size = lib.serialize_scan_request(self.token, self.buf)
        self.sock.sendall(bytes(self.buf[:size]))

        data = self.sock.recv(MAX_BUF)
        return list(data)
