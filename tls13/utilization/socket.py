# -*- coding: UTF-8 -*-
import sys
import socket
from time import sleep

__all__ = [
    'ClientConnection', 'ServerConnection',
]

HOST = '127.0.0.1'  # The virtual machine ip
PORT = 4443

def host_port():
    global HOST
    global PORT
    host = input("host address:")
    HOST = host
    port = int(input("host port:"))
    assert type(port) is int
    PORT = port
    return


class ClientConnection:
    def __init__(self, host=HOST, port=PORT):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

    def send_msg(self, byte_str):
        self.sock.sendall(byte_str)

    def recv_msg(self):
        data = self.sock.recv(4096)  # TLSPlaintext 接受缓存 2^14 byte
        # print(data)
        return data
        #
        # rcv_data = b''
        # self.sock.setblocking(False)
        # self.sock.settimeout(1)
        # while True:
        #     data = b''
        #     try:
        #         data = self.sock.recv(4096)
        #         print(data)
        #         print(len(data))
        #         if len(rcv_data) < 300 and len(data) > 300:
        #             return rcv_data + data
        #         else:
        #             rcv_data = rcv_data + data
        #     except socket.timeout as e:
        #         err = e.args[0]
        #         # this next if/else is a bit redundant, but illustrates how the
        #         # timeout exception is setup
        #         rcv_data += data
        #         if err == 'timed out':
        #             # sleep(1)
        #             print('recv timed out, retry later')
        #             print(len(rcv_data))
        #             if len(rcv_data) > 730:
        #                 break
        #             continue
        #         else:
        #             print(e)
        #             sys.exit(1)
        #     except socket.error as e:
        #         # Something else happened, handle error, exit, etc.
        #         print(e)
        #         break
        #     else:
        #         if len(data) == 0:
        #             print('orderly shutdown on server end')
        #             break
        #         else:
        #             rcv_data += data
        # print(rcv_data)
        # return rcv_data
        #             # data = self.sock.recv(4096)  # TLSPlaintext 接受缓存 2^14 byte
        # # print(len(data))

class ServerConnection:
    def __init__(self, host=HOST, port=PORT, _socket=None):
        if _socket:
            self.sock = _socket
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # prevent "Address already in use" error
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((host, port))
            self.sock.listen(1)
        conn, addr = self.sock.accept()
        self.conn = conn
        self.addr = addr
        print('Connected by', self.addr)

    def send_msg(self, byte_str):
        self.conn.sendall(byte_str)

    def recv_msg(self):
        data = self.conn.recv(4096)  # TLSPlaintext 接受缓存 2^14 byte
        return data
