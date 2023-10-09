import socket
import ssl
import select
import argparse

from dataclasses import dataclass
from typing import Dict, Any


# NC SETTINGS
NC_SERVER_HOST = '192.168.254.19'
NC_SERVER_PORT = 2023
NC_AUTH_STRING = "[anonymous;127.0.0.1;tcp;0;0;;/;;]\r\n"

@dataclass
class ConnectionPair():
    """Frontend + Backend socket objects pairing"""
    ssl_sock: ssl.SSLSocket
    tcp_sock: socket.socket
    ssl_remote_client: Any

def read_from_socket_and_write(c: ConnectionPair, read_fd: int) -> bytes:
    """Read from client socket and write to connection pair"""

    # NC_SRV -> TLS CLIENT
    if c.tcp_sock.fileno() == read_fd:
        data = c.tcp_sock.recv(4096)
        c.ssl_sock.sendall(data)

    # NC_SRV <- TLS CLIENT
    else:
        data = c.ssl_sock.recv(4096)
        c.tcp_sock.sendall(data)

    return data


def main():
    parser = argparse.ArgumentParser(description='NETCONF TLS 1.3 Proxy SERVER')
    parser.add_argument('--cafile', type=str, default='server.crt', help='Path to Certificate Authority (CA) file')
    parser.add_argument('--certfile', type=str, default='lab', help='Path to TLS server certificate file')
    parser.add_argument('--keyfile', type=str, default='server.key', help='Path to TLS server private key file')
    parser.add_argument('--host', type=str, default='localhost', help='NETCONF server host')
    parser.add_argument('--port', type=int, default=3023, help='NETCONF server port')
    args = parser.parse_args()

    # FRONTEND
    # Create a raw socket for TLS connections
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_socket.bind(('0.0.0.0', 3023))
    raw_socket.listen(5)

    # Wrap raw socket with TLS
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile=args.certfile, keyfile=args.keyfile)
    ctx.load_verify_locations(cafile=args.cafile)

    ssl_socket = ctx.wrap_socket(raw_socket, server_side=True)
    ssl_socket.setblocking(0)

    # Initialize EPOLL constructs for asynchronous IO
    epoll = select.epoll()
    epoll.register(ssl_socket.fileno(), select.EPOLLIN)

    print("[+] TLS proxy listening on port 3023...")
    runserver(ssl_socket, epoll)
    

def runserver(s: ssl.SSLSocket, epoll: select.epoll) -> None:
    """Run the TLS Proxy indefinitely"""
    connections: Dict[ int, ConnectionPair ] = {}

    # RUN EVENT LOOP
    while True:
        events = epoll.poll(1)
        for fileno, event in events:

            # NEW CLIENT CONNECTION
            if fileno == s.fileno():
                
                try:
                    # TLS FRONTEND
                    ssl_sock, addr = s.accept()
                    ssl_sock.setblocking(0)
                    epoll.register(ssl_sock.fileno(), select.EPOLLIN | select.EPOLLET)
                    print(f"[+] Accepted connection from {addr[0]}:{addr[1]}")                    

                    # NETCONF TCP BACKEND + AUTH
                    nc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    nc_sock.connect((NC_SERVER_HOST, NC_SERVER_PORT))
                    nc_sock.setblocking(0)
                    epoll.register(nc_sock.fileno(), select.EPOLLIN | select.EPOLLET)
                    nc_sock.sendall(NC_AUTH_STRING.encode())

                    # ADD CONNECTION PAIRS
                    c = ConnectionPair(ssl_sock, nc_sock, addr)
                    connections[ssl_sock.fileno()] = c
                    connections[nc_sock.fileno()] = c 

                except ssl.SSLError as e:
                    if 'unsupported protocol' in str(e):
                        print(f"Ensure TLS 1.3 is supported.", e)
                    else:
                        # Handle other SSL errors
                        print("[ERROR] SSL Error:", e)

            # READ FROM CLIENT
            elif event & select.EPOLLIN:
                try:
                    while True:
                        data = read_from_socket_and_write(connections[fileno], fileno)
                        
                        # NO DATA OR EOF
                        if not data:
                            print(f"[-] Closing connection from {addr[0]}:{addr[1]}")
                            epoll.unregister(fileno)
                            c.ssl_sock.close()
                            c.tcp_sock.close()

                except socket.error:
                    pass


if __name__ == "__main__":
    main()