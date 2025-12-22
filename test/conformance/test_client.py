#!/usr/bin/env python3
"""Simple test client for JAM conformance target"""

import socket
import struct
import sys

SOCKET_PATH = "/tmp/jam_target.sock"

def send_message(sock, data):
    """Send length-prefixed message"""
    sock.sendall(struct.pack('<I', len(data)))
    sock.sendall(data)

def recv_message(sock):
    """Receive length-prefixed message"""
    len_data = sock.recv(4)
    if len(len_data) < 4:
        return None
    msg_len = struct.unpack('<I', len_data)[0]
    data = b''
    while len(data) < msg_len:
        chunk = sock.recv(msg_len - len(data))
        if not chunk:
            return None
        data += chunk
    return data

def create_peer_info():
    """Create a PeerInfo message"""
    msg = bytearray()
    msg.append(0x00)  # MSG_PEER_INFO
    msg.append(0x01)  # fuzz_version
    msg.extend(struct.pack('<I', 0x02))  # features (FORKS)
    msg.append(0x00)  # jam_version.major
    msg.append(0x07)  # jam_version.minor
    msg.append(0x00)  # jam_version.patch
    msg.append(0x00)  # app_version.major
    msg.append(0x01)  # app_version.minor
    msg.append(0x00)  # app_version.patch
    name = b"test_client"
    msg.append(len(name))
    msg.extend(name)
    return bytes(msg)

def main():
    print(f"Connecting to {SOCKET_PATH}...")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(SOCKET_PATH)
        print("Connected!")

        # Send PeerInfo
        peer_info = create_peer_info()
        print(f"Sending PeerInfo ({len(peer_info)} bytes)...")
        send_message(sock, peer_info)

        # Receive response
        response = recv_message(sock)
        if response:
            print(f"Got response ({len(response)} bytes)")
            print(f"  Discriminant: 0x{response[0]:02x}")
            if response[0] == 0x00:
                print("  Got PeerInfo response")
                # Parse app_name
                name_len = response[11]
                app_name = response[12:12+name_len].decode('utf-8')
                print(f"  App name: {app_name}")
                print("SUCCESS: Handshake completed!")
        else:
            print("No response received")
            return 1

    except FileNotFoundError:
        print(f"Socket not found. Is the target running?")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1
    finally:
        sock.close()

    return 0

if __name__ == '__main__':
    sys.exit(main())
