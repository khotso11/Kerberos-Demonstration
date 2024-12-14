import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

TGS_SECRET_KEY = b'\x02' * 16
CLIENT_SECRET_KEY = b'\x01' * 16

def encrypt_data(key, plaintext):
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

# AS server socket setup
as_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
as_socket.bind(('localhost', 10000))
as_socket.listen(1)
print("AS listening on port 10000...")

conn, addr = as_socket.accept()
print(f"Connection established with {addr}")

try:
    # Receive client identity
    client_identity = conn.recv(1024).decode()
    print(f"Client Identity Received: {client_identity}")

    # Generate session key for C-TGS communication
    session_key_ctgs = os.urandom(16)
    tgt = f"{session_key_ctgs.hex()}||{client_identity}".encode()
    print(f"TGT (before encryption): {tgt}")

    # Encrypt TGT for TGS
    ticket_tgs = encrypt_data(TGS_SECRET_KEY, tgt)
    print(f"Encrypted Ticket_tgs (for TGS): {ticket_tgs.hex()}")

    # Encrypt session key for client
    encrypted_session_key = encrypt_data(CLIENT_SECRET_KEY, session_key_ctgs)
    print(f"Encrypted session key (for client): {encrypted_session_key.hex()}")

    # Send encrypted session key and Ticket_tgs to client
    response_data = encrypted_session_key + b'||' + ticket_tgs
    conn.send(response_data)
    print("Response sent to client successfully.")

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    conn.close()
