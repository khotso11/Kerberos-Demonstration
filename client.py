import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

CLIENT_SECRET_KEY = b'\x01' * 16

def encrypt_data(key, plaintext):
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def decrypt_data(key, ciphertext):
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# Connect to AS and request TGT
print("Connecting to AS to request TGT...")
as_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
as_socket.connect(('localhost', 10000))

client_identity = "client1"
print(f"Identifying to AS as: {client_identity}")
as_socket.send(client_identity.encode())

# Receive response from AS
response = as_socket.recv(1024)
response_parts = response.split(b'||')
if len(response_parts) < 2:
    print("Error: Received incomplete response from AS.")
    as_socket.close()
    exit(1)

encrypted_session_key_ctgs = response_parts[0]
ticket_tgs = response_parts[1]

# Decrypt session key for C-TGS
session_key_ctgs = decrypt_data(CLIENT_SECRET_KEY, encrypted_session_key_ctgs)
print(f"Received and decrypted session key for C-TGS: {session_key_ctgs.hex()}")

# The client cannot see or decrypt Ticket_tgs; it just forwards it
print(f"Received Ticket_tgs (client cannot decrypt): {ticket_tgs.hex()}")

as_socket.close()

# Connect to TGS and request Service Ticket
print("\nConnecting to TGS to request Service Ticket...")
tgs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tgs_socket.connect(('localhost', 10001))

timestamp = os.urandom(8)
authenticator_c = f"{client_identity}||{timestamp.hex()}".encode()
print(f"Authenticator for C-TGS (before encryption): {authenticator_c}")

encrypted_authenticator_c = encrypt_data(session_key_ctgs, authenticator_c)
print(f"Encrypted Authenticator for C-TGS: {encrypted_authenticator_c.hex()}")

print(f"Sending Ticket_tgs and Authenticator to TGS.")
tgs_socket.send(ticket_tgs + b'||' + encrypted_authenticator_c)

response = tgs_socket.recv(1024).split(b'||')
if len(response) < 2:
    print("Error: Received incomplete response from TGS.")
    tgs_socket.close()
    exit(1)

encrypted_session_key_cv = response[0]
ticket_v = response[1]

# Decrypt session key for C-V
session_key_cv = decrypt_data(session_key_ctgs, encrypted_session_key_cv)
print(f"Received and decrypted session key for C-V: {session_key_cv.hex()}")

# The client cannot see or decrypt Ticket_v; it just forwards it
print(f"Received Ticket_v (client cannot decrypt): {ticket_v.hex()}")

tgs_socket.close()

# Connect to Service Server V
print("\nConnecting to Service Server V to request access...")
v_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
v_socket.connect(('localhost', 10002))

authenticator_cv = f"{client_identity}||{timestamp.hex()}".encode()
print(f"Authenticator for C-V (before encryption): {authenticator_cv}")

encrypted_authenticator_cv = encrypt_data(session_key_cv, authenticator_cv)
print(f"Encrypted Authenticator for C-V: {encrypted_authenticator_cv.hex()}")

print(f"Sending Ticket_v and Authenticator to Server V.")
v_socket.send(ticket_v + b'||' + encrypted_authenticator_cv)

v_socket.close()
