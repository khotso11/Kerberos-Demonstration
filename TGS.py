import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

TGS_SECRET_KEY = b'\x02' * 16
SERVER_SECRET_KEY = b'\x03' * 16

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

# TGS server socket setup
tgs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tgs_socket.bind(('localhost', 10001))
tgs_socket.listen(1)
print("TGS listening on port 10001...")

conn, addr = tgs_socket.accept()
print(f"Connection established with {addr}")

try:
    # Receive client request with Ticket_tgs and Authenticator
    data = conn.recv(1024).split(b'||')
    if len(data) < 2:
        print("Error: Incomplete data received from client.")
        conn.close()
        exit(1)

    ticket_tgs = data[0]
    encrypted_authenticator = data[1]
    print(f"Received Ticket_tgs: {ticket_tgs.hex()}")

    # Decrypt Ticket_tgs with TGS secret key
    decrypted_tgt = decrypt_data(TGS_SECRET_KEY, ticket_tgs)
    print(f"Decrypted TGT: {decrypted_tgt}")

    tgt_parts = decrypted_tgt.split(b'||')
    if len(tgt_parts) < 2:
        print("Error: Decrypted TGT does not have the expected parts.")
        conn.close()
        exit(1)

    session_key_ctgs = bytes.fromhex(tgt_parts[0].decode())
    client_identity = tgt_parts[1]
    print(f"Extracted session key for C-TGS: {session_key_ctgs.hex()}")

    # Decrypt the Authenticator
    authenticator = decrypt_data(session_key_ctgs, encrypted_authenticator)
    print(f"Authenticator received and decrypted: {authenticator.decode()}")

    # Generate session key for C-V communication
    session_key_cv = os.urandom(16)
    ticket_v = f"{session_key_cv.hex()}||{client_identity}".encode()
    print(f"Ticket_v (before encryption): {ticket_v}")

    encrypted_ticket_v = encrypt_data(SERVER_SECRET_KEY, ticket_v)
    print(f"Generated and encrypted Ticket_v (for V server): {encrypted_ticket_v.hex()}")

    encrypted_session_key_cv = encrypt_data(session_key_ctgs, session_key_cv)
    print(f"Encrypted session key for C-V (for client): {encrypted_session_key_cv.hex()}")

    # Send encrypted session key and Ticket_v to client
    response_data = encrypted_session_key_cv + b'||' + encrypted_ticket_v
    conn.send(response_data)
    print("Response sent to client successfully.")

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    conn.close()
