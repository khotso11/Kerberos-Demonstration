import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

SERVER_SECRET_KEY = b'\x03' * 16

def decrypt_data(key, ciphertext):
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

# V server socket setup
v_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
v_socket.bind(('localhost', 10002))
v_socket.listen(1)
print("Server V listening on port 10002...")

conn, addr = v_socket.accept()
print(f"Connection established with {addr}")

try:
    data = conn.recv(1024).split(b'||')
    ticket_v = data[0]
    encrypted_authenticator = data[1]

    decrypted_ticket_v = decrypt_data(SERVER_SECRET_KEY, ticket_v)
    ticket_parts = decrypted_ticket_v.split(b'||')
    if len(ticket_parts) < 2:
        print("Error: Decrypted Ticket_v does not have the expected parts.")
        conn.close()
        exit(1)

    session_key_cv = bytes.fromhex(ticket_parts[0].decode())
    authenticator = decrypt_data(session_key_cv, encrypted_authenticator)

    print(f"Client is authenticated and granted access to the service.")

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    conn.close()
