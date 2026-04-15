import socket
import threading
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = input("Enter target IP: ")
PORT = 5000

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

# RSA Keys
private_key = None
peer_public_key = None

# AES Key
aes_key = None

def generate_rsa():
    global private_key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.public_key()

def serialize_public_key(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def load_public_key(data):
    return serialization.load_pem_public_key(data)

def encrypt_aes(message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

def decrypt_aes(data):
    raw = base64.b64decode(data)
    iv = raw[:16]
    ct = raw[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode()

def send(msg):
    sock.send(msg.encode())

def receive():
    global peer_public_key, aes_key

    while True:
        data = sock.recv(4096).decode()

        if data.startswith("PUBKEY:"):
            peer_public_key = load_public_key(data[7:].encode())
            print("[+] Received Public Key")

        elif data.startswith("AESKEY:"):
            encrypted_key = base64.b64decode(data[7:])
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None)
            )
            print("[+] AES Key Received & Decrypted")

        elif aes_key:
            print("Peer:", decrypt_aes(data))
        else:
            print("Peer:", data)

def main():
    global aes_key

    threading.Thread(target=receive).start()

    while True:
        msg = input()

        if msg == "/rsa":
            pub = generate_rsa()
            send("PUBKEY:" + serialize_public_key(pub).decode())

        elif msg == "/aes":
            aes_key = os.urandom(32)
            encrypted_key = peer_public_key.encrypt(
                aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None)
            )
            send("AESKEY:" + base64.b64encode(encrypted_key).decode())
            print("[+] AES Key Sent")

        else:
            if aes_key:
                send(encrypt_aes(msg))
            else:
                send(msg)

main()
