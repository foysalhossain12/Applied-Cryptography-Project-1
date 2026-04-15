#!/usr/bin/env python3
"""
CSE722 Project 1 - Encrypted Chat Application
Implements: RSA key exchange + AES-256 encrypted messaging over TCP
"""

import socket
import threading
import os
import json
import base64
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ─── Crypto Helpers ────────────────────────────────────────────────────────────

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    return private_key, private_key.public_key()

def serialize_public_key(pub_key):
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())

def rsa_encrypt(pub_key, data: bytes) -> bytes:
    return pub_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(priv_key, ciphertext: bytes) -> bytes:
    return priv_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_sign(priv_key, data: bytes) -> bytes:
    return priv_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_verify(pub_key, data: bytes, signature: bytes) -> bool:
    try:
        pub_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def aes_encrypt(aes_key: bytes, plaintext: str) -> dict:
    """AES-256-CBC encrypt. Returns dict with iv + ciphertext + hmac (base64)."""
    iv = os.urandom(16)
    # Pad plaintext to block size
    data = plaintext.encode()
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(data) + enc.finalize()

    # HMAC for integrity
    mac = hmac.new(aes_key, iv + ciphertext, hashlib.sha256).digest()

    return {
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ciphertext).decode(),
        "mac": base64.b64encode(mac).decode()
    }

def aes_decrypt(aes_key: bytes, payload: dict) -> str:
    """AES-256-CBC decrypt. Verifies HMAC first."""
    iv = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["ct"])
    mac_received = base64.b64decode(payload["mac"])

    # Verify HMAC (integrity + authenticity)
    mac_expected = hmac.new(aes_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac_received, mac_expected):
        raise ValueError("HMAC verification failed! Message may be tampered.")

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len].decode()

# ─── Message framing ────────────────────────────────────────────────────────────

def send_msg(sock, msg_type: str, payload: dict):
    """Send a length-prefixed JSON message."""
    msg = json.dumps({"type": msg_type, "payload": payload}).encode()
    length = len(msg).to_bytes(4, "big")
    sock.sendall(length + msg)

def recv_msg(sock) -> dict:
    """Receive a length-prefixed JSON message."""
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return None
    length = int.from_bytes(raw_len, "big")
    data = _recv_exact(sock, length)
    return json.loads(data.decode())

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

# ─── Chat Client ───────────────────────────────────────────────────────────────

class ChatClient:
    def __init__(self, conn: socket.socket, peer_addr: str):
        self.conn = conn
        self.peer_addr = peer_addr
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.aes_key = None
        self.encrypted_mode = False
        self.lock = threading.Lock()

    def print_status(self, msg):
        print(f"\n[*] {msg}")

    def print_msg(self, sender, text, encrypted=False):
        tag = "🔒 ENCRYPTED" if encrypted else "📨 PLAINTEXT"
        print(f"\n[{tag}] {sender}: {text}")

    def start_receive_thread(self):
        t = threading.Thread(target=self.receive_loop, daemon=True)
        t.start()

    def receive_loop(self):
        while True:
            try:
                msg = recv_msg(self.conn)
                if msg is None:
                    self.print_status("Peer disconnected.")
                    break
                self.handle_message(msg)
            except Exception as e:
                self.print_status(f"Receive error: {e}")
                break

    def handle_message(self, msg: dict):
        t = msg["type"]
        p = msg["payload"]

        if t == "CHAT_PLAIN":
            self.print_msg("Peer", p["text"], encrypted=False)

        elif t == "CHAT_ENCRYPTED":
            if not self.aes_key:
                self.print_status("Received encrypted message but no AES key yet!")
                return
            try:
                text = aes_decrypt(self.aes_key, p)
                self.print_msg("Peer", text, encrypted=True)
            except ValueError as e:
                self.print_status(f"Decryption failed: {e}")

        elif t == "PUBLIC_KEY":
            # Receive peer's public key
            pem = base64.b64decode(p["pem"])
            self.peer_public_key = deserialize_public_key(pem)
            self.print_status("Received peer's RSA public key!")

            # If we haven't sent ours yet, generate and send back
            if self.private_key is None:
                self.private_key, self.public_key = generate_rsa_keypair()
                my_pem = serialize_public_key(self.public_key)
                send_msg(self.conn, "PUBLIC_KEY", {
                    "pem": base64.b64encode(my_pem).decode()
                })
                self.print_status("Sent our RSA public key back.")

        elif t == "AES_KEY_EXCHANGE":
            # Receive AES key encrypted with our public key + signed by peer
            encrypted_key = base64.b64decode(p["encrypted_key"])
            signature = base64.b64decode(p["signature"])

            # Verify signature (authenticity)
            if not rsa_verify(self.peer_public_key, encrypted_key, signature):
                self.print_status("❌ AES key signature INVALID! Rejecting.")
                return

            # Decrypt the AES key (confidentiality)
            self.aes_key = rsa_decrypt(self.private_key, encrypted_key)
            self.encrypted_mode = True
            self.print_status("✅ AES-256 key received and verified! Encrypted mode ON.")

    def exchange_public_keys(self):
        if self.private_key is None:
            self.private_key, self.public_key = generate_rsa_keypair()
        my_pem = serialize_public_key(self.public_key)
        send_msg(self.conn, "PUBLIC_KEY", {
            "pem": base64.b64encode(my_pem).decode()
        })
        self.print_status("Sent our RSA public key. Waiting for peer's...")

    def exchange_aes_key(self):
        if self.peer_public_key is None:
            self.print_status("Exchange RSA public keys first!")
            return
        if self.private_key is None:
            self.print_status("We don't have our RSA key pair yet!")
            return

        # Generate AES-256 key (32 bytes)
        self.aes_key = os.urandom(32)

        # Encrypt with peer's public key (confidentiality)
        encrypted_key = rsa_encrypt(self.peer_public_key, self.aes_key)

        # Sign with our private key (authenticity + integrity)
        signature = rsa_sign(self.private_key, encrypted_key)

        send_msg(self.conn, "AES_KEY_EXCHANGE", {
            "encrypted_key": base64.b64encode(encrypted_key).decode(),
            "signature": base64.b64encode(signature).decode()
        })
        self.encrypted_mode = True
        self.print_status("✅ AES-256 key generated and sent securely! Encrypted mode ON.")

    def send_chat(self, text: str):
        if self.encrypted_mode and self.aes_key:
            payload = aes_encrypt(self.aes_key, text)
            send_msg(self.conn, "CHAT_ENCRYPTED", payload)
            self.print_msg("You", text, encrypted=True)
        else:
            send_msg(self.conn, "CHAT_PLAIN", {"text": text})
            self.print_msg("You", text, encrypted=False)

    def run_ui(self):
        print("\n" + "="*60)
        print("  CSE722 - Encrypted Chat Application")
        print("="*60)
        print("Commands:")
        print("  /keys   - Exchange RSA public keys")
        print("  /aes    - Exchange AES-256 secret key")
        print("  /status - Show current crypto status")
        print("  /quit   - Exit")
        print("  (anything else) - Send message")
        print("="*60 + "\n")

        self.start_receive_thread()

        while True:
            try:
                user_input = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not user_input:
                continue

            if user_input == "/keys":
                self.exchange_public_keys()
            elif user_input == "/aes":
                self.exchange_aes_key()
            elif user_input == "/status":
                print(f"  RSA key pair: {'✅ Generated' if self.private_key else '❌ Not generated'}")
                print(f"  Peer RSA key: {'✅ Received' if self.peer_public_key else '❌ Not received'}")
                print(f"  AES-256 key:  {'✅ Active' if self.aes_key else '❌ Not set'}")
                print(f"  Mode:         {'🔒 ENCRYPTED' if self.encrypted_mode else '📨 PLAINTEXT'}")
            elif user_input == "/quit":
                break
            else:
                self.send_chat(user_input)

        print("Goodbye!")
        self.conn.close()


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("CSE722 Encrypted Chat - Choose mode:")
    print("  1. Server (wait for connection)")
    print("  2. Client (connect to peer)")
    mode = input("Enter 1 or 2: ").strip()

    if mode == "1":
        port = int(input("Enter port to listen on (e.g. 9000): ").strip())
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", port))
        server_sock.listen(1)
        print(f"[*] Listening on port {port}... waiting for peer.")
        conn, addr = server_sock.accept()
        print(f"[*] Connected to {addr[0]}:{addr[1]}")
        client = ChatClient(conn, f"{addr[0]}:{addr[1]}")

    elif mode == "2":
        peer_ip = input("Enter peer IP address: ").strip()
        peer_port = int(input("Enter peer port: ").strip())
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((peer_ip, peer_port))
        print(f"[*] Connected to {peer_ip}:{peer_port}")
        client = ChatClient(conn, f"{peer_ip}:{peer_port}")

    else:
        print("Invalid mode.")
        return

    client.run_ui()

if __name__ == "__main__":
    main()
