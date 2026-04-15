# CSE722 Project 1 — Encrypted Chat Application

A peer-to-peer encrypted chat application implementing:
- **RSA-2048** public key exchange
- **AES-256-CBC** encrypted messaging
- **HMAC-SHA256** for message integrity
- **RSA-PSS signature** for authenticity of the AES key

---

## Requirements

- Python 3.8+
- Install dependency:

```bash
pip install cryptography
```

---

## How to Run

### Step 1 — Start the Server (Machine A)

```bash
python chat.py
```

Choose option **1** (Server), then enter a port number, e.g. `9000`.

```
Enter 1 or 2: 1
Enter port to listen on (e.g. 9000): 9000
[*] Listening on port 9000... waiting for peer.
```

### Step 2 — Start the Client (Machine B)

```bash
python chat.py
```

Choose option **2** (Client), then enter the IP and port of Machine A.

```
Enter 1 or 2: 2
Enter peer IP address: 192.168.1.10
Enter peer port: 9000
[*] Connected to 192.168.1.10:9000
```

---

## Chat Commands

| Command   | Description                              |
|-----------|------------------------------------------|
| `/keys`   | Exchange RSA-2048 public keys            |
| `/aes`    | Exchange AES-256 secret key (securely)  |
| `/status` | Show current crypto status               |
| `/quit`   | Exit the chat                            |
| (text)    | Send a message (plain or encrypted)      |

---

## Step-by-Step Usage

### Phase 1: Plain Text Chat (Step iii of spec)

Just type messages — they are sent in plaintext. Capture with Wireshark to see them readable.

### Phase 2: Exchange RSA Public Keys (Step iv)

On **one client**, type:
```
/keys
```
This generates an RSA-2048 key pair and sends the public key. The other client automatically responds with its own public key.

### Phase 3: Exchange AES-256 Key (Step v)

On **the same client** that initiated `/keys`, type:
```
/aes
```
This generates a random AES-256 key, encrypts it with the peer's RSA public key (confidentiality), signs it with our RSA private key (authenticity + integrity), and sends it. The other client verifies the signature before accepting the key.

### Phase 4: Encrypted Chat (Step vi)

Now just type messages — they are automatically AES-256 encrypted. Capture with Wireshark to see they are no longer readable.

---

## Cryptographic Protocol Design

```
CLIENT A                                CLIENT B
   |                                       |
   |--- CHAT_PLAIN {text} -------------->  |   (Step iii: plaintext)
   |  <-- CHAT_PLAIN {text} -------------- |
   |                                       |
   |--- PUBLIC_KEY {pem_A} ------------>   |   (Step iv: key exchange)
   |  <-- PUBLIC_KEY {pem_B} ------------- |
   |                                       |
   |   A generates AES-256 key K           |
   |   encrypted_K = RSA_Encrypt(pub_B, K) |
   |   sig = RSA_Sign(priv_A, encrypted_K) |
   |--- AES_KEY_EXCHANGE {                 |   (Step v: AES key exchange)
   |      encrypted_key, signature} -----> |
   |                                       |   B verifies sig with pub_A
   |                                       |   B decrypts with priv_B → K
   |                                       |
   |--- CHAT_ENCRYPTED {iv, ct, mac} --->  |   (Step vi: encrypted chat)
   |  <-- CHAT_ENCRYPTED {iv, ct, mac} --- |
```

### Security Properties Satisfied

| Property      | Mechanism                                    |
|---------------|----------------------------------------------|
| Confidentiality | AES-256-CBC encryption of messages; RSA-OAEP encryption of AES key |
| Integrity     | HMAC-SHA256 over each encrypted message      |
| Authenticity  | RSA-PSS digital signature on the AES key     |

---

## Capturing Traffic with Wireshark

1. Open Wireshark and select your network interface.
2. Filter: `tcp.port == 9000` (replace with your port)
3. Send a plaintext message → You will see the text in clear in the packet payload.
4. After `/keys` and `/aes`, send an encrypted message → The payload will appear as random bytes.

---

## Libraries Used

- [`cryptography`](https://cryptography.io/en/latest/) — RSA, AES, HMAC primitives (Apache 2.0 License)
- Python standard library: `socket`, `threading`, `json`, `os`, `hashlib`, `hmac`, `base64`

---

## GitHub Repository

Upload this project to a GitHub repository and include the link in your report.

---

## References

- Cryptography library docs: https://cryptography.io/en/latest/
- RSA-OAEP: PKCS#1 v2.2
- AES-CBC + HMAC pattern (Encrypt-then-MAC): https://en.wikipedia.org/wiki/Authenticated_encryption
- Assisted with Claude (Anthropic) for code generation and protocol design

