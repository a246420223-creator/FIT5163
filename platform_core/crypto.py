from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def load_aes_key(path: str) -> bytes:
    try:
        with open(path, "r") as f:
            return bytes.fromhex(f.read().strip())
    except FileNotFoundError:
        raise FileNotFoundError(
            f"AES key file not found: {path}\n"
            f"  Run 'python setup_keys.py' to generate all required key files."
        )


def encrypt_message(key: bytes, plaintext: bytes, aad: bytes) -> dict:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    print("[AES-GCM] Encrypting payload...")
    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        aad
    )

    return {
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }


def decrypt_message(key: bytes, nonce_hex: str, ciphertext_hex: str, aad: bytes) -> bytes:
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    aesgcm = AESGCM(key)
    print("[AES-GCM] Decrypting payload...")
    return aesgcm.decrypt(
        nonce,
        ciphertext,
        aad
    )