from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def load_private_key(path: str):

    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


def load_public_key(path: str):

    with open(path, "rb") as f:
        return serialization.load_pem_public_key(
            f.read()
        )


def sign_data(private_key, data: bytes) -> str:

    signature = private_key.sign(data)

    return signature.hex()


def verify_signature(public_key, signature_hex: str, data: bytes) -> bool:

    try:
        signature = bytes.fromhex(signature_hex)

        public_key.verify(signature, data)

        return True

    except Exception:
        return False


def rsa_encrypt(public_key, data: bytes) -> str:
    print("[RSA] Encrypting shared AES key...")
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext.hex()


def rsa_decrypt(private_key, ciphertext_hex: str) -> bytes:
    print("[RSA] Decrypting shared AES key...")
    ciphertext = bytes.fromhex(ciphertext_hex)

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext