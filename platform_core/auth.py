from cryptography.hazmat.primitives import serialization


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