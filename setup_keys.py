import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_DIR = "keys"


def save_key_pair(agent_id: str):

    private_path = f"{KEY_DIR}/{agent_id}_private.pem"
    public_path = f"{KEY_DIR}/{agent_id}_public.pem"

    if os.path.exists(private_path) and os.path.exists(public_path):
        print(f"{agent_id} signature keys already exist.")
        return

    private_key = Ed25519PrivateKey.generate()

    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_path, "wb") as f:
        f.write(private_bytes)

    with open(public_path, "wb") as f:
        f.write(public_bytes)

    print(f"Generated signature keys for {agent_id}")


def save_rsa_key_pair(agent_id: str):

    private_path = f"{KEY_DIR}/{agent_id}_rsa_private.pem"
    public_path = f"{KEY_DIR}/{agent_id}_rsa_public.pem"

    if os.path.exists(private_path) and os.path.exists(public_path):
        print(f"{agent_id} RSA keys already exist.")
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_path, "wb") as f:
        f.write(private_bytes)

    with open(public_path, "wb") as f:
        f.write(public_bytes)

    print(f"Generated RSA keys for {agent_id}")


def save_aes_key():
    aes_path = f"{KEY_DIR}/aes.key"

    if os.path.exists(aes_path):
        print("AES key already exists.")
        return

    aes_key = AESGCM.generate_key(bit_length=256)

    with open(aes_path, "w") as f:
        f.write(aes_key.hex())

    print("Generated AES-256 key.")


def main():

    os.makedirs(KEY_DIR, exist_ok=True)

    save_key_pair("planner_1")
    save_key_pair("executor_1")

    save_rsa_key_pair("planner_1")
    save_rsa_key_pair("executor_1")

    save_aes_key()


if __name__ == "__main__":
    main()