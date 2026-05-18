import json
from platform_core.message_schema import Message, SecureEnvelope
from platform_core.crypto import encrypt_message, decrypt_message
from platform_core.auth import sign_data, verify_signature
from platform_core.logger import log_event
from platform_core.transport import send_message


class SecurePlatform:
    def __init__(self, agent_id: str, aes_key: bytes, private_key, public_keys: dict):
        self.agent_id = agent_id
        self.aes_key = aes_key
        self.private_key = private_key
        self.public_keys = public_keys

    def _aad(self, sender: str, receiver: str) -> bytes:
        return f"{sender}->{receiver}".encode("utf-8")

    def _signature_data(self, envelope: dict) -> bytes:
        data = {
            "message_id": envelope["message_id"],
            "sender": envelope["sender"],
            "receiver": envelope["receiver"],
            "nonce": envelope["nonce"],
            "ciphertext": envelope["ciphertext"]
        }

        return json.dumps(data, sort_keys=True).encode("utf-8")

    def secure_wrap(self, message: Message) -> dict:
        plaintext = message.model_dump_json().encode("utf-8")

        encrypted = encrypt_message(
            key=self.aes_key,
            plaintext=plaintext,
            aad=self._aad(message.sender, message.receiver)
        )

        envelope = {
            "message_id": message.message_id,
            "sender": message.sender,
            "receiver": message.receiver,
            "nonce": encrypted["nonce"],
            "ciphertext": encrypted["ciphertext"],
            "signature": None
        }

        signature = sign_data(
            self.private_key,
            self._signature_data(envelope)
        )

        envelope["signature"] = signature

        log_event(f"{message.sender} encrypted and signed message {message.message_id}")

        return envelope

    def secure_unwrap(self, envelope_data: dict) -> Message:
        envelope = SecureEnvelope(**envelope_data)

        if envelope.sender not in self.public_keys:
            raise ValueError(f"Unknown sender: {envelope.sender}")

        signature_valid = verify_signature(
            public_key=self.public_keys[envelope.sender],
            signature_hex=envelope.signature,
            data=self._signature_data(envelope.model_dump())
        )

        if not signature_valid:
            raise ValueError("Invalid digital signature. Message may be fake or tampered.")

        plaintext = decrypt_message(
            key=self.aes_key,
            nonce_hex=envelope.nonce,
            ciphertext_hex=envelope.ciphertext,
            aad=self._aad(envelope.sender, envelope.receiver)
        )

        message = Message(**json.loads(plaintext.decode("utf-8")))

        log_event(f"{self.agent_id} verified and decrypted message {message.message_id}")

        return message

    def send_secure_message(self, message: Message, host: str, port: int) -> Message:
        envelope = self.secure_wrap(message)

        log_event(f"{message.sender} sent message {message.message_id} to {message.receiver}")

        response_envelope = send_message(
            host=host,
            port=port,
            message=envelope
        )

        response_message = self.secure_unwrap(response_envelope)

        log_event(f"{self.agent_id} received result for task {response_message.task_id}")

        return response_message