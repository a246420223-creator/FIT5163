import json
from datetime import datetime, timezone
from uuid import uuid4

from platform_core.message_schema import Message, SecureEnvelope, KeyEnvelope

from platform_core.crypto import (
    encrypt_message,
    decrypt_message
)

from platform_core.auth import (
    sign_data,
    verify_signature,
    rsa_encrypt,
    rsa_decrypt
)

from platform_core.logger import log_event
from platform_core.transport import send_message


class SecurePlatform:

    REPLAY_WINDOW_SECONDS = 300

    def __init__(
        self,
        agent_id: str,
        private_key,
        public_keys: dict,
        rsa_private_key=None,
        rsa_public_keys: dict | None = None,
        aes_key: bytes | None = None
    ):

        self.agent_id = agent_id

        self.private_key = private_key
        self.public_keys = public_keys

        self.rsa_private_key = rsa_private_key
        self.rsa_public_keys = rsa_public_keys or {}

        self.aes_key = aes_key
        self.seen_message_ids = {}

    def _aad(self, sender: str, receiver: str) -> bytes:

        return f"{sender}->{receiver}".encode("utf-8")

    def _envelope_signature_data(self, envelope: dict) -> bytes:
        """Canonical bytes signed/verified for a SecureEnvelope."""

        data = {
            "message_id": envelope["message_id"],
            "sender": envelope["sender"],
            "receiver": envelope["receiver"],
            "nonce": envelope["nonce"],
            "ciphertext": envelope["ciphertext"]
        }

        return json.dumps(data, sort_keys=True).encode("utf-8")

    def _key_envelope_signature_data(self, envelope: dict) -> bytes:
        """Canonical bytes signed/verified for a KeyEnvelope."""

        data = {
            "message_id": envelope["message_id"],
            "sender": envelope["sender"],
            "receiver": envelope["receiver"],
            "timestamp": self._timestamp_to_string(envelope["timestamp"]),
            "encrypted_aes_key": envelope["encrypted_aes_key"]
        }

        return json.dumps(data, sort_keys=True).encode("utf-8")

    def _timestamp_to_string(self, timestamp) -> str:
        if isinstance(timestamp, datetime):
            return timestamp.isoformat()

        return str(timestamp)

    def _utc_now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _as_utc(self, timestamp: datetime) -> datetime:
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    def _reject_replay(self, sender: str, message_id: str, timestamp: datetime) -> None:
        now = self._utc_now()
        cutoff_seconds = self.REPLAY_WINDOW_SECONDS

        expired_ids = [
            cache_key
            for cache_key, seen_at in self.seen_message_ids.items()
            if (now - seen_at).total_seconds() > cutoff_seconds
        ]

        for cache_key in expired_ids:
            del self.seen_message_ids[cache_key]

        message_time = self._as_utc(timestamp)
        message_age = abs((now - message_time).total_seconds())

        if message_age > cutoff_seconds:
            raise ValueError(
                "Replay attack detected: message timestamp is outside the accepted window."
            )

        cache_key = (sender, message_id)

        if cache_key in self.seen_message_ids:
            raise ValueError(
                "Replay attack detected: duplicate message_id."
            )

        self.seen_message_ids[cache_key] = now

    # ------------------------------------------------------------------
    # AES key distribution (RSA-protected)
    # ------------------------------------------------------------------

    def distribute_aes_key(self, receiver: str) -> dict:
        """
        Encrypt the shared AES key with the receiver's RSA public key,
        sign the KeyEnvelope, and return it as a plain dict.
        """

        if self.aes_key is None:
            raise ValueError(
                "distribute_aes_key failed: this agent has no AES key to distribute."
            )

        print(f"[Router] Distributing AES key to {receiver}...")

        encrypted_aes_key = rsa_encrypt(
            self.rsa_public_keys[receiver],
            self.aes_key
        )

        envelope = {
            "message_id": str(uuid4()),
            "sender": self.agent_id,
            "receiver": receiver,
            "timestamp": self._utc_now().isoformat(),
            "encrypted_aes_key": encrypted_aes_key,
            "signature": None
        }

        signature = sign_data(
            self.private_key,
            self._key_envelope_signature_data(envelope)
        )

        envelope["signature"] = signature

        log_event(
            f"{self.agent_id} signed and sent AES key to {receiver}"
        )

        return envelope

    def receive_aes_key(self, envelope_data: dict) -> None:
        """
        Verify a KeyEnvelope's signature, decrypt the AES key with this
        agent's RSA private key, and store it as self.aes_key.
        """

        envelope = KeyEnvelope(**envelope_data)

        if envelope.sender not in self.public_keys:
            raise ValueError(
                f"Unknown sender: {envelope.sender}"
            )

        signature_valid = verify_signature(
            public_key=self.public_keys[envelope.sender],
            signature_hex=envelope.signature,
            data=self._key_envelope_signature_data(
                envelope.model_dump()
            )
        )

        if not signature_valid:
            raise ValueError(
                "Invalid signature on KeyEnvelope."
            )

        if envelope.receiver != self.agent_id:
            raise ValueError(
                f"KeyEnvelope receiver mismatch: expected {self.agent_id}, got {envelope.receiver}."
            )

        self._reject_replay(
            sender=envelope.sender,
            message_id=envelope.message_id,
            timestamp=envelope.timestamp
        )

        print("[Router] Recovering shared AES key via RSA...")

        self.aes_key = rsa_decrypt(
            self.rsa_private_key,
            envelope.encrypted_aes_key
        )

        log_event(
            f"{self.agent_id} received and stored AES key from {envelope.sender}"
        )

    # ------------------------------------------------------------------
    # Normal message encryption / decryption (AES-GCM with shared key)
    # ------------------------------------------------------------------

    def secure_wrap(self, message: Message) -> dict:

        if self.aes_key is None:
            raise ValueError(
                "secure_wrap failed: AES key has not been distributed yet."
            )

        plaintext = message.model_dump_json().encode("utf-8")

        # Fresh nonce per message — never reuse a nonce with the same AES key.
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
            self._envelope_signature_data(envelope)
        )

        envelope["signature"] = signature

        log_event(
            f"{message.sender} encrypted and signed message {message.message_id}"
        )

        return envelope

    def secure_unwrap(self, envelope_data: dict) -> Message:

        if self.aes_key is None:
            raise ValueError(
                "secure_unwrap failed: AES key has not been distributed yet."
            )

        envelope = SecureEnvelope(**envelope_data)

        if envelope.sender not in self.public_keys:
            raise ValueError(
                f"Unknown sender: {envelope.sender}"
            )

        signature_valid = verify_signature(
            public_key=self.public_keys[envelope.sender],
            signature_hex=envelope.signature,
            data=self._envelope_signature_data(
                envelope.model_dump()
            )
        )

        if not signature_valid:
            raise ValueError(
                "Invalid digital signature."
            )

        plaintext = decrypt_message(
            key=self.aes_key,
            nonce_hex=envelope.nonce,
            ciphertext_hex=envelope.ciphertext,
            aad=self._aad(envelope.sender, envelope.receiver)
        )

        message = Message(
            **json.loads(plaintext.decode("utf-8"))
        )

        if message.message_id != envelope.message_id:
            raise ValueError(
                "Envelope message_id does not match decrypted message_id."
            )

        if message.sender != envelope.sender:
            raise ValueError(
                "Envelope sender does not match decrypted message sender."
            )

        if message.receiver != self.agent_id:
            raise ValueError(
                f"Message receiver mismatch: expected {self.agent_id}, got {message.receiver}."
            )

        self._reject_replay(
            sender=message.sender,
            message_id=message.message_id,
            timestamp=message.timestamp
        )

        log_event(
            f"{self.agent_id} verified and decrypted message {message.message_id}"
        )

        return message

    def send_secure_message(
        self,
        message: Message,
        host: str,
        port: int
    ) -> Message:

        envelope = self.secure_wrap(message)

        log_event(
            f"{message.sender} sent message {message.message_id} to {message.receiver}"
        )

        response_envelope = send_message(
            host=host,
            port=port,
            message=envelope
        )

        response_message = self.secure_unwrap(response_envelope)

        log_event(
            f"{self.agent_id} received result for task {response_message.task_id}"
        )

        return response_message
