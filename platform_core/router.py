"""
SecurePlatform — the central security orchestrator.

Responsibilities:
  - AES session-key distribution via RSA-OAEP (hybrid encryption)
  - Per-message AES-GCM encryption / decryption
  - Ed25519 digital signature creation and verification
  - Replay-attack protection via timestamp window + message-ID cache
  - Audit logging for every security event (success and failure)

Usage pattern:
  planner = SecurePlatform(agent_id="planner_1", ...)
  executor = SecurePlatform(agent_id="executor_1", ...)

  # Key distribution (once per session)
  key_envelope = planner.distribute_aes_key("executor_1")
  executor.receive_aes_key(key_envelope)

  # Per-message secure communication
  envelope  = planner.secure_wrap(message)
  plaintext = executor.secure_unwrap(envelope)
"""

import json
from datetime import datetime, timezone
from uuid import uuid4

from platform_core.message_schema import Message, SecureEnvelope, KeyEnvelope
from platform_core.crypto import encrypt_message, decrypt_message
from platform_core.auth import sign_data, verify_signature, rsa_encrypt, rsa_decrypt
from platform_core.logger import log_event, log_warning
from platform_core.transport import send_message


class SecurePlatform:

    # Messages whose timestamp falls outside this window are rejected as stale
    # or replayed.  300 s (5 min) is a reasonable value for a local demo.
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

        # Maps (sender, message_id) → time-first-seen.
        # Used to detect duplicate deliveries within the replay window.
        self.seen_message_ids: dict = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _aad(self, sender: str, receiver: str) -> bytes:
        """Additional authenticated data bound to sender→receiver direction."""
        return f"{sender}->{receiver}".encode("utf-8")

    def _envelope_signature_data(self, envelope: dict) -> bytes:
        """Canonical bytes that are signed / verified for a SecureEnvelope."""
        data = {
            "message_id": envelope["message_id"],
            "sender":     envelope["sender"],
            "receiver":   envelope["receiver"],
            "nonce":      envelope["nonce"],
            "ciphertext": envelope["ciphertext"],
        }
        return json.dumps(data, sort_keys=True).encode("utf-8")

    def _key_envelope_signature_data(self, envelope: dict) -> bytes:
        """Canonical bytes that are signed / verified for a KeyEnvelope."""
        data = {
            "message_id":       envelope["message_id"],
            "sender":           envelope["sender"],
            "receiver":         envelope["receiver"],
            "timestamp":        self._timestamp_to_string(envelope["timestamp"]),
            "encrypted_aes_key": envelope["encrypted_aes_key"],
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
        """
        Raise ValueError if *message_id* has already been processed, or if the
        message timestamp is outside the accepted freshness window.

        Also evicts expired entries from the seen-IDs cache so it does not grow
        without bound during a long-running session.
        """
        now = self._utc_now()

        # Evict cache entries that are older than the replay window.
        expired = [
            key for key, seen_at in self.seen_message_ids.items()
            if (now - seen_at).total_seconds() > self.REPLAY_WINDOW_SECONDS
        ]
        for key in expired:
            del self.seen_message_ids[key]

        # Check message freshness.
        message_age = abs((now - self._as_utc(timestamp)).total_seconds())
        if message_age > self.REPLAY_WINDOW_SECONDS:
            log_warning(
                f"{self.agent_id} REJECTED stale/replayed message from {sender} "
                f"(id={message_id}, age={message_age:.1f}s > window={self.REPLAY_WINDOW_SECONDS}s)"
            )
            raise ValueError(
                "Replay attack detected: message timestamp is outside the accepted window."
            )

        # Check for duplicate message ID.
        cache_key = (sender, message_id)
        if cache_key in self.seen_message_ids:
            log_warning(
                f"{self.agent_id} REJECTED duplicate message_id from {sender} (id={message_id})"
            )
            raise ValueError("Replay attack detected: duplicate message_id.")

        self.seen_message_ids[cache_key] = now

    # ------------------------------------------------------------------
    # AES session-key distribution (RSA-OAEP hybrid encryption)
    # ------------------------------------------------------------------

    def distribute_aes_key(self, receiver: str) -> dict:
        """
        Encrypt the shared AES key with *receiver*'s RSA public key and sign
        the resulting KeyEnvelope with this agent's Ed25519 private key.

        Returns a plain dict suitable for JSON serialisation and socket transmission.
        """
        if self.aes_key is None:
            raise ValueError(
                "distribute_aes_key: this agent has no AES key to distribute."
            )

        encrypted_aes_key = rsa_encrypt(self.rsa_public_keys[receiver], self.aes_key)

        envelope = {
            "message_id":       str(uuid4()),
            "sender":           self.agent_id,
            "receiver":         receiver,
            "timestamp":        self._utc_now().isoformat(),
            "encrypted_aes_key": encrypted_aes_key,
            "signature":        None,
        }

        envelope["signature"] = sign_data(
            self.private_key,
            self._key_envelope_signature_data(envelope)
        )

        log_event(
            f"{self.agent_id} signed and sent AES key to {receiver} "
            f"(RSA-OAEP encrypted, Ed25519 signed)"
        )
        return envelope

    def receive_aes_key(self, envelope_data: dict) -> None:
        """
        Verify the KeyEnvelope signature, check the receiver field, apply
        replay protection, then decrypt and store the AES session key.
        """
        envelope = KeyEnvelope(**envelope_data)

        if envelope.sender not in self.public_keys:
            log_warning(
                f"{self.agent_id} REJECTED KeyEnvelope from unknown sender: {envelope.sender}"
            )
            raise ValueError(f"Unknown sender: {envelope.sender}")

        sig_ok = verify_signature(
            public_key=self.public_keys[envelope.sender],
            signature_hex=envelope.signature,
            data=self._key_envelope_signature_data(envelope.model_dump())
        )
        if not sig_ok:
            log_warning(
                f"{self.agent_id} REJECTED KeyEnvelope from {envelope.sender}: "
                f"Ed25519 signature verification failed (id={envelope.message_id})"
            )
            raise ValueError("Invalid signature on KeyEnvelope.")

        if envelope.receiver != self.agent_id:
            log_warning(
                f"{self.agent_id} REJECTED KeyEnvelope: receiver mismatch "
                f"(expected {self.agent_id}, got {envelope.receiver})"
            )
            raise ValueError(
                f"KeyEnvelope receiver mismatch: expected {self.agent_id}, "
                f"got {envelope.receiver}."
            )

        self._reject_replay(
            sender=envelope.sender,
            message_id=envelope.message_id,
            timestamp=envelope.timestamp
        )

        self.aes_key = rsa_decrypt(self.rsa_private_key, envelope.encrypted_aes_key)

        log_event(
            f"{self.agent_id} received and stored AES key from {envelope.sender} "
            f"(RSA-OAEP decrypted, signature verified)"
        )

    # ------------------------------------------------------------------
    # Per-message encryption / decryption (AES-GCM with shared session key)
    # ------------------------------------------------------------------

    def secure_wrap(self, message: Message) -> dict:
        """
        Encrypt *message* with AES-GCM (fresh random nonce) and sign the
        resulting SecureEnvelope with this agent's Ed25519 private key.

        Returns a plain dict suitable for JSON serialisation.
        """
        if self.aes_key is None:
            raise ValueError("secure_wrap: AES key has not been distributed yet.")

        plaintext = message.model_dump_json().encode("utf-8")

        # A fresh 96-bit nonce is generated inside encrypt_message for every
        # call — nonce reuse with the same key would break AES-GCM security.
        encrypted = encrypt_message(
            key=self.aes_key,
            plaintext=plaintext,
            aad=self._aad(message.sender, message.receiver)
        )

        envelope = {
            "message_id": message.message_id,
            "sender":     message.sender,
            "receiver":   message.receiver,
            "nonce":      encrypted["nonce"],
            "ciphertext": encrypted["ciphertext"],
            "signature":  None,
        }

        envelope["signature"] = sign_data(
            self.private_key,
            self._envelope_signature_data(envelope)
        )

        log_event(
            f"{message.sender} -> {message.receiver}: "
            f"AES-GCM encrypted + Ed25519 signed message {message.message_id}"
        )
        return envelope

    def secure_unwrap(self, envelope_data: dict) -> Message:
        """
        Verify the Ed25519 signature, AES-GCM decrypt the payload, validate
        metadata consistency, and apply replay protection.

        Raises ValueError for any security violation so callers can return a
        safe error response without crashing.
        """
        if self.aes_key is None:
            raise ValueError("secure_unwrap: AES key has not been distributed yet.")

        envelope = SecureEnvelope(**envelope_data)

        # --- 1. Authenticity: verify the sender's Ed25519 signature ----------
        if envelope.sender not in self.public_keys:
            log_warning(
                f"{self.agent_id} REJECTED message from unknown sender: {envelope.sender}"
            )
            raise ValueError(f"Unknown sender: {envelope.sender}")

        sig_ok = verify_signature(
            public_key=self.public_keys[envelope.sender],
            signature_hex=envelope.signature,
            data=self._envelope_signature_data(envelope.model_dump())
        )
        if not sig_ok:
            log_warning(
                f"{self.agent_id} REJECTED message from {envelope.sender}: "
                f"Ed25519 signature verification FAILED (id={envelope.message_id})"
            )
            raise ValueError("Invalid digital signature.")

        # --- 2. Confidentiality + Integrity: AES-GCM decrypt -----------------
        # decrypt_message raises InvalidTag if the ciphertext or AAD was tampered.
        try:
            plaintext = decrypt_message(
                key=self.aes_key,
                nonce_hex=envelope.nonce,
                ciphertext_hex=envelope.ciphertext,
                aad=self._aad(envelope.sender, envelope.receiver)
            )
        except Exception:
            log_warning(
                f"{self.agent_id} REJECTED message from {envelope.sender}: "
                f"AES-GCM authentication tag verification FAILED -- "
                f"ciphertext may have been tampered (id={envelope.message_id})"
            )
            raise ValueError(
                "AES-GCM decryption failed: ciphertext integrity check did not pass."
            )

        # --- 3. Structural validation: parse and cross-check fields ----------
        try:
            message = Message(**json.loads(plaintext.decode("utf-8")))
        except Exception as exc:
            log_warning(
                f"{self.agent_id} REJECTED malformed message from {envelope.sender}: {exc}"
            )
            raise ValueError(f"Malformed message payload: {exc}")

        if message.message_id != envelope.message_id:
            log_warning(
                f"{self.agent_id} REJECTED message: message_id mismatch between "
                f"envelope ({envelope.message_id}) and payload ({message.message_id})"
            )
            raise ValueError(
                "Envelope message_id does not match decrypted message_id."
            )

        if message.sender != envelope.sender:
            log_warning(
                f"{self.agent_id} REJECTED message: sender mismatch between "
                f"envelope ({envelope.sender}) and payload ({message.sender})"
            )
            raise ValueError(
                "Envelope sender does not match decrypted message sender."
            )

        if message.receiver != self.agent_id:
            log_warning(
                f"{self.agent_id} REJECTED message: receiver mismatch "
                f"(expected {self.agent_id}, got {message.receiver})"
            )
            raise ValueError(
                f"Message receiver mismatch: expected {self.agent_id}, "
                f"got {message.receiver}."
            )

        # --- 4. Freshness / replay protection --------------------------------
        self._reject_replay(
            sender=message.sender,
            message_id=message.message_id,
            timestamp=message.timestamp
        )

        log_event(
            f"{self.agent_id} [OK] verified and decrypted message {message.message_id} "
            f"from {message.sender} (signature OK, AES-GCM tag OK, no replay)"
        )
        return message

    # ------------------------------------------------------------------
    # Convenience: wrap + send + receive + unwrap in one call
    # ------------------------------------------------------------------

    def send_secure_message(self, message: Message, host: str, port: int) -> Message:
        """
        Encrypt and sign *message*, send it over TCP, and securely unwrap the
        response.  The caller receives a verified, decrypted Message.
        """
        envelope = self.secure_wrap(message)

        log_event(
            f"{message.sender} sent message {message.message_id} "
            f"to {message.receiver} at {host}:{port}"
        )

        response_envelope = send_message(host=host, port=port, message=envelope)

        # If the executor returned a plain error dict (not a SecureEnvelope),
        # surface the reason rather than failing with a confusing Pydantic error.
        if response_envelope.get("status") == "error":
            reason = response_envelope.get("reason", "unknown error")
            log_warning(
                f"{self.agent_id} received error response for message "
                f"{message.message_id}: {reason}"
            )
            raise ValueError(f"Executor returned error: {reason}")

        response_message = self.secure_unwrap(response_envelope)

        log_event(
            f"{self.agent_id} received verified result for task {response_message.task_id}"
        )
        return response_message
