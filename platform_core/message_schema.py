from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime


class Message(BaseModel):

    message_id: str
    sender: str
    receiver: str
    timestamp: datetime
    message_type: str
    task_id: str

    payload: Dict[str, Any]


class SecureEnvelope(BaseModel):
    """Carries an AES-GCM encrypted message. No per-message RSA key."""

    message_id: str
    sender: str
    receiver: str

    nonce: str
    ciphertext: str

    signature: Optional[str] = None


class KeyEnvelope(BaseModel):
    """Carries a RSA-encrypted shared AES key from sender to receiver."""

    message_id: str
    sender: str
    receiver: str
    timestamp: datetime

    encrypted_aes_key: str

    signature: Optional[str] = None
