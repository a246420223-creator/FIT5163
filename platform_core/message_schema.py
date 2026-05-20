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

    message_id: str
    sender: str
    receiver: str

    encrypted_key: str

    nonce: str
    ciphertext: str

    signature: Optional[str] = None