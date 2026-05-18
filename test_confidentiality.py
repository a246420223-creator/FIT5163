from datetime import datetime
from uuid import uuid4

from platform_core.message_schema import Message
from platform_core.crypto import load_aes_key
from platform_core.auth import load_private_key, load_public_key
from platform_core.router import SecurePlatform
import json


aes_key = load_aes_key("keys/aes.key")

planner_private_key = load_private_key("keys/planner_1_private.pem")

public_keys = {
    "planner_1": load_public_key("keys/planner_1_public.pem"),
    "executor_1": load_public_key("keys/executor_1_public.pem")
}

platform = SecurePlatform(
    agent_id="planner_1",
    aes_key=aes_key,
    private_key=planner_private_key,
    public_keys=public_keys
)

message = Message(
    message_id=str(uuid4()),
    sender="planner_1",
    receiver="executor_1",
    timestamp=datetime.utcnow(),
    message_type="task_request",
    task_id=str(uuid4()),
    payload={
        "task_type": "summarise_text",
        "input": "This is a secret task message."
    }
)

envelope = platform.secure_wrap(message)

print("Original plaintext message:")
print(message.model_dump_json(indent=2))


print("\nEncrypted envelope sent over the channel:")
print(json.dumps(envelope, indent=2))

print("\nCan we see the secret input directly?")
print("This is a secret task message." in str(envelope))