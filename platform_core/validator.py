from platform_core.message_schema import Message


def validate_message(message_data: dict) -> Message:
    try:
        message = Message(**message_data)
        return message
    except Exception as e:
        raise ValueError(f"Invalid message format: {e}")