import logging
import os


os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/communication.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def log_event(event: str):
    logging.info(event)