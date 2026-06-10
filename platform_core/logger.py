"""
Audit logger.

Writes structured event records to both the console and
logs/communication.log.  Three severity levels are exposed:

  log_event()   — normal operation (INFO)
  log_warning() — security policy violations, rejected messages (WARNING)
  log_error()   — unexpected / unrecoverable failures (ERROR)

Keeping security rejections as WARNING (not ERROR) makes it easy to grep
the log file for all policy decisions:  grep WARNING logs/communication.log
"""

import logging
import os

os.makedirs("logs", exist_ok=True)

_logger = logging.getLogger("secure_platform")
_logger.setLevel(logging.DEBUG)

# File handler — full audit trail at DEBUG and above.
_file_handler = logging.FileHandler("logs/communication.log")
_file_handler.setLevel(logging.DEBUG)
_file_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)

# Console handler — INFO and above so the terminal is not too noisy.
# Explicitly use stdout (not stderr) so log lines appear in order with print().
import sys as _sys
_console_handler = logging.StreamHandler(_sys.stdout)
_console_handler.setLevel(logging.INFO)
_console_handler.setFormatter(
    logging.Formatter("[%(levelname)s] %(message)s")
)

_logger.addHandler(_file_handler)
_logger.addHandler(_console_handler)


def log_event(event: str) -> None:
    """Record a normal operational event (INFO)."""
    _logger.info(event)


def log_warning(event: str) -> None:
    """Record a security policy violation or rejected message (WARNING)."""
    _logger.warning(event)


def log_error(event: str) -> None:
    """Record an unexpected failure (ERROR)."""
    _logger.error(event)
