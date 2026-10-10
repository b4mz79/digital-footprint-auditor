from __future__ import annotations

import io
import logging

from utils.logging_setup import SensitiveDataFormatter


def test_formatter_redacts_pii_in_exception_traceback() -> None:
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.setFormatter(SensitiveDataFormatter("%(levelname)s %(message)s"))

    logger = logging.getLogger("test_sensitive_exception_formatter")
    previous_handlers = logger.handlers[:]
    previous_propagate = logger.propagate
    previous_level = logger.level
    try:
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.ERROR)
        try:
            raise RuntimeError("failed for user@example.com")
        except RuntimeError:
            logger.exception("scan failed")

        rendered = output.getvalue()
        assert "scan failed" in rendered
        assert "user@example.com" not in rendered
    finally:
        logger.handlers = previous_handlers
        logger.propagate = previous_propagate
        logger.setLevel(previous_level)
        handler.close()
