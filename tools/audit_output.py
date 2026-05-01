#!/usr/bin/env python3
"""Shared logging output helpers for audit scripts."""

from __future__ import annotations

import logging
import sys
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
LOGGER = logging.getLogger("apexmail.audit")


def emit(*values: Any, sep: str = " ", end: str = "\n") -> None:
    message = sep.join(str(value) for value in values)
    if end and end != "\n":
        message += end.rstrip("\n")
    LOGGER.info("%s", message)
