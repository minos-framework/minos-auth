"""
Copyright (C) 2021 Clariteia SL

This file is part of minos framework.

Minos framework can not be copied and/or distributed without the express permission of Clariteia SL.
"""
from pathlib import (
    Path,
)

BASE_PATH = Path(__file__).parent


class FakeEntrypoint:
    """For testing purposes."""

    def __init__(self):
        self.call_count = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return

    def run_forever(self):
        """For testing purposes."""
        self.call_count += 1
