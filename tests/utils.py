import os
from typing import Any


def load_from_file(filename, mode="rb") -> Any:
    """Load a file from the tests/repository directory."""
    filepath = os.path.dirname(__file__)
    with open(os.path.join(filepath, "repository", filename), mode=mode) as f:
        return f.read()
