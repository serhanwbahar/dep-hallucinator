# In src/dep_hallucinator/dependency.py
from dataclasses import dataclass


@dataclass(frozen=True)
class Dependency:
    """A unified internal data structure to represent a dependency."""

    name: str
    version: str
    source_file: str
