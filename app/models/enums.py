from enum import Enum


class Decision(str, Enum):
    ALLOW = "ALLOW"
    SAFE_MODE = "SAFE_MODE"
    BLOCK = "BLOCK"