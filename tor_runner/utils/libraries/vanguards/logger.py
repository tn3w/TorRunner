#!/usr/bin/env python

"""
logger.py
"""

from typing import Any


def is_convertible_to_string(entity: Any) -> bool:
    return hasattr(entity, "__str__") and callable(entity.__str__) or \
           hasattr(entity, "__repr__") and callable(entity.__repr__)


def plog(level, msg, *args):
    string = f"[Vanguards {level}]: {msg}"
    for arg in args:
        if not isinstance(arg, str):
            if not is_convertible_to_string(arg):
                continue

            arg = str(arg)

        string += " " + arg

    print(string)
