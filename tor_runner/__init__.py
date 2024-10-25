"""
__init__.py

Initializes TorRunner.

License: Made available under the GPL-3.0 license.
Source: https://github.com/tn3w/TorRunner
"""

from .tor_runner import TorRunner
from .tor_proxy import TorProxy

__all__ = ["TorRunner", "TorProxy"]
