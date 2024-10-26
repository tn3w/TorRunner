"""
__init__.py

Initializes TorRunner.

License: GNU General Public License v3.0
    https://github.com/tn3w/TorRunner/blob/master/LICENSE
Source: https://github.com/tn3w/TorRunner
"""

from .tor_runner import TorRunner
from .tor_proxy import TorProxy

__all__ = ["TorRunner", "TorProxy"]
