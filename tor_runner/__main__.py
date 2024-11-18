"""
__main__.py

Runs TorRunner.

License: GNU General Public License v3.0
    https://github.com/tn3w/TorRunner/blob/master/LICENSE
Source: https://github.com/tn3w/TorRunner
"""

try:
    from .cli import main
except ImportError:
    from cli import main

if __name__ == "__main__":
    main()
