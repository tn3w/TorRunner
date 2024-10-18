"""
__main__.py

Runs TorRunner.

License: Made available under the GPL-3.0 license.
Source: https://github.com/tn3w/TorRunner
"""

try:
    from .tor_runner import main
except ImportError:
    from tor_runner import main

if __name__ == "__main__":
    main()
