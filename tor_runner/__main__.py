"""
Runs TorRunner.
"""

try:
    from .tor_runner import main
except ImportError:
    from tor_runner import main

if __name__ == "__main__":
    main()
