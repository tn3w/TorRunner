from os import path
from subprocess import Popen
from argparse import ArgumentParser
from typing import Optional, Final, Tuple, List, Any
from sys import exit as sys_exit, argv, stdout, stderr

from utils.tor import install_tor, set_ld_library_path_environ
from utils.files import WORK_DIRECTORY_PATH, TOR_FILE_PATHS, SecureShredder
from utils.utils import OPERATING_SYSTEM, ARCHITECTURE, set_global_quiet, is_quiet


LOGO: Final[str] =\
"""
░▀▀█▀▀░▄▀▀▄░█▀▀▄░▒█▀▀▄░█░▒█░█▀▀▄░█▀▀▄░█▀▀░█▀▀▄
░░▒█░░░█░░█░█▄▄▀░▒█▄▄▀░█░▒█░█░▒█░█░▒█░█▀▀░█▄▄▀
░░▒█░░░░▀▀░░▀░▀▀░▒█░▒█░░▀▀▀░▀░░▀░▀░░▀░▀▀▀░▀░▀▀

Author: TN3W
GitHub: https://github.com/tn3w/TorRunner
"""


def parse_listener(listener_str: str) -> List[Tuple[int, int]]:
    """
    Parses a string of listener data into a list of tuples.

    Args:
        listener_str (str): A string containing listener coordinates in the format
                            "x1,y1 x2,y2 ...".

    Returns:
        List[Tuple[int, int]]: A list of tuples, where each tuple contains two integers
                               representing the coordinates of a listener. If the input
                               string is not in the expected format or cannot be parsed,
                               an empty list is returned.
    """

    try:
        listeners = listener_str.split(" ")
        listener_tuples = [
            tuple(map(int, listener.split(',')))
            for listener in listeners
        ]

        return listener_tuples

    except ValueError:
        pass

    return []


def parse_vanguards(value: Any) -> int:
    """
    Parses a value into an integer.

    Args:
        value (Any): The value to be parsed into an integer. This can be of any type, including
                     strings, numbers, or other data types.

    Returns:
        int: The parsed integer value. If the input value cannot be converted to an integer,
             returns 0.
    """

    try:
        return int(value)
    except ValueError:
        pass

    return 0


def parse_remove(value: Any) -> int:
    """
    Parses a value into an integer.

    Args:
        value (Any): The value to be parsed into an integer. This can be of any type, including
                     strings, numbers, or other data types.

    Returns:
        int: The parsed integer value. If the input value cannot be converted to an integer,
             returns 0.
    """

    try:
        return int(value)
    except ValueError:
        pass

    return 0


def parse_bridges(bridges: Optional[list]) -> Tuple[int, List[str]]:
    """
    Parses a list of bridges to extract the first numeric value (representing the number 
    of bridges) and a list of non-numeric strings (describing the bridge details).

    Args:
        bridges (Optional[list]): A list of items to parse. Items can be strings or other types.
            If None or an empty list is provided, defaults will be returned.

    Returns:
        Tuple[int, List[str]]: integer representing the first numeric value found and a list of
            non-numeric strings from the input list, which are interpreted as bridge details.
    """

    if not bridges:
        return 0, []

    bridge_quantity = next(
        (
            int(bridge) for bridge in bridges
            if isinstance(bridge, str) and bridge.isdigit()
        ), 0
    )
    bridge_strings = [
        bridge for bridge in bridges
        if isinstance(bridge, str) and not bridge.isdigit()
    ]

    return bridge_quantity, bridge_strings


def before_tor_start() -> bool:
    """
    Ensures that Tor is installed and performs any
    necessary setup for the system environment.

    Returns:
        bool: True if Tor is installed and the environment
            is properly set up, False otherwise.
    """

    is_installed = install_tor(OPERATING_SYSTEM, ARCHITECTURE)
    if not is_installed:
        return False

    if OPERATING_SYSTEM == "linux":
        set_ld_library_path_environ()

    return True


def get_remove_value():
    """
    Checks command-line arguments for a value indicating
    the number of iterations to remove data.

    Returns:
        int or None: The number of iterations for data removal,
            or None if no such request was made.
    """

    for i, arg in enumerate(argv):
        if arg in ["-r", "--remove"]:
            if i + 1 < len(argv) and argv[i + 1].isdigit():
                return int(argv[i + 1])

            return 3

    return None


def execute_main() -> None:
    """
    The main function that handles the execution of the script, including parsing arguments,
    setting quiet mode, handling data removal, and starting Tor processes or commands.

    Based on the parsed command-line arguments, this function performs different tasks:
    - Handles quiet mode
    - Handles the removal of data if requested
    - Executes commands via Tor if requested
    - Starts and configures Tor instances with optional
      listeners, control ports, and other settings.

    Returns:
        None
    """

    quiet = "-q" in argv or "--quiet" in argv
    set_global_quiet(quiet)

    if not quiet:
        print(LOGO)

    # Kill switch
    remove_iterations = get_remove_value()
    if remove_iterations is not None:
        if "-y" not in argv and not quiet:
            proceed = input("All data will be permanently removed. Do you wish to continue? [Y/n] ")
            print()
            if proceed.strip().lower() != "y":
                print("Aborting.")
                return

        if not quiet:
            print("All the data will now be removed...")

        if path.isdir(WORK_DIRECTORY_PATH):
            SecureShredder.directory(WORK_DIRECTORY_PATH, remove_iterations)

        if not quiet:
            print("\nDone.")

        return

    # Direct execution
    if "-e" in argv or "--execute" in argv:
        arguments = argv[1:]

        is_installed = before_tor_start()
        if not is_installed:
            if not is_quiet:
                print("Aborting.")

            return

        commands = [TOR_FILE_PATHS["tor"]]
        commands.extend([
            argument
            for argument in arguments
            if argument not in ["-e", "--execute", "-q", "--quiet"]
        ])

        if quiet:
            commands.append("--quiet")

        with Popen(commands, stdout = stdout, stderr = stderr) as process:
            process.wait()

        return

    parser = ArgumentParser(
        description = (
            "Quickly deploy Tor processes, proxies, and hidden services with robust "
            "multithreading capabilities, along with support for bridges and vanguards."
        )
    )

    parser.add_argument(
        "-i", "--instances",
        type = int,
        default = 1,
        help = "How many times Tor should start. (default: 1)"
    )
    parser.add_argument(
        "-l", "--listener",
        type = parse_listener,
        nargs = '*',
        default = [],
        help = "List of listeners in the format 'tor_port,listen_port'."
    )
    parser.add_argument(
        "-s", "--socks-port",
        type = int,
        default = None,
        help = "SOCKS port for Tor connections."
    )
    parser.add_argument(
        "-c", "--control-port",
        type = int,
        default = None,
        help = "Control port for Tor."
    )
    parser.add_argument(
        "-p", "--control-password",
        type = str,
        default = None,
        help = "Control password for Tor."
    )
    parser.add_argument(
        "-d", "--hidden-service-dirs",
        type = str,
        nargs = '*',
        help = "Directories for storing hidden service keys and hostname files."
    )
    parser.add_argument(
        "-b", "--bridges",
        type = str,
        nargs = '*',
        help = "List of bridges to use for connecting to the Tor network."
    )
    parser.add_argument(
        "-v", "--vanguards",
        nargs = '?',
        const = 1,
        default = 0,
        type = parse_vanguards,
        help = ("Enables Vanguards with an optional thread count to protect"
                " against guard discovery and related traffic analysis attacks.")
    )
    parser.add_argument(
        "-t", "--default-bridge-type",
        type = str,
        default = None,
        help = "Default bridge type to use when connecting to Tor."
    )
    parser.add_argument(
        "-r", "--remove",
        nargs = '?',
        const = 3,
        default = 0,
        type = parse_remove,
        help = "Remove all data associated with tor_runner."
    )
    parser.add_argument(
        "-e", "--execute",
        action = "store_true",
        help = "Executes your command directly via Tor."
    )
    parser.add_argument(
        "-q", "--quiet",
        action = "store_true",
        help = "Run the script in quiet mode with no output."
    )

    args = parser.parse_args()

    if len(argv) == 1:
        parser.print_help()
        return

    bridge_quantity, bridges = parse_bridges(getattr(args, "bridges", None))


def main():
    """
    Runs main and handles KeyboardInterrupt.
    """

    try:
        execute_main()
    except KeyboardInterrupt:
        if not is_quiet():
            print("\nReceived CTRL+C command. Exiting now.")

    finally:
        sys_exit(0)


if __name__ == "__main__":
    main()
