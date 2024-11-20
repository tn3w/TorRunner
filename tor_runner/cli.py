from os import path
from subprocess import Popen
from argparse import ArgumentParser
from typing import Optional, Final, Tuple, List, Any
from sys import exit as sys_exit, argv, stdout, stderr

from utils.tor import install_tor, set_ld_library_path_environ
from utils.utils import OPERATING_SYSTEM, ARCHITECTURE
from utils.files import WORK_DIRECTORY_PATH, TOR_FILE_PATHS, SecureShredder


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
    Parses a list of bridges to extract an integer representing the first numeric value 
    and a list of non-numeric strings.

    Args:
        bridges (Optional[list]): A list of items to parse. Each item can be of any type.

    Returns:
        Tuple[int, List[str]]: 
            - An integer representing the first numeric value found in the list (default is 0).
            - A list of non-numeric strings.
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


def before_tor_start() -> None:
    install_tor(OPERATING_SYSTEM, ARCHITECTURE)
    if OPERATING_SYSTEM == "linux":
        set_ld_library_path_environ()


def execute_main() -> None:
    print(LOGO)

    quiet = "-q" in argv or "--quiet" in argv
    if "-e" in argv or "--execute" in argv:
        arguments = argv[1:]

        before_tor_start()
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

    remove_iterations = getattr(args, "remove", None)
    if remove_iterations != 0:
        proceed = input("All data will be permanently removed. Do you wish to continue? [Y/n] ")
        print()
        if proceed.strip().lower() != "y":
            print("Aborting.")
            return

        print("All the data will now be removed...")
        if path.isdir(WORK_DIRECTORY_PATH):
            SecureShredder.directory(WORK_DIRECTORY_PATH, remove_iterations)

        print("Done.")
        return

    bridge_quantity, bridges = parse_bridges(getattr(args, "bridges", None))


def main():
    """
    Runs main and handles KeyboardInterrupt.
    """

    try:
        execute_main()
    except KeyboardInterrupt:
        print("\nReceived CTRL+C command. Exiting now.")
    finally:
        sys_exit(0)


if __name__ == "__main__":
    main()
