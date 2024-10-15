"""
tor_runner.py

This module provides a comprehensive set of functions and classes for managing Tor
installation, configuration, and execution. It includes utilities for verifying Tor
installations, downloading and extracting the necessary files, managing pluggable
transports, and setting up bridges. The module also facilitates running web applications
like Flask and Sanic on the Tor network, allowing for hidden services and secure connections.

License:
Made available under the GPL-3.0 license.
"""

import re
import os
import sys
import atexit
import select
import hashlib
import secrets
import argparse
import binascii
import subprocess
from itertools import chain
from sys import argv as ARGUMENTS
from typing import Optional, Tuple, Union, List, Any

try:
    from .common import (
        TOR_DIRECTORY_PATH, IMPORTANT_FILE_KEYS, TOR_FILE_PATHS,
        OPERATING_SYSTEM, ARCHITECTURE, ERROR_MESSAGE, TOR_ARCHIVE_FILE_PATH,
        DEBUG_DIRECTORY_PATH, PLUGGABLE_TRANSPORTS_DIRECTORY_PATH,
        DEFAULT_BRIDGES, DATA_DIRECTORY_PATH, PLUGGABLE_TRANSPORTS,
        CURRENT_DIRECTORY_PATH, HIDDEN_SERVICE_DIRECTORY_PATH, Progress,
        request_url, extract_links, download_file, extract_tar,
        delete, find_available_port, find_hostnames, configuration_to_str,
        generate_secure_random_string, write
    )
except ImportError:
    from common import (
        TOR_DIRECTORY_PATH, IMPORTANT_FILE_KEYS, TOR_FILE_PATHS,
        OPERATING_SYSTEM, ARCHITECTURE, ERROR_MESSAGE, TOR_ARCHIVE_FILE_PATH,
        DEBUG_DIRECTORY_PATH, PLUGGABLE_TRANSPORTS_DIRECTORY_PATH,
        DEFAULT_BRIDGES, DATA_DIRECTORY_PATH, PLUGGABLE_TRANSPORTS,
        CURRENT_DIRECTORY_PATH, HIDDEN_SERVICE_DIRECTORY_PATH, Progress,
        request_url, extract_links, download_file, extract_tar,
        delete, find_available_port, find_hostnames, configuration_to_str,
        generate_secure_random_string, write
    )


TOR_TIMEOUT = 60 # Seconds


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


def verify_tor_installation() -> bool:
    """
    Verifies the installation of all required Tor files.

    Returns:
        bool (bool): True if the file installation is correct, False otherwise.
    """

    if not os.path.isdir(TOR_DIRECTORY_PATH):
        return False

    for key in IMPORTANT_FILE_KEYS:
        file_path = TOR_FILE_PATHS[key]
        if not os.path.isfile(file_path):
            return False

    return True


def hash_tor_password(password: str) -> str:
    """
    Hash a password for use with Tor`s control port authentication.

    Args:
        password (str): The password to be hashed.

    Returns:
        str: The hashed password in a format suitable for Tor.
    """

    indicator_char = "`"
    salt = secrets.token_bytes(8) + indicator_char.encode("utf-8")
    indicator_value = ord(indicator_char)

    expected_bias = 6
    count = (16 + (indicator_value & 15)) << ((indicator_value >> 4) + expected_bias)

    sha1_hash = hashlib.sha1()
    salted_password = salt[:8] + password.encode("utf-8")
    password_length = len(salted_password)

    while count > 0:
        if count <= password_length:
            sha1_hash.update(salted_password[:count])
            break

        sha1_hash.update(salted_password)
        count -= password_length

    hashed_password = sha1_hash.digest()

    salt_hex = binascii.b2a_hex(salt[:8]).upper().decode("utf-8")
    indicator_hex = binascii.b2a_hex(indicator_char.encode("utf-8")).upper().decode("utf-8")
    hashed_password_hex = binascii.b2a_hex(hashed_password).upper().decode("utf-8")

    return "16:" + salt_hex + indicator_hex + hashed_password_hex


def install_tor() -> None:
    """
    Installs Tor based on the operating system and architecture.

    Returns:
        Nothing (None): Nothing is returned.
    """

    url = 'https://www.torproject.org/download/tor/'

    download_url = None
    content = request_url(url, return_as_bytes = False)

    if content is not None:
        anchors = extract_links(content)

        for anchor in anchors:
            if "archive.torproject.org/tor-package-archive/torbrowser" in anchor\
                and OPERATING_SYSTEM.lower() in anchor and "tor-expert-bundle" in anchor\
                    and ARCHITECTURE.lower() in anchor and not anchor.endswith(".asc"):

                download_url = anchor
                break

    if download_url is None:
        raise OSError("Tor download URL not found. " + ERROR_MESSAGE)

    is_downloaded = download_file(download_url, TOR_ARCHIVE_FILE_PATH)
    if not is_downloaded:
        raise OSError("Tor download failed. " + ERROR_MESSAGE)

    extracted_successfully = extract_tar(TOR_ARCHIVE_FILE_PATH, TOR_DIRECTORY_PATH)

    delete(TOR_ARCHIVE_FILE_PATH)
    delete(DEBUG_DIRECTORY_PATH)

    for file in os.listdir(PLUGGABLE_TRANSPORTS_DIRECTORY_PATH):
        if not file.strip().lower().startswith(("readme", "pt_config")):
            continue

        full_path = os.path.join(PLUGGABLE_TRANSPORTS_DIRECTORY_PATH, file)
        delete(full_path)

    if not extracted_successfully:
        raise OSError("Tor could not be extracted successfully. " + ERROR_MESSAGE)

    valid_installation = verify_tor_installation()
    if not valid_installation:
        raise OSError("An error occured while installing Tor. " + ERROR_MESSAGE)


def get_bridge_type(bridge_string: str) -> str:
    """
    Function for getting bridge type.

    Args:
        bridge_string (str): The full string of the bridge.

    Returns:
        str: The type of the bridge.
    """

    pattern = (r'^(.*?)\s*(?:\d{1,3}\.){3}\d{1,3}|'
               r'\[(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\]')

    match = re.match(pattern, bridge_string)
    if match:
        bridge_type = match.group(1)
        if bridge_type:
            return bridge_type.strip()

    for bridge_type in ["obfs4", "snowflake", "webtunnel", "meek_lite"]:
        if bridge_type.lower() in bridge_string.lower():
            return bridge_type

    return "vanilla"


def get_default_bridges(bridge_type: str = "obfs4", quantity: int = 3,
                        default_bridge_type: Optional[str] = "obfs4") -> Optional[List[str]]:
    """
    Returns bridges of a specific `brige_type`.

    Args:
        bridge_type (str): The type of bridges wanted. Possible: `vanilla`, `obfs4`,
            `snowflake`, `webtunnel`, `meek_azure` or `meek_lite`.
        quantity (int): The number of bridges to be returned.
        default_bridge_type (str): Optional bridge type if no bridges of the given type exist.

    Returns:
        bridges (Union[List[str], Any]): Bridges from type `bridge_type` to number
            of `quantity` or default bridges of `default_bridge_type` or None.
    """

    bridges = DEFAULT_BRIDGES.get(bridge_type, None)
    if bridges is None:
        bridges = DEFAULT_BRIDGES.get(default_bridge_type, None)

    if isinstance(bridges, list) and len(bridges) >= quantity:
        bridges = bridges[:quantity]

    return bridges


def create_tor_data() -> str:
    """
    Creates a new directory for Tor data with a randomly generated name.

    Returns:
        str: The path to the newly created Tor data directory.
    """

    random_name = generate_secure_random_string(8)
    tor_data_directory_path = os.path.join(DATA_DIRECTORY_PATH, f"{random_name}.data")

    if not os.path.exists(tor_data_directory_path):
        os.makedirs(tor_data_directory_path, exist_ok = True)

    return tor_data_directory_path


def create_temp_torrc(content: str) -> str:
    """
    Creates a temporary Tor configuration file with a randomly generated name.

    Args:
        content (str): The content to be written to the Tor configuration file.

    Returns:
        str: The path to the newly created Tor configuration file.
    """

    random_name = generate_secure_random_string(8)
    torrc_path = os.path.join(DATA_DIRECTORY_PATH, f"{random_name}.torrc")

    write(torrc_path, content)
    return torrc_path


def get_configuration(control_port: int, tor_password: str,
                      hidden_service_directories: list, listeners: list,
                      tor_data_directory_path: str, bridges: Optional[list] = None,
                      default_bridge_type: Optional[str] = None,
                      bridge_quantity: Optional[int] = None,
                      socks_port: Optional[int] = None) -> tuple:
    """
    Generate a configuration for a Tor client with specified parameters.

    Parameters:
        control_port (int): The port number for the Tor control interface.
        tor_password (str): The password to authenticate the Tor control interface.
        hidden_service_directories (list): A list of directories for hidden services.
        listeners (list): A list of tuples specifying the port mappings for hidden services.
                          Each tuple should contain (to_port, from_port).
        tor_data_directory_path (str): The file path to the Tor client's data directory.
        bridges (list): A list of bridges to be used by the Tor client.
        default_bridge_type (Optional[str]): The type of default bridge to
            use if no bridges are provided.
        bridge_quantity (Optional[int]): The number of default bridges to add if needed.
        socks_port (Optional[int]): The port number for the SOCKS proxy.

    Returns:
        tuple: A configuration dictionary containing the necessary settings for the Tor client.
    """

    if not isinstance(bridges, list):
        bridges = []

    quantity = 3 if bridge_quantity is None else bridge_quantity
    if default_bridge_type is not None:
        quantity = max(0, quantity - len(bridges))
        bridges.extend(get_default_bridges(default_bridge_type, quantity))

    hashed_tor_password = hash_tor_password(tor_password)

    configuration = [
        ("GeoIPFile", TOR_FILE_PATHS["geoip4"]),
        ("GeoIPv6File", TOR_FILE_PATHS["geoip6"]),
        ("DataDirectory", tor_data_directory_path),
        ("ControlPort", control_port),
        ("CookieAuthentication", 0),
        ("HashedControlPassword", hashed_tor_password),
        ("Log", "notice stdout"),
        ("ClientUseIPv6", 1),
        ("ClientPreferIPv6ORPort", 1),
        ("UseBridges", 1 if len(bridges) > 0 else 0)
    ]

    if socks_port is not None:
        configuration.append(("SocksPort", socks_port))

    required_pts = []
    for bridge in bridges:
        required_pts.append(get_bridge_type(bridge))

    for pluggable_transport, bridge_types in PLUGGABLE_TRANSPORTS.items():
        for bridge_type in bridge_types:
            if bridge_type in required_pts:
                transport = ','.join(bridge_types) + " exec " +\
                    TOR_FILE_PATHS.get(pluggable_transport)

                if pluggable_transport == "conjure":
                    transport += (
                        " -registerURL "
                        "https://registration.refraction.network/api"
                    )

                configuration.append(("ClientTransportPlugin", transport))
                break

    for bridge in bridges:
        configuration.append(("Bridge", bridge))

    for hidden_service_dir in hidden_service_directories:
        configuration.append(("HiddenServiceDir", hidden_service_dir))
        for listener in listeners:
            to_port, from_port = listener
            configuration.append(
                ("HiddenServicePort", str(to_port) + " 127.0.0.1:" + str(from_port))
            )

    return configuration


def get_percentage(output: str) -> Optional[int]:
    """
    Extracts the bootstrap percentage from a Tor startup output line.

    Args:
        output (str): The output string from the Tor startup process, which may contain
                      a line indicating the bootstrap progress.

    Returns:
        Optional[int]: The bootstrap percentage as an integer if found; otherwise, None.
    """

    match = re.search(r'Bootstrapped (\d+)%', output)

    if match:
        percent = match.group(1)

        if percent.isdigit():
            return int(percent)

    return None


class TorProcess:
    """
    A class to manage a Tor process.

    This class encapsulates the functionality required to start and control a Tor process,
    including handling the control port, authentication, and configuration settings.
    """


    def __init__(self, tor_process: subprocess.Popen, control_port: str, password: str,
                 data_directory_path: str, torrc_file_path: str,
                 socks_port: Optional[int] = None) -> None:
        """
        Initializes a tor process data structure.

        Args:
            tor_process (subprocess.Popen): The subprocess instance representing
                the running Tor process.
            control_port (str): The port used for controlling the Tor
                process via the control protocol.
            password (str): The password for authenticating with the Tor control port.
            data_directory_path (str): The file path to the directory where Tor stores its data.
            torrc_file_path (str): The file path to the Tor configuration file (torrc).
            socks_port (Optional[int]): The port used for SOCKS connections.
                If not specified, defaults to None.

        Returns:
            None: none
        """

        self.tor_process = tor_process
        self.control_port = control_port
        self.password = password
        self.data_directory_path = data_directory_path
        self.torrc_file_path = torrc_file_path
        self.socks_port = socks_port


class TorRunner:
    """
    TorRunner is a class that runs Tor based on the operating system and architecture.
    """


    @staticmethod
    def get_ports() -> Tuple[int, int]:
        """
        Retrieves available control and SOCKS ports for the Tor service.

        Returns:
            Tuple[int, int]: A tuple containing the available control port and SOCKS port.
        """

        control_port = find_available_port(9051, 65536)
        socks_port = find_available_port(9000, 65536, [control_port])

        return control_port, socks_port


    def __init__(self, hs_dirs: Optional[List[str]] = None,
                 bridges: Optional[List[str]] = None,
                 default_bridge_type: Optional[str] = None,
                 bridge_quantity: Optional[int] = None) -> None:
        """
        Initializes the TorRunner instance with specified hidden service directories, bridges,
        and other configuration options.

        Args:
            hs_dirs (Optional[List[str]]): A list of hidden service directory paths.
            bridges (Optional[List[str]]): A list of bridge addresses to use.
            default_bridge_type (Optional[str]): The default type of bridge to use.
            bridge_quantity (Optional[int]): The number of bridges to use.

        Returns:
            None
        """

        if not isinstance(hs_dirs, list):
            hs_dirs = []

        hidden_directories = []
        for hs_dir in hs_dirs:
            if not '/' in hs_dir and not '\\' in hs_dir:
                hs_dir = os.path.join(CURRENT_DIRECTORY_PATH, hs_dir)

            hidden_directories.append(hs_dir)

        self.hs_dirs = hidden_directories

        if not isinstance(bridges, list):
            bridges = []

        self.bridges = bridges
        self.tor_processes: List[TorProcess] = []

        self.default_bridge_type = default_bridge_type
        self.bridge_quantity = bridge_quantity

        if not verify_tor_installation():
            install_tor()


    @property
    def _hostnames(self) -> List[str]:
        """
        Retrieve a list of hostnames from hidden service directories.

        Returns:
            List[str]: A list of hostnames found in the hidden service directories.
        """

        hidden_service_directories = self.hs_dirs\
            if len(self.hs_dirs) > 0 else [HIDDEN_SERVICE_DIRECTORY_PATH]

        return find_hostnames(hidden_service_directories)


    def exit(self) -> None:
        """
        Terminates the Tor process and cleans up the associated data.

        Returns:
            None
        """

        for tor_process_data in self.tor_processes:
            try:
                tor_process_data.tor_process.terminate()
            finally:
                delete(tor_process_data.data_directory_path)
                delete(tor_process_data.torrc_file_path)


    def run(self, listeners: list, socks_port: Optional[Union[int, bool]] = None,
            quite: bool = False, wait: bool = True) -> None:
        """
        Runs the Tor process with the specified listeners and configuration.

        Args:
            listeners (list): A list of tuples specifying the listeners for the Tor service.
            quite (bool): If True, suppresses progress output. Defaults to False.
            wait (bool): If True, waits for the Tor process to
                finish before returning. Defaults to True.

        Returns:
            None
        """

        if not verify_tor_installation():
            if not quite:
                print("Installing Tor...")

            install_tor()

        hidden_service_directories = []
        if len(listeners) > 0:
            hidden_service_directories = self.hs_dirs\
                if len(self.hs_dirs) > 0 else [HIDDEN_SERVICE_DIRECTORY_PATH]

        tor_password = generate_secure_random_string(32)
        tor_data_directory_path = create_tor_data()

        free_control_port, free_socks_port = self.get_ports()
        if isinstance(socks_port, bool):
            socks_port = None

            if socks_port is True:
                socks_port = free_socks_port

        config = get_configuration(
            free_control_port, tor_password, hidden_service_directories,
            listeners, tor_data_directory_path, self.bridges,
            self.default_bridge_type, self.bridge_quantity,
            socks_port
        )

        config_string = configuration_to_str(config)
        torrc_file_path = create_temp_torrc(config_string)

        atexit.register(self.exit)

        commands = [TOR_FILE_PATHS["exe"], "-f", torrc_file_path]

        if OPERATING_SYSTEM == 'linux':
            current_ld_library_path = os.environ.get('LD_LIBRARY_PATH', '')
            path_to_extend = os.path.join(TOR_DIRECTORY_PATH, 'tor')

            if path_to_extend not in current_ld_library_path:
                new_ld_library_path = f'{current_ld_library_path}:{path_to_extend}'\
                    if current_ld_library_path else path_to_extend

                os.environ['LD_LIBRARY_PATH'] = new_ld_library_path

        tor_process = subprocess.Popen(
            commands, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True
        )

        tor_process_data = TorProcess(
            tor_process, free_control_port, tor_password,
            tor_data_directory_path, torrc_file_path, socks_port
        )

        self.tor_processes.append(tor_process_data)

        progress = None
        if not quite:
            progress = Progress("Tor establishes a secure connection...", 100)

        stdout = ""
        for _ in range(TOR_TIMEOUT * 10):
            ready, _, _ = select.select([tor_process.stdout], [], [], 0.1)
            if not ready:
                continue

            output = tor_process.stdout.readline()
            stdout += output

            output = output.replace("\n", "").strip()

            if output == '' and tor_process.poll() is not None:
                break

            if output:
                percentage = get_percentage(output)
                if not quite:
                    progress.messages.append(output)
                    if percentage is not None:
                        progress.update(percentage)
                    else:
                        progress.update()

                if percentage == 100:
                    os.remove(torrc_file_path)
                    break
        else:
            if not quite:
                print("\n\n[Error] Timeout occurred while starting Tor.")

            self.exit()
            return

        return_code = tor_process.returncode
        if isinstance(return_code, int):
            if return_code > 0:
                if not quite:
                    print("\n[Error] Error occurred while starting",
                          "Tor: (Code", str(return_code) + ")")
                    print(stdout)

                self.exit()
                return

        if wait:
            if not quite and len(hidden_service_directories) > 0:
                joined_hostnames = ", ".join(find_hostnames(hidden_service_directories))
                print("Running on", joined_hostnames, end = "")

            tor_process.wait()


    def flask_run(self, app, host: str = "127.0.0.1", port: int = 5000,
                  debug: bool = False, load_dotenv: bool = False, **kwargs) -> None:
        """
        Runs a Flask application on Tor using the specified parameters.

        Args:
            host (str): The hostname to listen on. Typically set to '127.0.0.1' for localhost.
            port (int): The port to bind the web server to. Defaults to 5000 if not provided.
            debug (bool): If set to True, enables Flask's debug mode, which activates the
                debugger and reloads the app upon file changes.
            load_dotenv (bool): If set to True, loads environment variables from a `.env` file.
            **kwargs: Additional keyword arguments passed to `flask.Flask.run()` 
                    (e.g., `use_reloader`, `threaded`, `ssl_context`).

        Returns:
            None
        """

        self.run([(80, port)], wait = False)

        print("Starting Flask now...\n")
        print(" * Running Flask on", ", ".join(self._hostnames), end = "")

        app.run(host, port, debug, load_dotenv, **kwargs)


    def sanic_run(self, app, host: str = "127.0.0.1", port: int = 5000, **kwargs) -> None:
        """
        Runs a Sanic application on Tor using the specified parameters.

        Args:
            app: The Sanic application instance to run.
            host (str): The hostname to listen on. Typically set to '127.0.0.1' for localhost.
            port (int): The port to bind the web server to. Defaults to 5000 if not provided.
            **kwargs: Additional keyword arguments passed to `sanic.Sanic.run()` 
                    (e.g., `debug`, `ssl`, `workers`, etc.).

        Returns:
            None
        """

        self.run([(80, port)], wait = False)

        print("Starting Sanic now...\n")

        async def main_process_start(_app):
            print(" " * 32 + "🧅 TOR:   Running Sanic on", ", ".join(self._hostnames), end = "")

        app.register_listener(main_process_start, 'main_process_start')
        app.run(host, port, **kwargs)


def main() -> None:
    """
    The main function called at start
    """

    if "--delete" in ARGUMENTS:
        delete(DATA_DIRECTORY_PATH)
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description = (
            "Run as a Tor hidden service, allowing configuration "
            "of listeners, hidden service directories, and bridges."
        )
    )
    parser.add_argument(
        "-p", "--port",
        type = int,
        default = None,
        help = "HTTP port for the hidden service to listen on."
    )
    parser.add_argument(
        "-l", "--listener",
        type = parse_listener,
        nargs = '*',
        default = [],
        help = "List of listeners in the format 'tor_port,listen_port'."
    )
    parser.add_argument(
        "-t", "--threads",
        type = int,
        default = 1,
        help = "How many times Tor should start. (default: 1)"
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
        "-s", "--socks-port",
        type = int,
        default = None,
        help = "SOCKS port for Tor connections."
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
        "--bridge-quantity",
        type = int,
        default = None,
        help = "Number of bridges to use for connecting to the Tor network."
    )
    parser.add_argument(
        "--default-bridge-type",
        type = str,
        default = None,
        help = "Default bridge type to use when connecting to Tor."
    )
    parser.add_argument(
        "--delete",
        action = "store_true",
        help = "Delete all data associated with tor_runner."
    )
    parser.add_argument(
        "--quiet",
        action = "store_true",
        help = "Run the script in quiet mode with no output."
    )

    args = parser.parse_args()
    listener = []

    port = getattr(args, "port", None)
    if port is not None:
        listener.append((80, port))

    listener_arg = getattr(args, "listener", None)
    if isinstance(listener_arg, list):
        flat_listener = list(chain.from_iterable(listener_arg))
        listener.extend(flat_listener)

    socks_port = None
    arg_socks_port = getattr(args, "socks_port", None)
    if isinstance(arg_socks_port, int):
        if arg_socks_port == 1:
            arg_socks_port = True

        socks_port = arg_socks_port

    tor_runner = TorRunner(
        hs_dirs = getattr(args, "hidden_service_dirs", None),
        bridges = getattr(args, "bridges", None),
        default_bridge_type = getattr(args, "default_bridge_type", None),
        bridge_quantity = getattr(args, "bridge_quantity", None)
    )
    tor_runner.run(listener, socks_port, getattr(args, "quiet", False))


if __name__ == "__main__":
    main()
