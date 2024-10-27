"""
tor_runner.py

This module provides a comprehensive set of functions and classes for managing Tor
installation, configuration, and execution. It includes utilities for verifying Tor
installations, downloading and extracting the necessary files, managing pluggable
transports, and setting up bridges. The module also facilitates running web applications
like Flask and Sanic on the Tor network, allowing for hidden services and secure connections.

License: GNU General Public License v3.0
    https://github.com/tn3w/TorRunner/blob/master/LICENSE
Source: https://github.com/tn3w/TorRunner
"""

import re
import os
import io
import sys
import socket
import atexit
import select
import hashlib
import secrets
import argparse
import binascii
import subprocess
import http.client
import urllib.error
import urllib.request
from itertools import chain
from sys import argv as ARGUMENTS
from multiprocessing import Process
from contextlib import contextmanager
from typing import Optional, Tuple, Union, Generator, List, Any

try:
    from .common import (
        TOR_DIRECTORY_PATH, IMPORTANT_FILE_KEYS, TOR_FILE_PATHS, IS_WINDOWS,
        OPERATING_SYSTEM, ARCHITECTURE, ERROR_MESSAGE, TOR_ARCHIVE_FILE_PATH,
        DEBUG_DIRECTORY_PATH, PLUGGABLE_TRANSPORTS_DIRECTORY_PATH,
        DEFAULT_BRIDGES, DATA_DIRECTORY_PATH, PLUGGABLE_TRANSPORTS,
        CURRENT_DIRECTORY_PATH, HIDDEN_SERVICE_DIRECTORY_PATH, Progress, DirectoryLock,
        extract_links, download_file, extract_tar, delete, find_available_port,
        find_hostnames, configuration_to_str, generate_secure_random_string, write
    )
except ImportError:
    from common import (
        TOR_DIRECTORY_PATH, IMPORTANT_FILE_KEYS, TOR_FILE_PATHS, IS_WINDOWS,
        OPERATING_SYSTEM, ARCHITECTURE, ERROR_MESSAGE, TOR_ARCHIVE_FILE_PATH,
        DEBUG_DIRECTORY_PATH, PLUGGABLE_TRANSPORTS_DIRECTORY_PATH,
        DEFAULT_BRIDGES, DATA_DIRECTORY_PATH, PLUGGABLE_TRANSPORTS,
        CURRENT_DIRECTORY_PATH, HIDDEN_SERVICE_DIRECTORY_PATH, Progress, DirectoryLock,
        extract_links, download_file, extract_tar, delete, find_available_port,
        find_hostnames, configuration_to_str, generate_secure_random_string, write
    )


TOR_TIMEOUT = 120 # Seconds


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


def get_tor_download_url(operating_system: str, architecture: str) -> Optional[str]:
    """
    Retrieves the download URL for the Tor Expert Bundle based on the operating system
    and system architecture provided.

    Args:
        operating_system (str): The operating system for which the Tor
            package is required (e.g., 'windows', 'linux', 'mac').
        architecture (str): The architecture of the system (e.g., 'x86_64', 'i686').

    Returns:
        Optional[str]: The download URL for the matching
            Tor Expert Bundle, or None if no matching URL is found.
    """

    def matches(url: str) -> bool:
        return "archive.torproject.org/tor-package-archive/torbrowser" in url \
                and operating_system.lower() in url and "tor-expert-bundle" in url \
                    and architecture.lower() in url and not url.endswith(".asc")

    download_page_url = "https://www.torproject.org/download/tor/"

    req = urllib.request.Request(
        download_page_url, headers = {"Range": "bytes=0-", "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            " (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.3"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout = 3) as response:
            html = ""
            while True:
                chunk = response.read(128).decode("utf-8", errors = "ignore")
                if not chunk:
                    break

                html += chunk

                urls = extract_links(html)
                for url in urls:
                    if matches(url):
                        return url

    except (urllib.error.HTTPError, urllib.error.URLError, socket.timeout,
            FileNotFoundError, PermissionError, http.client.RemoteDisconnected,
            UnicodeEncodeError, TimeoutError, http.client.IncompleteRead,
            http.client.HTTPException, ConnectionResetError, ConnectionAbortedError,
            ConnectionRefusedError, ConnectionError):
        pass

    return None


def install_tor(download_url: str) -> Optional[str]:
    """
    Downloads and installs the Tor Expert Bundle from the provided URL.

    Args:
        download_url (str): The URL to download the Tor package from.

    Returns:
        None: This function installs the Tor package to the appropriate directory,
            removing temporary files and ensuring the installation is verified.
    """

    is_downloaded = download_file(download_url, TOR_ARCHIVE_FILE_PATH)
    if not is_downloaded:
        return "Tor download failed."

    extracted_successfully = extract_tar(TOR_ARCHIVE_FILE_PATH, TOR_DIRECTORY_PATH)

    delete(TOR_ARCHIVE_FILE_PATH)
    delete(DEBUG_DIRECTORY_PATH)

    if IS_WINDOWS:
        delete(os.path.join(TOR_DIRECTORY_PATH, "tor", "tor-gencert.exe"))

    for file_name in os.listdir(PLUGGABLE_TRANSPORTS_DIRECTORY_PATH):
        normalized_file_name = file_name.strip().lower()
        if not normalized_file_name.startswith(("readme", "pt_config")):
            continue

        full_path = os.path.join(PLUGGABLE_TRANSPORTS_DIRECTORY_PATH, file_name)
        delete(full_path)

    if not extracted_successfully:
        return "Tor could not be extracted successfully."

    valid_installation = verify_tor_installation()
    if not valid_installation:
        return "An error occured while installing Tor."

    return None


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


def create_tor_data(random_name: str) -> str:
    """
    Creates a new directory for Tor data with a randomly generated name.

    Returns:
        str: The path to the newly created Tor data directory.
    """

    tor_data_directory_path = os.path.join(DATA_DIRECTORY_PATH, f"{random_name}.data")

    if not os.path.exists(tor_data_directory_path):
        os.makedirs(tor_data_directory_path, exist_ok = True)

    return tor_data_directory_path


def create_temp_torrc(content: str, random_name: str) -> str:
    """
    Creates a temporary Tor configuration file with a randomly generated name.

    Args:
        content (str): The content to be written to the Tor configuration file.

    Returns:
        str: The path to the newly created Tor configuration file.
    """

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
        ("SocksPort", 0 if socks_port is None else socks_port),
        ("CookieAuthentication", 0),
        ("HashedControlPassword", hashed_tor_password),
        ("Log", "notice stdout"),
        ("ClientUseIPv6", 1),
        ("AvoidDiskWrites", 1),
        ("ClientOnly", 1),
        ("ClientPreferIPv6ORPort", 1),
        ("UseBridges", 1 if len(bridges) > 0 else 0)
    ]

    required_pts = []
    for bridge in bridges:
        required_pts.append(get_bridge_type(bridge))

    for pluggable_transport, bridge_types in PLUGGABLE_TRANSPORTS.items():
        for bridge_type in bridge_types:
            if bridge_type in required_pts:
                transport = ','.join(bridge_types) + " exec " + \
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
                 data_directory_path: str, directory_lock_stream: io.TextIOWrapper,
                 torrc_file_path: str, socks_port: Optional[int] = None) -> None:
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
        self.directory_lock_stream = directory_lock_stream
        self.torrc_file_path = torrc_file_path
        self.socks_port = socks_port
        self.vanguard_process: Optional[Process] = None


class TorRunner:
    """
    TorRunner is a class that runs Tor based on the operating system and architecture.
    """


    @staticmethod
    def clean() -> None:
        """
        Cleans up the data directory by removing specific files and directories.

        Args:
            None

        Returns:
            None
        """

        for file_or_directory_name in os.listdir(DATA_DIRECTORY_PATH):
            file_or_directory_path = os.path.join(DATA_DIRECTORY_PATH, file_or_directory_name)
            if not file_or_directory_name.endswith(".data") or\
                not os.path.isdir(file_or_directory_path):

                continue

            if DirectoryLock(file_or_directory_path).locked:
                continue

            delete(file_or_directory_path)

            random_name = file_or_directory_name.split(".data")[0]
            delete(os.path.join(DATA_DIRECTORY_PATH, random_name + ".torrc"))


    @staticmethod
    def set_ld_library_path_environ() -> None:
        """
        Sets the 'LD_LIBRARY_PATH' environment variable
        to include the path to the Tor library.

        Returns:
            None
        """

        if OPERATING_SYSTEM != 'linux':
            return

        current_ld_library_path = os.environ.get('LD_LIBRARY_PATH', '')
        path_to_extend = os.path.join(TOR_DIRECTORY_PATH, 'tor')

        if path_to_extend in current_ld_library_path:
            return

        new_ld_library_path = f'{current_ld_library_path}:{path_to_extend}' \
            if current_ld_library_path else path_to_extend

        os.environ['LD_LIBRARY_PATH'] = new_ld_library_path


    @staticmethod
    def verify_or_install_tor(quiet: bool = True) -> None:
        """
        Verifies if Tor is installed and installs it if it is not.

        Args:
            quiet (bool): If True, suppresses progress output. Defaults to False.

        Returns:
            None
        """

        if verify_tor_installation():
            return

        if not quiet:
            print("Getting Tor download url...")
        download_url = get_tor_download_url(OPERATING_SYSTEM, ARCHITECTURE)

        if not quiet:
            print("Installing Tor...")
        error_message = install_tor(download_url)

        if error_message is not None:
            raise OSError(error_message + " " + ERROR_MESSAGE)


    @staticmethod
    def direct(*args, wait: bool = True) -> None:
        """
        Runs the Tor executable with the specified arguments.

        Args:
            *args: Additional command-line arguments to pass to the Tor executable.
            wait (bool): If set to True, the method will wait for the Tor process to finish.

        Returns:
            None
        """

        TorRunner.verify_or_install_tor()
        TorRunner.set_ld_library_path_environ()

        commands = [TOR_FILE_PATHS["exe"], "--quiet"]
        commands.extend(args)

        tor_process = subprocess.Popen(
            commands, text=True
        )

        if wait:
            tor_process.wait()


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
                 vanguards_threads: int = 0,
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
        self.vanguards_threads = vanguards_threads
        self.tor_processes: List[TorProcess] = []

        self.default_bridge_type = default_bridge_type
        self.bridge_quantity = bridge_quantity


    @property
    def _hostnames(self) -> List[str]:
        """
        Retrieve a list of hostnames from hidden service directories.

        Returns:
            List[str]: A list of hostnames found in the hidden service directories.
        """

        hidden_service_directories = self.hs_dirs \
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
                try:
                    if tor_process_data.vanguard_process is not None:
                        tor_process_data.vanguard_process.terminate()
                        tor_process_data.vanguard_process.join()
                except AttributeError:
                    pass

                try:
                    DirectoryLock(tor_process_data.data_directory_path)\
                        .remove(tor_process_data.directory_lock_stream)
                    delete(tor_process_data.data_directory_path)
                    delete(tor_process_data.torrc_file_path)

                    TorRunner.clean()
                except ValueError:
                    pass


    def run(self, listeners: list, socks_port: Optional[Union[int, bool]] = None,
            quiet: bool = False, wait: bool = True) -> None:
        """
        Runs the Tor process with the specified listeners and configuration.

        Args:
            listeners (list): A list of tuples specifying the listeners for the Tor service.
            socks_port (Optional[Union[int, bool]]): The port for SOCKS proxy.
            quiet (bool): If True, suppresses progress output. Defaults to False.
            wait (bool): If True, waits for the Tor process to
                finish before returning. Defaults to True.

        Returns:
            None
        """

        self.verify_or_install_tor(quiet)

        hidden_service_directories = []
        if len(listeners) > 0:
            hidden_service_directories = self.hs_dirs \
                if len(self.hs_dirs) > 0 else [HIDDEN_SERVICE_DIRECTORY_PATH]

        def tor_run(socks_port: Optional[Union[int, bool]] = None) -> bool:
            control_password = generate_secure_random_string(32)

            random_name = generate_secure_random_string(16)
            tor_data_directory_path = create_tor_data(random_name)

            free_control_port, free_socks_port = self.get_ports()
            if isinstance(socks_port, bool):
                socks_port = None

                if socks_port is True:
                    socks_port = free_socks_port

            config = get_configuration(
                free_control_port, control_password, hidden_service_directories,
                listeners, tor_data_directory_path, self.bridges,
                self.default_bridge_type, self.bridge_quantity,
                socks_port
            )

            config_string = configuration_to_str(config)
            torrc_file_path = create_temp_torrc(config_string, random_name)

            atexit.register(self.exit)

            self.set_ld_library_path_environ()

            commands = [TOR_FILE_PATHS["exe"], "-f", torrc_file_path]
            tor_process = subprocess.Popen(
                commands, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True
            )

            data_directory_lock_stream = DirectoryLock(
                tor_data_directory_path
            ).create(tor_process.pid)

            tor_process_data = TorProcess(
                tor_process, free_control_port, control_password, tor_data_directory_path,
                data_directory_lock_stream, torrc_file_path, socks_port
            )

            self.tor_processes.append(tor_process_data)

            progress = None
            if not quiet:
                progress = Progress("Tor establishes a secure connection...", 100)

            stdout = ""
            for _ in range(TOR_TIMEOUT * 10):
                try:
                    ready, _, _ = select.select([tor_process.stdout], [], [], 0.1)
                    if not ready:
                        continue
                except OSError:
                    pass

                output = tor_process.stdout.readline()
                stdout += output

                output = output.replace("\n", "").strip()

                if output == '' and tor_process.poll() is not None:
                    break

                if output:
                    percentage = get_percentage(output)
                    if not quiet:
                        progress.messages.append(output)
                        if percentage is not None:
                            progress.update(percentage)
                        else:
                            progress.update()

                    if percentage == 100:
                        delete(torrc_file_path)
                        break

            else:
                if not quiet:
                    print("\n\n[Error] A timeout occurred while starting Tor.",
                          "Use bridges with `-b <BRIDGE>` or the default bridges with",
                          "`--default-bridge-type obfs4`.")

                self.exit()
                return False

            return_code = tor_process.returncode
            if isinstance(return_code, int):
                if return_code > 0:
                    if not quiet:
                        print("\n[Error] Error occurred while starting",
                              "Tor: (Code", str(return_code) + ")")
                        print(stdout)

                    self.exit()
                    return False

            return True

        started_sucessfully = tor_run(socks_port)
        if not started_sucessfully:
            return

        if not quiet and len(hidden_service_directories) > 0:
            joined_hostnames = ", ".join(find_hostnames(hidden_service_directories))
            print("Running on", joined_hostnames, end = "")

        if wait and self.vanguards_threads == 0:
            self.tor_processes[0].tor_process.wait()

        if self.vanguards_threads != 0:
            try:
                import stem as _
            except ImportError:
                print(
                    "\n[Vanguards Error] Stem is not installed, install stem with "
                    "`pip install stem` after you have created a virtual "
                    "environment: `python3 -m venv .venv` and activated: "
                    "`source .venv/bin/activate`."
                )
                return

            try:
                from libraries.vanguards import Vanguards
            except ImportError as exc1:
                try:
                    from .libraries.vanguards import Vanguards
                except ImportError as exc2:
                    if not quiet:
                        print("\n[Vanguards Error] Error occurred while importing Vanguards:\n",
                              exc1 + "\n", exc2)

                    return

            if not quiet:
                print("\nTrying to start Vanguards...")

            new_tor_processes = []
            for tor_process in self.tor_processes:
                vanguards = Vanguards(
                    tor_process.data_directory_path,
                    tor_process.control_port, tor_process.password
                )

                vanguard_process = Process(
                    target = vanguards.run, args = (self.vanguards_threads, )
                )
                vanguard_process.run()

                tor_process.vanguard_process = vanguard_process
                new_tor_processes.append(tor_process)


    @contextmanager
    def context_run(self, listeners: list, socks_port: Optional[Union[int, bool]] = None,
                    quiet: bool = False) -> Generator:
        """
        Context manager to start and stop Tor process with specified listeners.

        Args:
            listeners (list): A list of tuples specifying the listeners for the Tor service.
            socks_port (Optional[Union[int, bool]]): The port for SOCKS proxy.
            quiet (bool): If True, suppresses progress output. Defaults to False.

        Yields:
            None
        """

        try:
            self.run(listeners, socks_port, quiet, False)
            yield
        finally:
            self.exit()


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


def run_main() -> None:
    """
    The main function called at start
    """

    TorRunner.clean()

    if "--delete" in ARGUMENTS:
        delete(DATA_DIRECTORY_PATH)
        sys.exit(0)

    if "--direct" in ARGUMENTS:
        arguments = ARGUMENTS[1:]

        try:
            arguments.remove("--direct")
        except ValueError:
            pass

        TorRunner.direct(*arguments)
        sys.exit()

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
        "--direct",
        action = "store_true",
        help = "Executes your command directly via Tor."
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

    tor_runner = TorRunner(
        hs_dirs = getattr(args, "hidden_service_dirs", None),
        bridges = getattr(args, "bridges", None),
        vanguards_threads = getattr(args, "vanguards", 0),
        default_bridge_type = getattr(args, "default_bridge_type", None),
        bridge_quantity = getattr(args, "bridge_quantity", None)
    )

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

    tor_runner.run(listener, socks_port, getattr(args, "quiet", False))


def main():
    """
    Runs main and handles KeyboardInterrupt.
    """

    try:
        run_main()
    except KeyboardInterrupt:
        print("\nReceived CTRL+C command. Exiting now.")
        sys.exit(0)


if __name__ == "__main__":
    main()
