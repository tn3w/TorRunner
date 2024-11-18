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

from os import mkdir, listdir, path

import io
import sys
import atexit
import select
import argparse
import subprocess
from itertools import chain
from sys import argv as ARGUMENTS
from multiprocessing import Process
from contextlib import contextmanager
from typing import Final, Optional, Tuple, Union, Generator, List, Dict

try:
    from utils.tor import hash_control_password, get_bridge_type
    from utils.utils import find_available_port, generate_secure_random_string
    from utils.files import DirectoryLock, WORK_DIRECTORY_PATH, TOR_FILE_PATHS, delete
except ImportError:
    from .utils.tor import hash_control_password, get_bridge_type
    from .utils.utils import find_available_port, generate_secure_random_string
    from .utils.files import DirectoryLock, WORK_DIRECTORY_PATH, TOR_FILE_PATHS, delete


PLUGGABLE_TRANSPORTS: Final[dict] = {
    "lyrebird": ["meek_lite", "obfs2", "obfs3", "obfs4", "scramblesuit", "webtunnel"],
    "snowflake": ["snowflake"],
    "conjure": ["conjure"]
}


TOR_TIMEOUT = 120 # Seconds


class TorConfiguration:


    @staticmethod
    def configuration_to_str(configurations: list) -> str:
        """
        Convert a list of configuration key-value pairs into a formatted string.

        Parameters:
            configurations (list): A tuple containing key-value pairs, where each pair 
                is expected to be a tuple of (key, value).

        Returns:
            str: A formatted string representation of the configuration, with each 
                key-value pair on a new line.
        """

        configuration_str = ""
        for pair in configurations:
            key, value = pair

            if not isinstance(value, str):
                try:
                    value = str(value)
                except ValueError:
                    continue

            configuration_str += key + " " + value + "\n"

        return configuration_str


    def __init__(self, hidden_service_directories: Dict[str, list], bridges: list,
                 control_port: Optional[int] = None, control_password: Optional[str] = None,
                 socks_port: Optional[int] = None, vanguard_threads: Optional[int] = None):

        self.hidden_service_directories = hidden_service_directories
        self.bridges = bridges

        self.socks_port = socks_port or None
        self.control_port = control_port or find_available_port(9051, exclude_ports = [socks_port])

        control_password = control_password or generate_secure_random_string(32)
        self.hashed_control_password = hash_control_password(control_password)
        self.control_password = control_password

        self.vanguard_threads = vanguard_threads or 0

        def get_new_path() -> str:
            while True:
                random_path = path.join(WORK_DIRECTORY_PATH, generate_secure_random_string(16))
                if not os.path.exists(random_path):
                    return random_path

        # FIXME: Rotating torrc and data directory name length
        data_directory_path = get_new_path()
        mkdir(data_directory_path)

        self.data_directory_path = data_directory_path
        self.torrc_file_path = get_new_path()


    def __str__(self) -> str:
        configuration = [
            ("GeoIPFile", TOR_FILE_PATHS["geoip"]),
            ("GeoIPv6File", TOR_FILE_PATHS["geoip6"]),
            ("DataDirectory", self.data_directory_path),
            ("ControlPort", self.control_port),
            ("SocksPort", self.socks_port if self.socks_port else 0),
            ("HashedControlPassword", self.hashed_control_password),
            ("Log", "notice stdout"),
            ("ClientUseIPv6", 1),
            ("AvoidDiskWrites", 1),
            ("ClientOnly", 1),
            ("ClientPreferIPv6ORPort", 1),
            ("UseBridges", 1 if self.bridges else 0)
        ]

        required_pluggable_transports = []
        for bridge in self.bridges:
            required_pluggable_transports.append(get_bridge_type(bridge))
            configuration.append(("Bridge", bridge))

        for pluggable_transport, bridge_types in PLUGGABLE_TRANSPORTS.items():
            for bridge_type in bridge_types:
                if bridge_type not in required_pluggable_transports:
                    continue

                transport = ','.join(bridge_types) + " exec " + \
                    TOR_FILE_PATHS.get(pluggable_transport)

                if pluggable_transport == "conjure":
                    transport += (
                        " -registerURL "
                        "https://registration.refraction.network/api"
                    )

                configuration.append(("ClientTransportPlugin", transport))
                break

        for hidden_service_dir, listeners in self.hidden_service_directories.items():
            configuration.append(("HiddenServiceDir", hidden_service_dir))
            for to_port, from_port in listeners:
                configuration.append(
                    ("HiddenServicePort", str(to_port) + " 127.0.0.1:" + str(from_port))
                )

        return self.configuration_to_str(configuration)


class TorProcess:
    """
    A class to manage a Tor process.

    This class encapsulates the functionality required to start and control a Tor process,
    including handling the control port, authentication, and configuration settings.
    """


    def __init__(self, configuration: TorConfiguration,
                 tor_process: subprocess.Popen, directory_lock_stream: io.TextIOWrapper) -> None:
        """
        Initializes a tor process data structure.

        Args:
            tor_process (subprocess.Popen): The subprocess instance representing
                the running Tor process.

        Returns:
            None: none
        """

        # FIXME: Update docstring

        self.configuration = configuration
        self.tor_process = tor_process
        self.directory_lock_stream = directory_lock_stream
        self.vanguard_process: Optional[Process] = None


def clean() -> None:
    for file_or_directory_name in listdir(WORK_DIRECTORY_PATH):
        if not len(file_or_directory_name) == 16:
            continue

        file_or_directory_path = path.join(WORK_DIRECTORY_PATH, file_or_directory_name)
        # FIXME: torrc locking
        if path.isdir(file_or_directory_path) and DirectoryLock(file_or_directory_path).locked:
            continue

        # FIXME: secure delete with SecureShredder - Scary!
        delete(file_or_directory_path)


class TorRunner:
    """
    TorRunner is a class that runs Tor based on the operating system and architecture.
    """

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

    print("""
░▀▀█▀▀░▄▀▀▄░█▀▀▄░▒█▀▀▄░█░▒█░█▀▀▄░█▀▀▄░█▀▀░█▀▀▄
░░▒█░░░█░░█░█▄▄▀░▒█▄▄▀░█░▒█░█░▒█░█░▒█░█▀▀░█▄▄▀
░░▒█░░░░▀▀░░▀░▀▀░▒█░▒█░░▀▀▀░▀░░▀░▀░░▀░▀▀▀░▀░▀▀

Author: TN3W
GitHub: https://github.com/tn3w/TorRunner
""")

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
        "-e", "--execute",
        action = "store_true",
        help = "Executes your command directly via Tor."
    )
    parser.add_argument(
        "-r", "--remove",
        action = "store_true",
        help = "Remove all data associated with tor_runner."
    )
    parser.add_argument(
        "-q", "--quiet",
        action = "store_true",
        help = "Run the script in quiet mode with no output."
    )

    args = parser.parse_args()

    print(args)

    return

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
