"""
-~- TorRunner - A simple Tor runner. -~-
This package is distributed under the terms of the
GNU General Public License version 3. It provides a simple
way to run Tor using Python. Tor is automatically downloaded,
extracted and installed. The configuration is then automatically
loaded and the app is started.

Made with ❤️ by TN3W - https://github.com/tn3w/TorRunner
"""

import os
import re
import time
import atexit
import argparse
import subprocess
from threading import Thread
from typing import List, Optional, Final, Tuple

try:
    from tor_runner.utils import DATA_DIRECTORY_PATH, OPERATING_SYSTEM, ARCHITECTURE, request_url,\
        extract_anchors, download_file, extract_tar, find_file, find_available_port, has_permission
except ImportError:
    from utils import DATA_DIRECTORY_PATH, OPERATING_SYSTEM, ARCHITECTURE, request_url,\
        extract_anchors, download_file, extract_tar, find_file, find_available_port, has_permission


FILE_EXT: Final[str] = '.exe' if OPERATING_SYSTEM == 'windows' else ''
HIDDEN_SERVICE_DIRECTORY_PATH: Final[str] = os.path.join(DATA_DIRECTORY_PATH, "hs")

LOG_FILE_PATH: Final[str] = os.path.join(DATA_DIRECTORY_PATH, "tor.log")

TOR_ARCHIVE_FILE_PATH: Final[str] = os.path.join(DATA_DIRECTORY_PATH, "tor.tar.gz")
TOR_DIRECTORY_PATH: Final[str] = os.path.join(DATA_DIRECTORY_PATH, "tor")

DEFAULT_TOR_FILE_PATHS: Final[str] = {
    "geoip4": os.path.join(TOR_DIRECTORY_PATH, "data", "geoip"),
    "geoip6": os.path.join(TOR_DIRECTORY_PATH, "data", "geoip6"),
    "lyrebird": os.path.join(
        TOR_DIRECTORY_PATH, "tor", "pluggable_transports", "lyrebird" + FILE_EXT),
    "snowflake": os.path.join(
        TOR_DIRECTORY_PATH, "tor", "pluggable_transports", "snowflake-client" + FILE_EXT),
    "conjure": os.path.join(
        TOR_DIRECTORY_PATH, "tor", "pluggable_transports", "conjure-client" + FILE_EXT),
    "exe": os.path.join(
        TOR_DIRECTORY_PATH, "tor", ("libTor.so" if OPERATING_SYSTEM == "Linux" else "Tor.exe")),
}

POTENTIAL_TOR_DIRECTORIES: Final[dict] = {
    "windows": [
        os.path.join(os.environ.get("USERPROFILE", ""), "Desktop", "Tor Browser"),
        os.path.join(os.environ.get("PROGRAMFILES", ""), "Tor Browser"),
        os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Tor Browser"),
    ],
    "macos": [
        "/Applications/Tor Browser.app/Contents/Resources"
    ],
    "linux": [
        os.path.expanduser("~/.local/share/tor-browser"),
        "/usr/local/tor",
        "/usr/bin/tor",
        "/usr/local/bin/tor"
    ],
    "android": [
        os.path.join(os.environ.get("HOME", ""), "tor")
    ]
}

PLUGGABLE_TRANSPORTS: Final[dict] = {
    "lyrebird": ["meek_lite", "obfs2", "obfs3", "obfs4", "scramblesuit", "webtunnel"],
    "snowflake": ["snowflake"],
    "conjure": ["conjure"]
}


def install_tor() -> None:
    """
    Installs Tor based on the operating system and architecture.

    :return: None
    """

    url = 'https://www.torproject.org/download/tor/'

    download_url = None
    content = request_url(url, return_as_bytes = False)

    if content is not None:
        anchors = extract_anchors(content)

        for anchor in anchors:
            if "archive.torproject.org/tor-package-archive/torbrowser" in anchor\
                and OPERATING_SYSTEM.lower() in anchor and "tor-expert-bundle" in anchor\
                    and ARCHITECTURE.lower() in anchor and not anchor.endswith(".asc"):

                download_url = anchor
                break

    if download_url is None:
        raise OSError("Tor download URL not found. Please install manual for your "+
                        "system from https://www.torproject.org/en/download/tor/ and "+
                        f"extract it to `{TOR_DIRECTORY_PATH}`.")

    is_downloaded = download_file(download_url, TOR_ARCHIVE_FILE_PATH)
    if not is_downloaded:
        raise OSError("Tor download failed.")

    extract_tar(TOR_ARCHIVE_FILE_PATH, TOR_DIRECTORY_PATH)
    os.remove(TOR_ARCHIVE_FILE_PATH)


def find_tor_file_paths() -> Optional[dict]:
    """
    Finds the Tor directory based on the operating system and architecture.

    :return: The path to the Tor directory.
    """

    potential_directories = POTENTIAL_TOR_DIRECTORIES.get(OPERATING_SYSTEM, [])

    for dir_path in potential_directories:
        tor_file_paths = {}
        for key, file_name in [
                ('geoip4', 'geoip'),
                ('geoip6', 'geoip6'),
                ('lyrebird', 'lyrebird' + FILE_EXT),
                ('snowflake', 'snowflake-client' + FILE_EXT),
                ('conjure', 'conjure-client' + FILE_EXT),
                ('exe', 'libTor.so' if OPERATING_SYSTEM == "Linux" else 'Tor.exe'),
            ]:

            found_file_path = find_file(file_name, dir_path)
            if found_file_path is not None:
                tor_file_paths[key] = found_file_path

        if len(tor_file_paths) == 6:
            return tor_file_paths

    return None


class TorRunner:
    """
    TorRunner is a class that runs Tor based on the operating system and architecture.
    """


    def __init__(self, app = None, bridges: Optional[List[str]] = None,
                 hs_dirs: Optional[List[str]] = None) -> None:
        """
        Initializes TorRunner.

        :param app: Flask app.
        :param host: an IPv4 or IPv6 address.
        :param port: the port to listen on.
        :param bridges: list of bridges.
        :param hs_dirs: list of hidden service directories.
        """

        self.app = app

        self.host = None
        self.port = None

        hs_dirs = hs_dirs or []

        hidden_directories = []
        for hs_dir in hs_dirs:
            if not '/' in hs_dir and not '\\' in hs_dir:
                hidden_directories.append(os.path.join(DATA_DIRECTORY_PATH, hs_dir))

        self.bridges = bridges or []
        self.hs_dirs = hidden_directories

        tor_file_paths = find_tor_file_paths()

        if not isinstance(tor_file_paths, dict)\
            or tor_file_paths.keys() != DEFAULT_TOR_FILE_PATHS.keys():

            if not os.path.isfile(DEFAULT_TOR_FILE_PATHS["exe"]):
                install_tor()

            tor_file_paths = DEFAULT_TOR_FILE_PATHS

        self.tor_file_paths = tor_file_paths
        self.tor_process = None
        self.running = True


    @staticmethod
    def get_ports() -> Tuple[int, int]:
        """
        Function for getting control and socks port.

        :return: Tuple of control and socks port.
        """

        control_port = find_available_port(9051, 10000)
        socks_port = find_available_port(9000, 10000, control_port)

        return control_port, socks_port


    @staticmethod
    def get_bridge_type(bridge_string: str) -> str:
        """
        Function for getting bridge type.

        :param bridge_string: bridge string
        :return: bridge type
        """

        pattern = (r'^(.*?)\s*(?:\d{1,3}\.){3}\d{1,3}|'
                r'\[(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\]')

        match = re.match(pattern, bridge_string)
        if match:
            bridge_type = match.group(1).strip()
            if bridge_type:
                return bridge_type
        return "vanilla"


    @staticmethod
    def delete_lock() -> None:
        """
        Function for deleting lock.
        """

        lock_file_path = os.path.join(DATA_DIRECTORY_PATH, 'lock')

        if not os.path.isfile(lock_file_path)\
            or not has_permission(lock_file_path, 'w'):

            return

        try:
            os.remove(lock_file_path)
        except Exception:
            pass


    @staticmethod
    def delete_torrc() -> None:
        """
        Function for deleting torrc.
        """

        torrc_path = os.path.join(DATA_DIRECTORY_PATH, 'torrc')

        time.sleep(3)

        if not os.path.isfile(torrc_path)\
            or not has_permission(torrc_path, 'w'):

            return

        try:
            os.remove(torrc_path)
        except Exception:
            pass


    def find_hostnames(self) -> List[str]:
        """
        Function for finding hostnames.

        :return: List of hostnames.
        """

        hostnames = []

        for hs_dir in (self.hs_dirs if len(self.hs_dirs)\
                        > 0 else [HIDDEN_SERVICE_DIRECTORY_PATH]):

            hostname_path = os.path.join(hs_dir, 'hostname')

            file_exists = False
            for _ in range(20):
                if os.path.isfile(hostname_path):
                    file_exists = True
                    break

                time.sleep(0.2)

            if not file_exists:
                continue

            try:
                with open(hostname_path, 'r', encoding = 'utf-8') as file:
                    hostname = file.read().strip()
                    hostnames.append(f"http://{hostname}")
            except Exception as e:
                print(f"Error reading {hostname_path}: {e}")

        return hostnames


    def configure_tor(self) -> str:
        """
        Function for configuring Tor.

        :return: Path to torrc file.
        """

        control_port, socks_port = self.get_ports()

        configuration = {
            "GeoIPFile": self.tor_file_paths["geoip4"],
            "GeoIPv6File": self.tor_file_paths["geoip6"],
            "DataDirectory": DATA_DIRECTORY_PATH,
            "Control" + ("Port" if OPERATING_SYSTEM == 'windows' else "Socket"): control_port,
            "SocksPort": socks_port,
            "CookieAuthentication": 1,
            "CookieAuthFile": os.path.join(DATA_DIRECTORY_PATH, 'cookie.txt'),
            "Log": "notice stdout",
            "ClientUseIPv6": 1,
            "ClientPreferIPv6ORPort": 1,
            "HiddenServiceDirs": [] if len(self.hs_dirs) > 0 else [HIDDEN_SERVICE_DIRECTORY_PATH],
            "\nUseBridges": 1 if len(self.bridges) > 0 else None,
            "ClientTransportPlugins": []
        }

        if len(self.hs_dirs) > 0:
            configuration["HiddenServiceDirs"].extend(self.hs_dirs)

        required_pts = []
        for bridge in self.bridges:
            required_pts.append(self.get_bridge_type(bridge))

        for pluggable_transport, bridge_types in PLUGGABLE_TRANSPORTS.items():
            for bridge_type in bridge_types:
                if bridge_type in required_pts:
                    configuration["ClientTransportPlugins"].append(
                        ','.join(bridge_types) + " exec "
                        + self.tor_file_paths.get(pluggable_transport)
                    )

                    break

        configuration_str = ""
        for key, value in configuration.items():
            if value is None:
                continue

            if key == "HiddenServiceDirs":
                for hs_dir in value:
                    configuration_str += f"HiddenServiceDir {hs_dir}\n"+\
                        f"HiddenServicePort 80 {self.host}:{self.port}\n"
                continue

            if key == "ClientTransportPlugins":
                for pluggable_transport in value:
                    configuration_str += f"ClientTransportPlugin {pluggable_transport}\n"
                continue

            if not isinstance(value, str):
                value = str(value)

            configuration_str += f"{key} {value}\n"

        for bridge in self.bridges:
            configuration_str += f"Bridge {bridge}\n"

        torrc_path = os.path.join(DATA_DIRECTORY_PATH, "torrc")
        with open(torrc_path, "w", encoding = "utf-8") as torrc_file:
            torrc_file.write(configuration_str)

        return torrc_path


    def run_tor(self, torrc_path: str) -> None:
        """
        Function for running Tor.

        :param torrc_path: Path to torrc file.
        """

        splitter = '\n' if os.path.isfile(LOG_FILE_PATH) else ''

        with open(LOG_FILE_PATH, 'a', encoding = 'utf-8') as log_file:
            log_file.write(splitter + '---- ' + time.strftime('%Y-%m-%d %H:%M:%S')
                            + ' New Tor Session ----\n')

        with open(LOG_FILE_PATH, 'a', encoding = 'utf-8') as log_file:
            tor_process = subprocess.Popen(
                [self.tor_file_paths["exe"], "-f", torrc_path],
                stdout = log_file, stderr = log_file
            )
            self.tor_process = tor_process

        tor_process.wait()


    def terminate_tor(self) -> None:
        """
        Function for terminating Tor.
        """

        try:
            self.tor_process.terminate()
        finally:
            self.delete_lock()
            self.running = False


    def run(self, host: str = '127.0.0.1', port: int = 5000) -> None:
        """
        Function for running Tor runner.

        :param host: an IPv4 or IPv6 address.
        :param port: the port to listen on.
        """

        if host == 'localhost':
            host = '127.0.0.1'

        self.host = host
        self.port = port

        torrc_path = self.configure_tor()

        self.delete_lock()
        run_tor_thread = Thread(target = self.run_tor, args = (torrc_path, ))
        run_tor_thread.start()

        delete_torrc_thread = Thread(target = self.delete_torrc)
        delete_torrc_thread.start()

        atexit.register(self.terminate_tor)

        print(' * Tor running on ' + ', '.join(self.find_hostnames()))

        try:
            if self.app:
                self.app.run(self.host, self.port)
            else:
                print(' * Listening on http://' + self.host + ':' + str(self.port) + '...')
                try:
                    while self.running:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
        finally:
            self.terminate_tor()


def main():
    """
    Main function.
    """

    parser = argparse.ArgumentParser(description="Run Flask app as Tor hidden service")
    parser.add_argument("--host", type = str, default = "127.0.0.1", help = "Host for Flask app")
    parser.add_argument("--port", type = int, default=5000, help = "Port for Flask app")
    parser.add_argument("--bridges", type = str, nargs='*', help = "List of bridges for Tor")
    parser.add_argument(
        "--hs-dirs", type = str, nargs='*',
        help = "List of hidden service directories"
    )

    args = parser.parse_args()

    tor_runner = TorRunner(bridges=args.bridges, hs_dirs=args.hs_dirs)
    tor_runner.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
