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
import socket
import atexit
import tarfile
import argparse
import platform
import subprocess
import urllib.request
from threading import Thread
from html.parser import HTMLParser
from typing import List, Optional, Union, Final, Tuple

REQUEST_HEADERS: Final[dict] = {"User-Agent": 'Mozilla/5.0'}
PERMISSION_MODES: Final[dict] = {
    'r': os.R_OK,
    'w': os.W_OK,
    'x': os.X_OK,
    'rw': os.R_OK | os.W_OK,
    'rx': os.R_OK | os.X_OK,
    'wx': os.W_OK | os.X_OK,
}

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Create the file test.env in the `src/tor_runner` folder if you do
# not want to install the module with pip but want to import it from this
# folder, e.g. to display code changes directly.
if not os.path.exists(os.path.join(CURRENT_DIR, 'test.env')):
    try:
        import pkg_resources
    except Exception:
        pass

def get_work_dir():
    """
    Determine the working directory for the application.

    :return: The working directory path.
    """

    if os.path.exists(os.path.join(CURRENT_DIR, 'test.env')):
        return CURRENT_DIR

    try:
        file_path = pkg_resources.resource_filename('tor_runner', '')
    except Exception:
        return CURRENT_DIR

    if not isinstance(file_path, str):
        return CURRENT_DIR

    return file_path

WORK_DIR: Final[str] = get_work_dir()

def get_system_information() -> Optional[Tuple[str, str]]:
    """
    Function to get the correct system information, including Android and various architectures.
    """
    operating_system = platform.system().lower()

    if operating_system == 'darwin':
        operating_system = 'macos'
    elif operating_system == 'linux':
        if 'android' in platform.platform().lower():
            operating_system = 'android'

    valid_operating_systems = ['windows', 'macos', 'linux', 'android']
    if operating_system not in valid_operating_systems:
        return None, None

    architecture_mappings = {
        'amd64': 'x86_64',
        'i386': 'i686',
        'i686': 'x86',
        'x86': 'x86',
        'x86_64': 'x86_64',
        'armv7l': 'armv7',
        'aarch64': 'aarch64'
    }

    architecture = platform.machine().lower()
    architecture = architecture_mappings.get(architecture, architecture)

    return operating_system, architecture

OPERATING_SYSTEM, ARCHITECTURE = get_system_information()
FILE_EXT: Final[str] = '.exe' if OPERATING_SYSTEM == 'windows' else ''

DATA_DIRECTORY_PATH: Final[str] = os.path.join(WORK_DIR, "data")
HIDDEN_SERVICE_DIRECTORY_PATH: Final[str] = os.path.join(DATA_DIRECTORY_PATH, "hs")

if not os.path.isdir(DATA_DIRECTORY_PATH):
    os.makedirs(DATA_DIRECTORY_PATH, exist_ok = True)

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

def has_permission(path: str, mode: str = 'r') -> bool:
    """
    Determines if a file can be accessed with the specified mode at the specified path.

    :param path: A string representing the file path to check.
    :param mode: A string representing the access mode. Default is 'w' for write access.
    :return: Returns True if the file at the given path can be accessed with the
             specified mode, False otherwise.
    """

    if not os.path.isfile(path):
        path = os.path.dirname(path)
        while not os.path.isdir(path):
            if len(path) < 5:
                break

            path = os.path.dirname(path)

        if not os.path.isdir(path):
            return False

    used_mode = PERMISSION_MODES.get(mode, os.R_OK)

    return os.access(path, used_mode)


def find_file(file_name: str, directory_path: str) -> Optional[str]:
    """
    Finds the specified file in the specified directory.

    :param file_name: The name of the file to find.
    :param directory_path: The path to the directory.
    :return: The relative path to the file if found, None otherwise.
    """

    if not os.path.isdir(directory_path)\
        or not has_permission(directory_path, 'r'):
        return None

    for entry in os.listdir(directory_path):
        full_path = os.path.join(directory_path, entry)

        if os.path.isdir(full_path):
            full_path = find_file(file_name, full_path)

            if isinstance(full_path, str):
                return full_path

            continue

        if entry.lower() == file_name.lower():
            return full_path

    return None


def request_url(url: str, timeout: int = 3,
                return_as_bytes: bool = True) -> Optional[Union[str, dict, bytes]]:
    """
    Makes an request and returns the data in the correct format.

    :param url: The url to send the GET Request to.
    :param timeout: The duration after which the connection is cancelled.
    :param return_as_bytes: If True, the response data will be returned as bytes.
    """

    req = urllib.request.Request(url, headers = REQUEST_HEADERS)

    try:
        with urllib.request.urlopen(req, timeout = timeout) as response:
            response_data = response.read()

        if return_as_bytes:
            return response_data

        return response_data.decode('utf-8')
    except Exception as exc:
        print(f"Request failed with exception: {exc}")

    return None


def download_file(url: str, file_path: str, timeout: int = 3) -> bool:
    """
    Downloads a file from the specified URL and saves it to the given file path.

    :param url: The URL to send the GET request to.
    :param file_path: The file path where the downloaded file will be saved.
    :param timeout: The duration after which the connection is cancelled.
    :return: True if the file was downloaded and saved successfully, False otherwise.
    """

    req = urllib.request.Request(url, headers = REQUEST_HEADERS)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            with open(file_path, 'wb') as file:
                file.write(response.read())

        return True
    except Exception as exc:
        print(f"Download failed with exception: {exc}")

    return False


def extract_tar(archive_file_path: str, directory_path: str) -> None:
    """
    Extracts a tar archive to the specified directory.

    :param archive_file_path: The path to the tar archive.
    :param directory_path: The directory where the contents of the tar archive will be extracted.
    :return: None
    """

    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

    if not os.path.isfile(archive_file_path)\
        or not has_permission(archive_file_path, 'r'):
        raise PermissionError(f"Cannot read file: {archive_file_path}")

    with tarfile.open(archive_file_path, 'r') as tar:
        tar.extractall(directory_path, filter = 'data')


def find_available_port(min_port: int = 1000, max_port: int = 65535,
                        exclude_ports: Optional[list] = None) -> int:
    """
    Function for finding an available port.

    :param min_port: Minimum port.
    :param max_port: Maximum port.
    :param exclude_ports: List of ports to exclude.

    :return: Available port.
    """

    if not isinstance(exclude_ports, list):
        exclude_ports = []

    with socket.socket() as tmpsock:
        for port in range(min_port, max_port):
            if port in exclude_ports:
                continue

            try:
                tmpsock.bind(("127.0.0.1", port))
                break
            except OSError:
                pass

    return port


def extract_anchors(html: str):
    """
    Extracts anchor elements (<a>) from the given HTML code.

    :param html: The HTML code from which anchors need to be extracted.
    :return: A list of dictionaries, where each dictionary represents
             the attributes of an anchor element.
    """

    parser = AnchorParser()
    parser.feed(html)
    return parser.anchors


class AnchorParser(HTMLParser):
    """
    AnchorParser is a subclass of HTMLParser used for
    extracting anchor elements (<a>) from HTML code.
    """


    def __init__(self):
        """
        Initializes the AnchorParser object.
        """

        super().__init__()
        self.anchors = []


    def handle_starttag(self, tag, attrs):
        """
        Overrides the handle_starttag method of HTMLParser.
        This method is called whenever the parser encounters a start tag in the HTML.
        
        :param tag: The name of the tag encountered.
        :param attrs: A list of (name, value) pairs containing the attributes of the tag.
        """

        if tag == 'a':
            href = None
            for attr in attrs:
                if attr[0] == 'href':
                    href = attr[1]
                    break

            if href is not None:
                self.anchors.append(href)


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

        if os.path.isfile(lock_file_path)\
            and has_permission(lock_file_path, 'w'):

            try:
                os.remove(lock_file_path)
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
