"""
common.py

This module provides a collection of utility functions and classes that facilitate
various common operations, particularly in the context of system and file handling,
network requests, and progress tracking.

License:
Made available under the GPL-3.0 license.
"""

import re
import os
import sys
import math
import time
import json
import socket
import shutil
import tarfile
import secrets
import platform
import urllib.error
import urllib.request
from typing import Optional, Tuple, Final, Union, List, Dict, Any


VALID_OPERATING_SYSTEMS: Final[List[str]] = ["windows", "macos", "linux", "android"]
ARCHITECTURE_MAPPINGS: Final[Dict[str, str]] = {
    "amd64": "x86_64", "i386": "i686", "i686": "x86", "x86": "x86",
    "x86_64": "x86_64", "armv7l": "armv7", "aarch64": "aarch64"
}


def get_system_information() -> Tuple[Optional[str], Optional[str]]:
    """
    Function to get the correct system information, including Android and various architectures.

    Returns:
        system_info (Tuple[Optional[str], Optional[str]]): The operating_system and architecture.
    """

    operating_system = platform.system().lower().strip()

    if operating_system == "darwin":
        operating_system = "macos"
    elif operating_system == "linux":
        if "android" in operating_system:
            operating_system = "android"

    if operating_system not in VALID_OPERATING_SYSTEMS:
        return None, None

    architecture = platform.machine().lower()
    if operating_system != "android":
        architecture = ARCHITECTURE_MAPPINGS.get(architecture, architecture)

    return operating_system, architecture


CURRENT_DIRECTORY_PATH: Final[str] = os.path.dirname(os.path.abspath(__file__))

# Create the file test.env in the `src/tor_runner` folder if you do
# not want to install the module with pip but want to import it from this
# folder, e.g. to display code changes directly.
pkg_resources_available = False
if not os.path.exists(os.path.join(CURRENT_DIRECTORY_PATH, 'test.env')):
    try:
        import pkg_resources
    except ImportError:
        pass
    else:
        pkg_resources_available = True

def get_work_dir() -> str:
    """
    Determine the working directory for the application.

    Returns:
        str: The working directory path.
    """

    if os.path.exists(os.path.join(CURRENT_DIRECTORY_PATH, '.test')):
        return CURRENT_DIRECTORY_PATH

    if not pkg_resources_available:
        return CURRENT_DIRECTORY_PATH

    try:
        file_path = pkg_resources.resource_filename('tor_runner', '')
    except (pkg_resources.DistributionNotFound, pkg_resources.UnknownExtra):
        return CURRENT_DIRECTORY_PATH

    if not os.path.exists(file_path):
        return CURRENT_DIRECTORY_PATH

    return file_path

WORK_DIRECTORY_PATH: Final[str] = get_work_dir()

DATA_DIRECTORY_PATH = os.path.join(WORK_DIRECTORY_PATH, "data")
TOR_DATA_DIRECTORY_PATH = os.path.join(DATA_DIRECTORY_PATH, "tor_data")

if not os.path.exists(DATA_DIRECTORY_PATH):
    os.makedirs(DATA_DIRECTORY_PATH, exist_ok = True)

OPERATING_SYSTEM, ARCHITECTURE = get_system_information()
FILE_EXT: Final[str] = ".exe" if OPERATING_SYSTEM == "windows" else ""
HIDDEN_SERVICE_DIRECTORY_PATH: Final[str] = os.path.join(DATA_DIRECTORY_PATH, "hidden_service")

TOR_ARCHIVE_FILE_PATH: Final[str] = os.path.join(DATA_DIRECTORY_PATH, "tor.tar.gz")
TOR_DIRECTORY_PATH: Final[str] = os.path.join(DATA_DIRECTORY_PATH, "tor")
PLUGGABLE_TRANSPORTS_DIRECTORY_PATH: Final[str] = os.path.join(
    TOR_DIRECTORY_PATH, "tor", "pluggable_transports")
DEBUG_DIRECTORY_PATH: Final[str] = os.path.join(TOR_DIRECTORY_PATH, "debug")

ERROR_MESSAGE: Final[str] = "Please download the Tor package for your system from "+\
    f"https://www.torproject.org/en/download/tor/ and extract it to {TOR_DIRECTORY_PATH}."

TOR_FILE_PATHS: Final[Dict[str, str]] = {
    "geoip4": os.path.join(TOR_DIRECTORY_PATH, "data", "geoip"),
    "geoip6": os.path.join(TOR_DIRECTORY_PATH, "data", "geoip6"),
    "exe": os.path.join(
        TOR_DIRECTORY_PATH, "tor", (
            "libTor.so" if OPERATING_SYSTEM == "android" else "tor" + FILE_EXT
        )
    ),
    "lyrebird": os.path.join(
        PLUGGABLE_TRANSPORTS_DIRECTORY_PATH, "lyrebird" + FILE_EXT
    ),
    "snowflake": os.path.join(
        PLUGGABLE_TRANSPORTS_DIRECTORY_PATH, "snowflake-client" + FILE_EXT
    ),
    "conjure": os.path.join(
        PLUGGABLE_TRANSPORTS_DIRECTORY_PATH, "conjure-client" + FILE_EXT
    )
}
IMPORTANT_FILE_KEYS: Final[List[str]] = ["exe", "geoip4", "geoip6"]


PLUGGABLE_TRANSPORTS: Final[dict] = {
    "lyrebird": ["meek_lite", "obfs2", "obfs3", "obfs4", "scramblesuit", "webtunnel"],
    "snowflake": ["snowflake"],
    "conjure": ["conjure"]
}
DEFAULT_BRIDGES: Final[Dict[str, List[str]]] = {
    "vanilla": [
        "45.33.1.189:443 F9DFF618E7BA6C018245D417F39E970C2F019BAA",
        "217.160.8.91:9706 FEA00E8A631508D55012222B4D31B68B31791D35",
        "104.156.237.105:55292 F9F2B2D90FDF48394A00A1BE7E9D849C45B7845D",
        "141.5.100.255:16749 9FA6E82152189521B3C78ACCF41F8B9F5069D26C",
        "92.117.182.55:443 755BA0E7F4FE1A197EDF0D83681D2572AF39CB2E",
        "158.69.207.216:9001 6565F31D9EC0C7DFFEA1920BE3BA4C73EF35B5C4",
        "192.210.175.193:443 CE7870C73917FF91CA8DD068BBA8C771F85CAD19",
        "116.202.247.57:9001 E094CE3392E59129B44B01DB5C63AA52F5FF4566",
        "199.231.94.134:443 040FE18615AB10F10E6942B53C3CAAC5BF74736B",
        "217.182.196.65:443 8FD3BAF5E14EBE1124D6253D59882AFE1C2B9B8E"
    ],
    "obfs4": [
        "obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 "
        "cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ "
        "iat-mode=1",
        "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D "
        "cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg "
        "iat-mode=0",
        "obfs4 85.31.186.98:443 011F2599C0E9B27EE74B353155E244813763C3E5 "
        "cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg "
        "iat-mode=0",
        "obfs4 85.31.186.26:443 91A6354697E6B02A386312F68D82CF86824D3606 "
        "cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw "
        "iat-mode=0",
        "obfs4 193.11.166.194:27015 2D82C2E354D531A68469ADF7F878FA6060C6BACA "
        "cert=4TLQPJrTSaDffMK7Nbao6LC7G9OW/NHkUwIdjLSS3KYf0Nv4/nQiiI8dY2TcsQx01NniOg "
        "iat-mode=0",
        "obfs4 193.11.166.194:27020 86AC7B8D430DAC4117E9F42C9EAED18133863AAF "
        "cert=0LDeJH4JzMDtkJJrFphJCiPqKx7loozKN7VNfuukMGfHO0Z8OGdzHVkhVAOfo1mUdv9cMg "
        "iat-mode=0",
        "obfs4 193.11.166.194:27025 1AE2C08904527FEA90C4C4F8C1083EA59FBC6FAF "
        "cert=ItvYZzW5tn6v3G4UnQa6Qz04Npro6e81AP70YujmK/KXwDFPTs3aHXcHp4n8Vt6w/bv8cA "
        "iat-mode=0",
        "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 "
        "cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw "
        "iat-mode=0",
        "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 "
        "cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw "
        "iat-mode=0",
        "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C "
        "cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw "
        "iat-mode=0",
        "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 "
        "cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew "
        "iat-mode=0"
    ],
    "snowflake": [
        "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
        "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
        "url=https://1098762253.rsc.cdn77.org/ "
        "fronts=www.cdn77.com,www.phpmyadmin.net "
        "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,"
        "stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,"
        "stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,"
        "stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,"
        "stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn",
        "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA "
        "fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA "
        "url=https://1098762253.rsc.cdn77.org/ "
        "fronts=www.cdn77.com,www.phpmyadmin.net "
        "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,"
        "stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,"
        "stun:stun.epygi.com:3478,stun:stun.sonetel.net:3478,"
        "stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,"
        "stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn"
    ],
    "webtunnel": [
        "webtunnel [2001:db8:9443:367a:3276:1e74:91c3:7a5a]:443 "
        "54BF1146B161573185FBA0299B0DC3A8F7D08080 "
        "url=https://d3pyjtpvxs6z0u.cloudfront.net/Exei6xoh1aev8fiethee ver=0.0.1",
        "webtunnel [2001:db8:3d87:58ab:4ec3:21ba:913f:99d8]:443 "
        "E4B91C347D685E929C1B7CE84CC27EB073127EA6 "
        "url=https://borntec.autos/poh8aiteaqu6oophaiXo ver=0.0.1",
        "webtunnel [2001:db8:f501:5e2b:27a0:2475:bf96:10d8]:443 "
        "B31170341D35C6E1FB5416BEB219E349D8FE093D "
        "url=https://files.gus.computer/kd2DLzS5EJEcB5LRsHS22pLE ver=0.0.1"
    ],
    "meek_azure": [
        "meek_lite 192.0.2.18:80 BE776A53492E1E044A26F17306E1BC46A55A1625 "
        "url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com"
    ],
    "meek_lite": [
        "meek_lite 192.0.2.18:80 BE776A53492E1E044A26F17306E1BC46A55A1625 "
        "url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com"
    ]
}

REQUEST_HEADERS: Final[Dict[str, str]] = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                   " (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.3")
}

CHARACTER_SETS: Final[list] = [
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
]


def generate_secure_random_string(length: int, characters: str = "aA0"):
    """
    Generate a secure random string of a specified length using defined character sets.

    Parameters:
        length (int): The length of the random string to generate.
        characters (str): A string specifying which character sets to include.

    Returns:
        str: A secure randomly generated string of the specified length, composed 
             of characters from the selected sets.
    """

    full_characters = set()
    for character_set in CHARACTER_SETS:
        if any(character in character_set for character in characters):
            full_characters.add(character_set)

    full_characters = ''.join(full_characters)

    return "".join(secrets.choice(full_characters) for _ in range(length))


def clear_console() -> None:
    """
    Clear the console screen.

    Returns:
        None: This function does not return any value.
    """

    os.system('cls' if os.name == 'nt' else 'clear')


class Progress:
    """
    A class to represent a progress tracker for a task.

    Attributes:
        message (str): A message describing the task being tracked.
        messages (list): A list of additional messages to display with the progress.
        total (int): The total number of tasks to complete.
        finished (int): The number of tasks that have been completed.
        start_time (float): The time when the progress tracking started.
        last_remaining_time (float or None): The last calculated remaining time.
    """


    def __init__(self, message: str, total: int) -> None:
        """
        Initializes the Progress tracker.

        Args:
            message (str): A message describing the task being tracked.
            total (int): The total number of tasks to complete.

        Returns:
            None: This method does not return a value.
        """
        self.message = message
        self.messages = []
        self.total = total

        self.finished = 0
        self.start_time = time.time()
        self.last_remaining_time = None


    def update(self, finished: Optional[int] = None) -> None:
        """
        Updates the progress with the number of finished tasks.

        Args:
            finished (Optional[int]): The number of tasks that have been completed.

        Returns:
            None: This method does not return a value.
        """

        if finished is not None:
            if finished <= self.finished:
                return

            self.finished = finished

        is_finished = False
        if self.finished >= self.total:
            self.total = self.finished
            is_finished = True

        elapsed_time = time.time() - self.start_time
        progress_speed = self.finished / elapsed_time if elapsed_time > 0 else 0

        remaining = self.total - self.finished
        remaining_time = max(0, remaining / progress_speed if progress_speed > 0 else float('inf'))
        if remaining_time == 0:
            remaining_time_str = "0"
        else:
            remaining_time_str = f"{remaining_time:.1f}"\
                if remaining_time < float('inf') else "unknown"

        total = str(self.total)
        finished = str(self.finished)

        progress = math.ceil((self.finished / self.total) * 30)
        progress_bar = '[' + '#' * progress + ' ' * (30 - progress) + ']'

        status = ""
        for message in self.messages:
            status += message + "\n"

        if len(self.messages) != 0:
            status += "\n"

        status += f'🚀 {self.message} [{finished}% of {total}%] '\
            + progress_bar + f" ({remaining_time_str} s) "

        if is_finished:
            status += 'Done\n'

        clear_console()

        if os.name == 'nt':
            sys.stdout.write('\r' + status + ' ' * 8)
            sys.stdout.flush()
            return

        message = '\r' + ' ' * len(status) + '\r' + status
        print(message, end='', flush=True)


def can_read(file_path: str) -> bool:
    """
    Checks if a file can be read.

    Args:
        file_path (str): The name to the file to check.

    Returns:
        bool (bool): True if the file can be read, False otherwise.    
    """

    if not os.path.isfile(file_path):
        return False

    return os.access(file_path, os.R_OK)


def can_write(file_path: str, content_size: Optional[int] = None) -> bool:
    """
    Checks if a file can be written to.

    Args:
        file_path (str): The path to the file to check.
        content_size (Optional[int]): The size of the content to write to the file.

    Returns:
        bool (bool): True if the file can be written to, False otherwise.    
    """

    directory_path = os.path.dirname(file_path)
    if not os.path.isdir(directory_path):
        return False

    if not os.access(directory_path, os.W_OK):
        return False

    if content_size is not None:
        if not os.path.getsize(directory_path) + content_size\
            <= os.stat(directory_path).st_blksize:

            return False

    return True


def read(file_path: str, as_bytes: bool = False, default: Any = None) -> Any:
    """
    Reads a file.
    
    Args:
        file_path (str): The path to the file to read.
        default (Any, optional): The default value to return if the file
                                 does not exist. Defaults to None.
        as_bytes (bool, optional): Whether to return the file as bytes. Defaults to False.

    Returns:
        Any: The contents of the file, or the default value if the file does not exist.
    """

    try:
        with open(file_path, "r" + ("b" if as_bytes else ""),
                  encoding = None if as_bytes else "utf-8") as file:
            return file.read()

    except (FileNotFoundError, IsADirectoryError, IOError,
            PermissionError, ValueError, UnicodeDecodeError,
            TypeError, OSError):
        pass

    return default


def write(file_path: str, content: Any) -> bool:
    """
    Writes a file.

    Args:
        file_path (str): The path to the file to write to.
        content (Any): The content to write to the file.

    Returns:
        bool: True if the file was written successfully, False otherwise.
    """

    try:
        with open(file_path, "w" + ("b" if isinstance(content, bytes) else "")) as file:
            file.write(content)

        return True

    except (FileNotFoundError, IsADirectoryError, IOError,
            PermissionError, ValueError, TypeError, OSError):
        pass

    return False


def is_empty(directory_path: str) -> bool:
    """
    Checks if a directory is empty.

    Args:
        directory_path (str): The path to the directory to check.

    Returns:
        bool (bool): True if the directory is empty, False otherwise.
    """

    if not os.path.isdir(directory_path):
        return False

    for entry in os.listdir(directory_path):
        full_path = os.path.join(directory_path, entry)
        if os.path.exists(full_path):
            return True

    return False


def delete(object_path: str) -> bool:
    """
    Deletes a object (like a file or directory).

    Args:
        object_path (str): The path to the object to delete.

    Returns:
        bool (bool): True if the object was deleted successfully, False otherwise.
    """

    if not os.path.exists(object_path):
        return False

    try:
        if os.path.isdir(object_path):
            if is_empty(object_path):
                shutil.rmtree(object_path)
                return True

            os.rmdir(object_path)
            return True

        os.remove(object_path)
        return True

    except (FileNotFoundError, IsADirectoryError, IOError,
            PermissionError, TypeError, OSError):
        pass

    return False


def request_url(url: str, timeout: int = 3,
                return_as_bytes: bool = True,
                return_as_json: bool = False) -> Optional[Union[str, dict, bytes]]:
    """
    Makes a request and returns the data in the specified format.

    Args:
        url (str): The URL to send the GET request to.
        timeout (int): The duration (in seconds) after which the connection will be cancelled.
        return_as_bytes (bool): If True, the response data will be returned as bytes.
        return_as_json (bool): If True, the response data will be returned as JSON.

    Returns:
        Response (Optional[Union[str, dict, bytes]]): Response data in the
            requested format (bytes, JSON, or text).
    """

    req = urllib.request.Request(url, headers = REQUEST_HEADERS)

    try:
        with urllib.request.urlopen(req, timeout = timeout) as response:
            response_data = response.read()

        if return_as_bytes:
            return response_data

        string_data = response_data.decode("utf-8")

        if not return_as_json:
            return string_data

        return json.load(string_data)
    except (urllib.error.HTTPError, urllib.error.URLError,
            socket.timeout, json.JSONDecodeError, UnicodeDecodeError):
        pass

    return None


def download_file(url: str, file_path: str, timeout: int = 3) -> bool:
    """
    Downloads a file from the specified URL and saves it to the given file path.

    Args:
        url (str): The URL to send the GET request to.
        file_path (str): The file path where the downloaded file will be saved.
        timeout (int): The duration after which the connection is cancelled.
    
    Returns:
        bool (bool): True if the file was downloaded and saved successfully, False otherwise.
    """

    if not can_write(file_path):
        return False

    req = urllib.request.Request(url, headers = REQUEST_HEADERS)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            with open(file_path, "wb") as file:
                file.write(response.read())

        return True
    except (urllib.error.HTTPError, urllib.error.URLError,
            socket.timeout, FileNotFoundError, PermissionError):
        pass

    return False


def extract_links(html: str) -> List[str]:
    """
    Extracts href links from anchor elements (<a>) in the given HTML code.

    Args:
        html (str): The HTML code from which links need to be extracted.
    
    Returns:
        links (List[str]): A list of href links.
    """

    anchor_regex = r'<a\s+[^>]*?href=["\']([^"\']+)["\'][^>]*?>'
    matches = re.findall(anchor_regex, html, re.IGNORECASE)

    return matches


def extract_tar(archive_file_path: str, directory_path: str) -> bool:
    """
    Extracts a tar archive to the specified directory.

    Args:
        archive_file_path (str): The path to the tar archive.
        directory_path (str): The directory where the contents of the tar archive will be extracted.
    
    Returns:
        bool (bool): True if the file was extracted successfully, False otherwise.
    """

    if not os.path.exists(directory_path):
        os.makedirs(directory_path, exist_ok = True)

    if not can_read(archive_file_path):
        return False

    try:
        with tarfile.open(archive_file_path, 'r') as tar:
            tar.extractall(directory_path)
    except (FileNotFoundError, tarfile.ReadError, PermissionError):
        return False

    return True


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


def find_available_port(min_port: int = 1000, max_port: int = 65535,
                        exclude_ports: Optional[list] = None) -> int:
    """
    Find an available port within a specified range, excluding any specified ports.

    Args:
        min_port (int): The minimum port number to check (inclusive). Default is 1000.
        max_port (int): The maximum port number to check (exclusive). Default is 65535.
        exclude_ports (Optional[list]): A list of ports to exclude from the search.
            Default is None, which means no ports are excluded.

    Returns:
        int: An available port number within the specified range.
    """

    if exclude_ports is None:
        exclude_ports = []

    with socket.socket() as tmpsock:
        for port in range(min_port, max_port):
            if port in exclude_ports:
                continue

            try:
                tmpsock.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue

    raise ValueError("No available port found in the specified range.")


def find_hostnames(hidden_service_directories: List[str]) -> List[str]:
    """
    Retrieve hostnames from a list of Tor hidden service directories.

    Parameters:
        hidden_service_directories (List[str]): A list of paths to hidden service directories.

    Returns:
        List[str]: A list of hostnames retrieved from the hidden service directories. 
                If a hostname cannot be read or the file does not exist, it is skipped.
    """

    hostnames = []
    for hs_dir in hidden_service_directories:
        hostname_path = os.path.join(hs_dir, 'hostname')

        file_exists = False
        for _ in range(20):
            if os.path.isfile(hostname_path):
                file_exists = True
                break

            time.sleep(0.2)

        if not file_exists:
            continue

        file_content = read(hostname_path)
        if file_content is None:
            print("on_tor.py: Error reading", hs_dir, "Skipping!")
            continue

        hostnames.append("http://" + file_content)

    return hostnames


if __name__ == "__main__":
    print("common.py: This file is not designed to be executed.")
