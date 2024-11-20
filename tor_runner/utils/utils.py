from os import path
from io import BytesIO
from uuid import getnode
from secrets import choice
from functools import lru_cache
from platform import system, machine
from re import IGNORECASE, search, findall
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from tarfile import TarError, open as tar_open
from typing import Final, Optional, Tuple, List
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from http.client import RemoteDisconnected, IncompleteRead, HTTPException


REQUEST_HEADERS: Final[dict] = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                   " (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.3")
}

CHARACTER_SETS: Final[list] = [
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
]


def get_system_information() -> Tuple[Optional[str], Optional[str]]:
    """
    Function to get the correct system information, including Android and various architectures.

    Returns:
        system_info (Tuple[Optional[str], Optional[str]]): The operating_system and architecture.
    """

    operating_system = system().lower().strip()

    if operating_system == "darwin":
        operating_system = "macos"
    elif operating_system == "linux":
        if "android" in operating_system:
            operating_system = "android"

    if operating_system not in ["windows", "macos", "linux", "android"]:
        return None, None

    architecture = machine().lower().strip()
    if operating_system != "android" and not architecture == "i686":
        architecture = "x86_64"

    return operating_system, architecture


OPERATING_SYSTEM, ARCHITECTURE = "linux", "x86_64"#get_system_information()

IS_WINDOWS: Final[bool] = OPERATING_SYSTEM == "windows"
IS_ANDROID: Final[bool] = OPERATING_SYSTEM == "android"


@lru_cache()
def get_mac_address() -> Optional[str]:
    """
    Returns the MAC address of the primary network interface or None if unavailable.
    
    Returns:
        str or None: The MAC address in standard format (e.g., "00:1A:2B:3C:4D:5E") or None.
    """

    try:
        mac = getnode()

        mac_address = ':'.join(f'{(mac >> i) & 0xff:02x}' for i in range(40, -1, -8))
        return mac_address

    except Exception:
        pass

    return None


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

    return "".join(choice(full_characters) for _ in range(length))


def download_file(url: str, timeout: int = 3) -> BytesIO:
    """
    Downloads a file from the specified URL and saves it to the given file path.

    Args:
        url (str): The URL to send the GET request to.
        timeout (int): The duration after which the connection is cancelled.
    
    Returns:
        BytesIO: A BytesIO object containing the downloaded file content,
            or None if an error occurs.
    """

    req = Request(url, headers = REQUEST_HEADERS)

    try:
        with urlopen(req, timeout = timeout) as response:
            content = response.read()

            return BytesIO(content)

        return None

    except (HTTPError, URLError, FileNotFoundError, PermissionError,
            RemoteDisconnected, UnicodeEncodeError, TimeoutError, IncompleteRead,
            HTTPException, ConnectionResetError, ConnectionAbortedError,
            ConnectionRefusedError, ConnectionError):
        pass

    return None


def extract_links(html: str) -> List[str]:
    """
    Extracts href links from anchor elements (<a>) in the given HTML code.

    Args:
        html (str): The HTML code from which links need to be extracted.
    
    Returns:
        links (List[str]): A list of href links.
    """

    anchor_regex = r'<a\s+[^>]*?href=["\']([^"\']+)["\'][^>]*?>'
    matches = findall(anchor_regex, html, IGNORECASE)

    return matches


def extract_tar(archive_data: BytesIO, new_file_paths: dict) -> bool:
    """
    Extracts specific files from a tar archive to specified directories, renaming them as needed.
    
    Args:
        archive_data (BytesIO): A BytesIO object containing the tar archive data.
        files (dict): A dictionary where keys are the original file paths in the archive,
            and values are tuples in the format `(new_file_name, destination_directory)`.
    
    Returns:
        bool: True if the specified files were extracted and renamed successfully, False otherwise.
    """

    try:
        with tar_open(fileobj = archive_data, mode='r') as tar:
            for member in tar.getmembers():
                for new_file_name, new_file_path in new_file_paths.items():
                    if new_file_name != member.name and not \
                        (new_file_name.endswith("*") and member.name.startswith(
                            new_file_name.replace("*", ""))
                        ):

                        continue

                    file_directory_path, file_name = path.split(new_file_path)
                    member.name = file_name
                    tar.extract(member, file_directory_path)

    except (FileNotFoundError, TarError, PermissionError):
        return False

    return True


def get_percentage(output: str) -> Optional[int]:
    """
    Extracts the bootstrap percentage from a Tor startup output line.

    Args:
        output (str): The output string from the Tor startup process, which may contain
                      a line indicating the bootstrap progress.

    Returns:
        Optional[int]: The bootstrap percentage as an integer if found; otherwise, None.
    """

    match = search(r'Bootstrapped (\d+)%', output)

    if match:
        percent = match.group(1)

        if percent.isdigit():
            return int(percent)

    return None


def find_available_port(min_port: int = 1000, max_port: int = 65535,
                        exclude_ports: Optional[list] = None) -> Optional[int]:
    """
    Find an available port within a specified range, excluding any specified ports.

    Args:
        min_port (int): The minimum port number to check (inclusive). Default is 1000.
        max_port (int): The maximum port number to check (exclusive). Default is 65535.
        exclude_ports (Optional[list]): A list of ports to exclude from the search.
            Default is None, which means no ports are excluded.

    Returns:
        Optional[int]: An available port number within the specified range.
    """

    if exclude_ports is None:
        exclude_ports = []

    for port in range(min_port, max_port):
        if port in exclude_ports:
            continue

        with socket(AF_INET, SOCK_STREAM) as s_all, socket(AF_INET, SOCK_STREAM) as s_local:

            s_all.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            s_local.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

            try:
                s_all.bind(("", port))
                s_local.bind(("127.0.0.1", port))

                return port
            except OSError:
                continue

    return None
