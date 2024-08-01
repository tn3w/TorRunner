import os
import socket
import tarfile
import tempfile
import platform
import urllib.request
from html.parser import HTMLParser
from typing import Optional, Union, Final, Tuple


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
DATA_DIRECTORY_PATH: Final[str] = os.path.join(WORK_DIR, "data")

if not os.path.isdir(DATA_DIRECTORY_PATH):
    os.makedirs(DATA_DIRECTORY_PATH, exist_ok = True)


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

    if os.path.isfile(file_path):
        return True

    req = urllib.request.Request(url, headers = REQUEST_HEADERS)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            with open(file_path, 'wb') as file:
                file.write(response.read())

        return True
    except Exception as exc:
        print(f"Download failed with exception: {exc}")

    return False


def temp_fp(file_name: str) -> str:
    """
    Returns a temporary file path.

    :param file_name: The name of the temporary file.
    :return: The temporary file path.
    """

    return os.path.join(tempfile.gettempdir(), file_name)


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
