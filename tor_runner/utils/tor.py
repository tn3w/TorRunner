import re
from os import path, environ
from hashlib import sha1
from binascii import b2a_hex
from secrets import token_bytes
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from typing import Final, Optional, List, Dict
from http.client import RemoteDisconnected, IncompleteRead, HTTPException

try:
    from utils.utils import REQUEST_HEADERS, extract_links, download_file, extract_tar, is_quiet
    from utils.files import TAR_FILE_PATHS, TOR_FILE_PATHS, TOR_BUNDLE_DIRECTORY_PATH, read, write
except ImportError:
    from utils import REQUEST_HEADERS, extract_links, download_file, extract_tar, is_quiet
    from files import TAR_FILE_PATHS, TOR_FILE_PATHS, TOR_BUNDLE_DIRECTORY_PATH, read, write


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
    "meek_lite": [
        "meek_lite 192.0.2.18:80 BE776A53492E1E044A26F17306E1BC46A55A1625 "
        "url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com"
    ]
}


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


def hash_control_password(password: str) -> str:
    """
    Hash a password for use with Tor`s control port authentication.

    Args:
        password (str): The password to be hashed.

    Returns:
        str: The hashed password in a format suitable for Tor.
    """

    indicator_char = "`"
    salt = token_bytes(8) + indicator_char.encode("utf-8")
    indicator_value = ord(indicator_char)

    expected_bias = 6
    count = (16 + (indicator_value & 15)) << ((indicator_value >> 4) + expected_bias)

    sha1_hash = sha1()
    salted_password = salt[:8] + password.encode("utf-8")
    password_length = len(salted_password)

    while count > 0:
        if count <= password_length:
            sha1_hash.update(salted_password[:count])
            break

        sha1_hash.update(salted_password)
        count -= password_length

    hashed_password = sha1_hash.digest()

    salt_hex = b2a_hex(salt[:8]).upper().decode("utf-8")
    indicator_hex = b2a_hex(indicator_char.encode("utf-8")).upper().decode("utf-8")
    hashed_password_hex = b2a_hex(hashed_password).upper().decode("utf-8")

    return "16:" + salt_hex + indicator_hex + hashed_password_hex


def set_ld_library_path_environ() -> None:
    """
    Sets the 'LD_LIBRARY_PATH' environment variable
    to include the path to the Tor library.

    Returns:
        None
    """

    current_ld_library_path = environ.get('LD_LIBRARY_PATH', '')

    if TOR_BUNDLE_DIRECTORY_PATH in current_ld_library_path:
        return

    environ['LD_LIBRARY_PATH'] = f'{current_ld_library_path}:{TOR_BUNDLE_DIRECTORY_PATH}' \
        if current_ld_library_path else TOR_BUNDLE_DIRECTORY_PATH


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

    headers = REQUEST_HEADERS.copy()
    headers["Range"] = "bytes=0-"

    req = Request(download_page_url, headers = headers)

    try:
        with urlopen(req, timeout = 3) as response:
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

    except (HTTPError, URLError, FileNotFoundError, PermissionError,
            RemoteDisconnected, UnicodeEncodeError, TimeoutError, IncompleteRead,
            HTTPException, ConnectionResetError, ConnectionAbortedError,
            ConnectionRefusedError, ConnectionError):
        pass

    return None


def is_tor_installation_verified() -> bool:
    """
    Checks if the Tor installation is verified by confirming
    the presence of required files.

    Returns:
        bool: True if all required Tor files exist, otherwise False.
    """

    for file_path in TOR_FILE_PATHS.values():
        if not path.isfile(file_path):
            return False

    return True


def install_tor(operating_system: str, architecture: str) -> bool:
    """
    Installs the Tor Expert Bundle for the specified operating system and architecture.

    Args:
        operating_system (str): The operating system for the
            installation (e.g., 'windows', 'linux').
        architecture (str): The architecture of the system (e.g., 'x86_64', 'i686').

    Returns:
        bool: True if the installation was successful, otherwise False.
    """

    if is_tor_installation_verified():
        return True

    quiet = is_quiet()

    if not quiet:
        print("Receiving Tor download url...")

    download_url = get_tor_download_url(operating_system, architecture)
    if download_url is None:
        if not quiet:
            print("Failed.\n")

        return False

    if not quiet:
        print("Downloading Tor bundle...")

    archive_data = download_file(download_url)
    if archive_data is None:
        if not quiet:
            print("Failed.\n")

        return False

    if not quiet:
        print("Extracting Tor bundle...")

    extracted_successfully = extract_tar(archive_data, TAR_FILE_PATHS)
    if not extracted_successfully:
        if not quiet:
            print("Failed.\n")

        return False

    if not quiet:
        print("Cleaning up...")

    for file_path in [TOR_FILE_PATHS["geoip"], TOR_FILE_PATHS["geoip6"]]:
        file_content = read(file_path)
        if not isinstance(file_content, str):
            continue

        new_file_content = "\n".join(
            [
                line for line in file_content.splitlines()
                if not line.startswith("#")
            ]
        )
        write(new_file_content, file_path, True)

    print()
    return True
