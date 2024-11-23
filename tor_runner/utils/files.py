import random
import string
from errno import ESRCH
from hashlib import sha256
from threading import Lock
from io import TextIOWrapper
from contextlib import contextmanager
from shutil import copy2, move, rmtree
from secrets import token_bytes, token_hex
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Final, Callable, Tuple, Optional, Generator, List, Dict, Any
from os import listdir, remove, rmdir, kill, getpid, walk, unlink, fsync, mkdir, cpu_count, path

try:
    from utils.utils import (
        IS_WINDOWS, OPERATING_SYSTEM, ARCHITECTURE,
        IS_ANDROID, dummy_context_manager
    )
except ImportError:
    from utils import (
        IS_WINDOWS, OPERATING_SYSTEM, ARCHITECTURE,
        IS_ANDROID, dummy_context_manager
    )

if IS_WINDOWS:
    import msvcrt
else:
    import fcntl


DOD_PATTERNS: Final[List[Callable]] = [
    lambda size: bytes([0x00] * size),
    lambda size: bytes([0xFF] * size),
    lambda size: bytes([0x00] * size),
]
GUTMANN_PATTERNS: Final[List[Callable]] = [
    lambda size: bytes([0x55] * size),  # 5
    lambda size: bytes([0xAA] * size),  # 6
    lambda size: bytes([0x92, 0x49, 0x24] * (size // 3 + 1))[:size],  # 7
    lambda size: bytes([0x49, 0x24, 0x92] * (size // 3 + 1))[:size],  # 8
    lambda size: bytes([0x24, 0x92, 0x49] * (size // 3 + 1))[:size],  # 9
    lambda size: bytes([0x00] * size),  # 10
    lambda size: bytes([0x11] * size),  # 11
    lambda size: bytes([0x22] * size),  # 12
    lambda size: bytes([0x33] * size),  # 13
    lambda size: bytes([0x44] * size),  # 14
    lambda size: bytes([0x55] * size),  # 15
    lambda size: bytes([0x66] * size),  # 16
    lambda size: bytes([0x77] * size),  # 17
    lambda size: bytes([0x88] * size),  # 18
    lambda size: bytes([0x99] * size),  # 19
    lambda size: bytes([0xAA] * size),  # 20
    lambda size: bytes([0xBB] * size),  # 21
    lambda size: bytes([0xCC] * size),  # 22
    lambda size: bytes([0xDD] * size),  # 23
    lambda size: bytes([0xEE] * size),  # 24
    lambda size: bytes([0xFF] * size),  # 25
    lambda size: bytes([0x92, 0x49, 0x24] * (size // 3 + 1))[:size],  # 26
    lambda size: bytes([0x49, 0x24, 0x92] * (size // 3 + 1))[:size],  # 27
    lambda size: bytes([0x24, 0x92, 0x49] * (size // 3 + 1))[:size],  # 28
    lambda size: bytes([0x6D, 0xB6, 0xDB] * (size // 3 + 1))[:size],  # 29
    lambda size: bytes([0xB6, 0xDB, 0x6D] * (size // 3 + 1))[:size],  # 30
    lambda size: bytes([0xDB, 0x6D, 0xB6] * (size // 3 + 1))[:size],  # 31
]

file_locks: Dict[str, Lock] = {}
file_cache: Dict[str, Tuple[str, bytes]] = {}
WRITE_EXECUTOR: Final[ThreadPoolExecutor] = ThreadPoolExecutor()
SHREDDER_EXECUTOR: Final[ThreadPoolExecutor] = ThreadPoolExecutor(round(cpu_count() / 2))


def get_current_dir() -> str:
    """
    Determine the current directory for the application.

    Returns:
        str: The current directory path.
    """

    current_directory_path = path.dirname(path.abspath(__file__)) \
        .replace("\\", "/").replace("//", "/").replace("/utils", "") \
        .replace("//", "/")

    # Check for the existence of the .env file
    if path.exists(path.join(current_directory_path, '.env')):
        return current_directory_path

    try:
        __import__("tor_runner")

        import pkg_resources
    except ImportError:
        return current_directory_path

    try:
        file_path = pkg_resources.resource_filename('tor_runner', '')
    except (pkg_resources.DistributionNotFound,
            pkg_resources.UnknownExtra, ModuleNotFoundError):
        return current_directory_path

    # Validate the resolved path
    if not path.exists(file_path):
        return current_directory_path

    return file_path


# Used to make it harder for attackers to find the Tor data directories.
# This mainly refers to attackers who know nothing about the application.
# But it adds complexity, and attackers could use Tor hashes, since the
# Tor software is also stored in this directory.
def get_work_path(current_dir: str, seed: str = "") -> str:
    """
    Generate a unique and consistent working directory path for the application.

    Parameters:
        current_dir (str): The base directory where the working directory will be created.
        seed (str, optional): An optional string that can be used to influence the uniqueness 
                              of the generated directory name. Defaults to an empty string.

    Returns:
        str: The full path to the generated working directory, which includes the base directory 
             and a unique directory name.
    """

    system_info = (
        OPERATING_SYSTEM +
        ARCHITECTURE +
        current_dir +
        seed
    )

    hasher = sha256()
    hasher.update(system_info.encode("utf-8"))
    hash_result = hasher.digest()

    length = 8 + (hash_result[0] % 5)
    random.seed(hash_result)
    valid_chars = string.ascii_letters + string.digits + "-._"
    random_string = "".join(random.choices(valid_chars, k=length))

    return path.join(current_dir, random_string)


CURRENT_DIRECTORY_PATH: Final[str] = get_current_dir()
WORK_DIRECTORY_PATH: Final[str] = get_work_path(CURRENT_DIRECTORY_PATH)


def make_work_directory() -> None:
    if not path.exists(WORK_DIRECTORY_PATH):
        mkdir(WORK_DIRECTORY_PATH)


EXTENSION = ".exe" if IS_WINDOWS else ""

TOR_BUNDLE_DIRECTORY_PATH: Final[str] = get_work_path(WORK_DIRECTORY_PATH, "bundle")
RAW_FILE_PATHS: Final[list] = [
    ("data/geoip", get_work_path(TOR_BUNDLE_DIRECTORY_PATH, "geoip")),
    ("data/geoip6", get_work_path(TOR_BUNDLE_DIRECTORY_PATH, "geoip6")),
    ("tor/libcrypto*", path.join(TOR_BUNDLE_DIRECTORY_PATH, "libcrypto.so.3")),
    ("tor/libssl*", path.join(TOR_BUNDLE_DIRECTORY_PATH, "libssl.so.3")),
    ("tor/libstdc*", path.join(TOR_BUNDLE_DIRECTORY_PATH, "libstdc++.so.6")),
    ("tor/libevent-*.so*", path.join(TOR_BUNDLE_DIRECTORY_PATH, "libevent-2.1.so.7")),
    ("tor/libevent-*.dylib*", path.join(TOR_BUNDLE_DIRECTORY_PATH, "libevent-2.1.7.dylib")),
    ("tor/pluggable_transports/conjure-client" + EXTENSION, \
        get_work_path(TOR_BUNDLE_DIRECTORY_PATH, "conjure") + EXTENSION),
    ("tor/pluggable_transports/lyrebird" + EXTENSION, \
        get_work_path(TOR_BUNDLE_DIRECTORY_PATH, "lyrebird") + EXTENSION),
    ("tor/pluggable_transports/snowflake-client" + EXTENSION, \
        get_work_path(TOR_BUNDLE_DIRECTORY_PATH, "snowflake") + EXTENSION),
    (("tor/tor" + EXTENSION) if not IS_ANDROID else "tor/libTor.so", \
        get_work_path(TOR_BUNDLE_DIRECTORY_PATH, "tor") + EXTENSION)
]
TAR_FILE_PATHS: Final[dict] = dict(RAW_FILE_PATHS)
TOR_FILE_PATHS: Final[dict] = {
    file_name.replace("data/", "").replace("tor/", "").replace("-client", "")\
        .replace("tor/pluggable_transports/", ""): file_path
    for file_name, file_path in RAW_FILE_PATHS
    if file_name == "tor/tor" or file_name.startswith(("data/", "tor/pluggable_transports"))
}

HIDDEN_SERVICE_DIRECTORY_PATH: Final[str] = get_work_path(WORK_DIRECTORY_PATH, "hidden_service")


def is_directory_empty(directory_path: str) -> bool:
    """
    Check if a specified directory is empty.

    Args:
        directory_path (str): The path to the directory to be checked.

    Returns:
        bool: True if the directory does not exist or is empty, 
              False if it contains any files or subdirectories.
    """

    if not path.isdir(directory_path):
        return True

    return len(listdir(directory_path)) == 0


def get_lock(file_path: str) -> Lock:
    """
    Retrieve or create a lock for the specified file.

    Args:
        file_path (str): The path to the file for which a lock is to be 
            retrieved or created.

    Returns:
        Lock: A threading.Lock object associated with the specified file path.
    """

    if not file_path in file_locks:
        new_lock = Lock()
        file_locks[file_path] = new_lock

        return new_lock

    return file_locks[file_path]


def delete_lock(file_path: str) -> None:
    """
    Remove the lock associated with the specified file.

    Args:
        file_path (str): The path to the file for which the lock should be 
            deleted.
    
    Returns:
        None: This function does not return a value.
    """

    if file_path in file_locks:
        del file_locks[file_path]


def get_shadow_copy_temp_path(file_path: str) -> str:
    """
    Generate a temporary file path for a shadow copy of the specified file.

    Args:
        file_path (str): The path to the original file for which a shadow 
            copy path is to be generated.

    Returns:
        str: The path to the temporary shadow copy file.
    """

    directory, file = path.split(file_path)

    random_hex = token_hex(16)
    temp_file_name = random_hex + "_" + file

    return path.join(directory, temp_file_name)


@contextmanager
def get_read_stream(file_path: str, read_as_bytes: bool = False,
                    shadow_copy: bool = True) -> Optional[Generator[TextIOWrapper, None, None]]:
    """
    Context manager for reading a file stream, with options for reading as 
    bytes and creating a shadow copy.

    Args:
        file_path (str): The path to the file to be read.
        read_as_bytes (bool, optional): If True, the file will be opened in 
            binary mode. Defaults to False (text mode).
        shadow_copy (bool, optional): If True, a temporary shadow copy of the 
            file will be created for reading. Defaults to True.

    Yields:
        Optional[Generator[io.TextIOWrapper, None, None]]: A file stream object 
            that can be used to read the contents of the file. The type of the 
            stream will depend on the `read_as_bytes` parameter.
    """

    mode = "r" + ("b" if read_as_bytes else "")
    encoding = None if read_as_bytes else "utf-8"

    if not path.isfile(file_path):
        yield None
        return

    temp_file_path = get_shadow_copy_temp_path(file_path) if shadow_copy else file_path

    try:
        if shadow_copy:
            copy2(file_path, temp_file_path)

        file_stream = open(temp_file_path, mode, encoding = encoding)
        yield file_stream

    finally:
        file_stream.close()
        if shadow_copy:
            unlink(temp_file_path)


def read(file_path: str, default: Optional[Any] = None,
         read_as_bytes: bool = False, shadow_copy: bool = True) -> Optional[Tuple[str, bytes, Any]]:
    """
    Read the contents of a file and return its data.

    Args:
        file_path (str): The path to the file to be read.
        default (Optional[Any]): The value to return if the file cannot 
            be read or an error occurs. Defaults to None.
        read_as_bytes (bool): If True, the file will be read in binary mode. 
            If False, it will be read as text. Defaults to False.

    Returns:
        Optional[Tuple[str, bytes, Any]]: The contents of the file as a string 
                                          or bytes, or the default value if 
                                          the file cannot be read.
    """

    try:
        with get_read_stream(file_path, read_as_bytes, shadow_copy) as file_stream:
            if file_stream is not None and file_stream.readable():
                return file_stream.read()

    except (FileNotFoundError, IsADirectoryError, OSError, IOError,
            PermissionError, ValueError, TypeError, UnicodeDecodeError):
        pass #log(f"`{file_path}` could not be read.", level = 4)

    return default


@contextmanager
def get_write_stream(file_path: str, write_as_bytes: bool = False, make_sure: bool = True,
                     shadow_copy: bool = True) -> Optional[Generator[TextIOWrapper, None, None]]:
    """
    Context manager for writing to a file stream, with options for creating 
    a shadow copy and ensuring data integrity.

    Args:
        file_path (str): The path to the file where the content will be written.
        write_as_bytes (Tuple[str, bytes]): Determines the mode in which the file
            is opened (text or binary).
        make_sure (bool, optional): If True, the file will be flushed and 
            synchronized to disk after writing. Defaults to True.
        shadow_copy (bool, optional): If True, a temporary shadow copy of the 
            file will be created for writing. Defaults to True.

    Yields:
        Optional[Generator[io.TextIOWrapper, None, None]]: A file stream object 
        that can be used to write the specified content to the file.
    """


    mode = "w" + ("b" if write_as_bytes else "")
    encoding = None if write_as_bytes else "utf-8"
    write_file_path = get_shadow_copy_temp_path(file_path) if shadow_copy else file_path
    lock_context_manager = dummy_context_manager if shadow_copy else get_lock

    try:
        with lock_context_manager(write_file_path):
            file_stream = open(write_file_path, mode, encoding = encoding)
            yield file_stream

            if make_sure:
                for _ in range(20):
                    file_stream.flush()
                    fsync(file_stream.fileno())

    finally:
        file_stream.close()
        if shadow_copy and write_file_path != file_path:
            move(write_file_path, file_path)


def execute_write(content: Tuple[str, bytes], file_path: str, make_sure: bool = False,
                  shadow_copy: bool = True) -> bool:
    """
    Write content to a specified file.

    Args:
        content (Tuple[str, bytes]): The content to be written to the file. 
                                     This can be a string or bytes.
        file_path (str): The path to the file where the content will be written.
        make_sure (bool): If True, flushes the file buffer to disk after writing.
        shadow_copy (bool): If True, uses a temporary shadow copy.

    Returns:
        bool: True if the content was successfully written to the file, 
              False otherwise.
    """

    try:
        with get_write_stream(file_path, isinstance(content, bytes),
                              make_sure, shadow_copy) as file_stream:
            if file_stream is not None and file_stream.writable():
                file_stream.write(content)
                return True

    except (FileNotFoundError, IsADirectoryError, OSError, IOError,
            PermissionError, ValueError, TypeError, UnicodeDecodeError):
        pass #log(f"`{file_path}` could not be writen.", level = 4)

    return False


def write(content: Tuple[str, bytes], file_path: str, make_sure: bool = False,
          shadow_copy: bool = False, as_thread: bool = False) -> bool:
    """
    Write content to a specified file, with options for execution mode.

    Args:
        content (Tuple[str, bytes]): The content to be written to the file. 
                                     This can be a string or bytes.
        file_path (str): The path to the file where the content will be written.
        make_sure (bool): If True, ensures that the content is flushed to disk 
                          after writing.
        shadow_copy (bool): If True, uses a temporary shadow copy.
        as_thread (bool): If True, executes the write operation in a separate thread.

    Returns:
        bool: True if the write operation was initiated successfully, 
              False if executed synchronously and the content was not written.
    """

    if as_thread:
        WRITE_EXECUTOR.submit(execute_write, content, file_path, make_sure, shadow_copy)
        return True

    return execute_write(content, file_path, make_sure, shadow_copy)


def delete_file(file_path: str) -> bool:
    try:
        remove(file_path)
        return True

    except (PermissionError, IsADirectoryError, OSError,
            FileNotFoundError, ValueError):
        pass

    return False


def delete(object_path: str) -> bool:
    """
    Delete a specified file or directory and its contents.

    Args:
        object_path (str): The path to the object (file or directory) to be deleted.

    Returns:
        bool: True if the object was successfully deleted, 
              False if the object type is unknown or an error occurred during deletion.
    """

    if not path.exists(object_path):
        return False

    if path.isfile(object_path):
        return delete_file(object_path)

    for root, directories, files in walk(object_path, topdown=False):
        for file in files:
            file_path = path.join(root, file)
            delete_file(file_path)

        for directory in directories:
            dir_path = path.join(root, directory)
            rmtree(dir_path)

    rmdir(object_path)

    return True


def is_process_running(process_id: str) -> bool:
    """
    Check if a process with the given process ID is currently running.

    Args:
        process_id (str): The ID of the process to check.

    Returns:
        bool: True if the process is running, False otherwise.
    """

    try:
        kill(process_id, 0)
    except OSError as exc:
        if exc.errno == ESRCH:
            return False

    return True


class DirectoryLock:
    """
    A class to manage a directory lock using a lock file.
    """


    def __init__(self, directory_path: str) -> None:
        """
        Initialize the DirectoryLock with the specified directory path.

        Args:
            directory_path (str): The path to the directory to be locked.
        """

        self.lock_file_path = path.join(directory_path, "running.lock")


    @property
    def locked(self) -> bool:
        """
        Check if the directory is currently locked.

        Returns:
            bool: True if the directory is locked, False otherwise.
        """

        if not path.isfile(self.lock_file_path):
            return False

        try:
            with open(self.lock_file_path, "r", encoding = "utf-8") as file_stream:
                try:
                    if IS_WINDOWS:
                        msvcrt.locking(file_stream.fileno(), msvcrt.LK_NBLCK, 1)
                        msvcrt.locking(file_stream.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(file_stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
                        fcntl.flock(file_stream, fcntl.LOCK_UN)

                except (IOError, OSError):
                    return True

                file_content = file_stream.read()
                return is_process_running(file_content.strip())

        except (FileNotFoundError, IsADirectoryError, OSError, IOError,
                PermissionError, ValueError, TypeError, UnicodeDecodeError):
            pass

        return False


    def create(self, process_id: Optional[int] = None) -> Optional[TextIOWrapper]:
        """
        Create a lock file to indicate that the directory is locked.

        Returns:
            Optional[io.TextIOWrapper]: A file stream to the lock file if
                created successfully, None otherwise.
        """

        file_stream = None

        try:
            file_stream = open(self.lock_file_path, "w", encoding = "utf-8")

            if IS_WINDOWS:
                msvcrt.locking(file_stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(file_stream, fcntl.LOCK_EX | fcntl.LOCK_NB)

            if process_id is None:
                process_id = getpid()

            file_stream.write(f"{process_id}")
            file_stream.flush()
            return file_stream

        except (PermissionError, IsADirectoryError, OSError, IOError,
                FileNotFoundError, ValueError, TypeError, UnicodeEncodeError):
            if file_stream:
                file_stream.close()

        return None


    def remove(self, lock_file: Optional[TextIOWrapper] = None) -> None:
        """
        Remove the lock file and release the lock.

        Args:
            lock_file (Optional[io.TextIOWrapper]): The file stream of the lock file to be removed.
                If None, only the file will be deleted.
        """

        if lock_file:
            try:
                if IS_WINDOWS:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock_file, fcntl.LOCK_UN)

            except (IOError, OSError):
                pass

            lock_file.close()

        delete(self.lock_file_path)


# This is not the safest way to delete files.
# If the files should be completely destroyed, physically remove your
# hard disk, smashing the disks inside. For an SSD, you can drill
# multiple holes in the drive or burn it to ensure that the storage
# chips are irreparably damaged.
class SecureShredder:
    """
    A class for securely shredding files and directories.
    """

    @staticmethod
    def file(file_path: str, iterations: int = 3) -> bool:
        """
        Securely shred a specified file by overwriting its contents.

        Args:
            file_path (str): The path to the file to be shredded.
            iterations (int): The number of times to overwrite the file. 
                              Defaults to 3.

        Returns:
            bool: True if the shredding process was successful, 
                  False if the specified path is a directory.
        """

        if path.isdir(file_path):
            return False

        file_size = path.getsize(file_path)

        def random_data() -> None:
            for _ in range(4):
                with get_write_stream(file_path, True, True, False) as file_stream:
                    file_stream.write(token_bytes(file_size))

        for _ in range(iterations):
            # Gutmann patterns
            random_data()
            for pattern_func in GUTMANN_PATTERNS:
                with get_write_stream(file_path, True, True, False) as file_stream:
                    file_stream.write(pattern_func(file_size))

            random_data()

            # DoD 5220.22-M
            for pattern_func in DOD_PATTERNS:
                with get_write_stream(file_path, True, True, False) as file_stream:
                    file_stream.write(pattern_func(file_size))

        delete(file_path)

        return True


    @staticmethod
    def directory(directory_path: str, iterations: int = 3) -> bool:
        """
        Securely shred all files within a specified directory and delete the directory.

        Args:
            directory_path (str): The path to the directory to be shredded.
            iterations (int): The number of times to overwrite each file. 
                Defaults to 3.

        Returns:
            None: This method does not return a value.
        """

        for dirpath, dirnames, filenames in walk(directory_path, topdown = False):
            futures = []
            for filename in filenames:
                file_path = path.join(dirpath, filename)

                futures.append(
                    SHREDDER_EXECUTOR.submit(
                        SecureShredder.file, file_path, iterations
                    )
                )

            for future in as_completed(futures):
                future.result()

            for dirname in dirnames:
                sub_directory_path = path.join(dirpath, dirname)
                delete(sub_directory_path)

        delete(directory_path)
