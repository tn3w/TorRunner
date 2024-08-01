"""

This file requires pytesseract and PIL.
"""

import os
import re
import time
import subprocess
from typing import Optional
from urllib.parse import urljoin

try:
    from tor_runner.utils import OPERATING_SYSTEM, ARCHITECTURE, request_url, extract_anchors,\
        temp_fp, download_file
except ImportError:
    from utils import OPERATING_SYSTEM, ARCHITECTURE, request_url, extract_anchors, temp_fp,\
        download_file


if OPERATING_SYSTEM == 'windows':
    import ctypes
    import ctypes.wintypes

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    shell32 = ctypes.WinDLL('shell32', use_last_error=True)


    class ShellExecuteInfo(ctypes.Structure):
        """
        A ctypes structure used to specify information for
        executing a command via ShellExecuteEx.

        https://docs.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-shellexecuteinfoa
        """

        _fields_ = [
            ('cbSize', ctypes.wintypes.DWORD),
            ('fMask', ctypes.wintypes.ULONG),
            ('hwnd', ctypes.wintypes.HANDLE),
            ('lpVerb', ctypes.wintypes.LPCWSTR),
            ('lpFile', ctypes.wintypes.LPCWSTR),
            ('lpParameters', ctypes.wintypes.LPCWSTR),
            ('lpDirectory', ctypes.wintypes.LPCWSTR),
            ('nShow', ctypes.c_int),
            ('hInstApp', ctypes.wintypes.HINSTANCE),
            ('lpIDList', ctypes.c_void_p),
            ('lpClass', ctypes.wintypes.LPCWSTR),
            ('hkeyClass', ctypes.wintypes.HKEY),
            ('dwHotKey', ctypes.wintypes.DWORD),
            ('hIcon', ctypes.wintypes.HANDLE),
            ('hProcess', ctypes.wintypes.HANDLE)
        ]

        def __init__(self, lpVerb: Optional[str] = None,
                     lpFile: Optional[str] = None,
                     nShow: Optional[int] = None):
            if None in [lpVerb, lpFile]:
                return

            self.cbSize = ctypes.sizeof(self)
            self.lpVerb = lpVerb
            self.lpFile = lpFile

            if not isinstance(nShow, int):
                nShow = 1

            self.nShow = nShow

    shell_execute_ex = shell32.ShellExecuteExW
    shell_execute_ex.argtypes = [ctypes.POINTER(ShellExecuteInfo)]
    shell_execute_ex.restype = ctypes.wintypes.BOOL

    wait_for_single_object = kernel32.WaitForSingleObject
    wait_for_single_object.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
    wait_for_single_object.restype = ctypes.wintypes.DWORD


def windows_download_latest() -> str:
    """
    Download the latest version of Tesseract for Windows.

    :return: The path to the downloaded file.
    """

    correct_architecture: str = {
        "i686": "w32",
        "x86_64": "w64",
    }.get(ARCHITECTURE, ARCHITECTURE)

    url = 'https://digi.bib.uni-mannheim.de/tesseract/'

    download_url = None
    content = request_url(url, return_as_bytes = False)

    if content is not None:
        anchors = extract_anchors(content)

        for anchor in anchors:
            if re.search(
                re.compile(
                    fr'tesseract.*ocr.*{correct_architecture}.*setup.*\.exe',
                    re.IGNORECASE
                ), anchor
            ):

                download_url = urljoin(url, anchor)
                break

    if download_url is None:
        raise OSError("Tesseract download URL not found. Please install manual for your "+
                      "system from https://digi.bib.uni-mannheim.de/tesseract/ and install it.")

    temp_file_path = temp_fp(f"tesseract-{correct_architecture}.exe")
    print(" * Downloading Tesseract...")
    download_file(download_url, temp_file_path)

    return temp_file_path


def wait_for_tesseract(tesseract_file_path: str) -> None:
    """
    Wait for Tesseract to finish.

    :param file_path: The path to the downloaded file.
    :return: None
    """

    while True:
        try:
            os.remove(tesseract_file_path)
        except PermissionError:
            time.sleep(0.5)
        else:
            break


def run_wizard(tesseract_file_path: str) -> None:
    """
    Run the Tesseract OCR wizard and wait for completion.

    :param file_path: The path to the downloaded file.
    :return: None
    """

    command = [tesseract_file_path, '/quiet']

    if OPERATING_SYSTEM == "windows":
        if not ctypes.windll.shell32.IsUserAnAdmin():
            sei = ShellExecuteInfo('runas', command[0], ' '.join(command[1:]))

            if shell_execute_ex(ctypes.byref(sei)) and sei.hProcess:
                wait_for_single_object(sei.hProcess, 0xFFFFFFFF)

            print(" * Waiting for Tesseract Wizard to finish...")
            wait_for_tesseract(tesseract_file_path)

            return

    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        process.wait()


if __name__ == "__main__":
    if OPERATING_SYSTEM == "windows":
        file_path = windows_download_latest()
        run_wizard(file_path)
    else:
        raise OSError("Unsupported operating system.")
