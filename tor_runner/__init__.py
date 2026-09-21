import atexit
import json
import os
import platform
import shutil
import subprocess
import tarfile
import threading
import urllib.request
from pathlib import Path

ARCHIVE_URL = "https://archive.torproject.org/tor-package-archive/torbrowser"
RELEASES_URL = "https://aus1.torproject.org/torbrowser/update_3/release/downloads.json"
FALLBACK_VERSION = "15.0.15"
DATA_DIRECTORY = Path.home() / ".cache" / "tor_runner"
ARCHITECTURES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "arm64": "aarch64",
    "aarch64": "aarch64",
    "i386": "i686",
    "i686": "i686",
}
TRANSPORTS = {
    "obfs4,meek_lite,webtunnel": "lyrebird",
    "snowflake": "snowflake-client",
}


def latest_version() -> str:
    try:
        with urllib.request.urlopen(RELEASES_URL, timeout=15) as response:
            downloads = json.load(response)["downloads"]
        url = downloads["linux-x86_64"]["ALL"]["binary"]
        return url.split("/torbrowser/")[1].split("/")[0]
    except (OSError, KeyError, IndexError, ValueError):
        return FALLBACK_VERSION


def download_tor(system: str, binary: Path) -> None:
    architecture = ARCHITECTURES[platform.machine().lower()]
    version = latest_version()
    package = f"tor-expert-bundle-{system}-{architecture}-{version}.tar.gz"
    print(f" * Downloading Tor {version} for {system}/{architecture}", flush=True)

    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    archive, _ = urllib.request.urlretrieve(f"{ARCHIVE_URL}/{version}/{package}")
    with tarfile.open(archive) as bundle:
        bundle.extractall(DATA_DIRECTORY, filter="data")
    binary.chmod(0o700)


def find_tor() -> tuple[str, dict, Path | None]:
    installed = shutil.which("tor")
    if installed:
        return installed, {}, None

    system = platform.system().lower()
    system = {"darwin": "macos", "windows": "windows"}.get(system, "linux")
    binary = DATA_DIRECTORY / "tor" / ("tor.exe" if system == "windows" else "tor")
    if not binary.exists():
        download_tor(system, binary)

    transports = DATA_DIRECTORY / "tor" / "pluggable_transports"
    if system == "windows":
        return str(binary), {}, transports
    variable = "DYLD_LIBRARY_PATH" if system == "macos" else "LD_LIBRARY_PATH"
    return str(binary), {variable: str(binary.parent)}, transports


def transport_lines(transports: Path | None) -> list[str]:
    lines = []
    for protocols, name in TRANSPORTS.items():
        executable = shutil.which(name)
        if not executable and transports:
            executable = shutil.which(name, path=transports)
        if executable:
            lines.append(f'ClientTransportPlugin {protocols} exec "{executable}"')
    return lines


class TorRunner:
    def __init__(
        self,
        hidden_service_directory: str | Path | None = None,
        bridges: list[str] | None = None,
        socks_port: int = 0,
    ):
        self.directory = Path(hidden_service_directory or DATA_DIRECTORY / "service")
        self.bridges = bridges or []
        self.socks_port = socks_port
        self.process: subprocess.Popen | None = None

    def configuration(self, listeners: list[tuple[int, int]], transports) -> str:
        lines = [
            f"SocksPort {self.socks_port}",
            f'DataDirectory "{(DATA_DIRECTORY / "data").as_posix()}"',
        ]
        if listeners:
            lines.append(f'HiddenServiceDir "{self.directory.as_posix()}"')
        for onion_port, local_port in listeners:
            lines.append(f"HiddenServicePort {onion_port} 127.0.0.1:{local_port}")
        if self.bridges:
            lines.append("UseBridges 1")
            lines += transport_lines(transports)
            lines += [f"Bridge {bridge}" for bridge in self.bridges]
        return "\n".join(lines) + "\n"

    def start(self, listeners: list[tuple[int, int]] = ()) -> str | None:
        binary, environment, transports = find_tor()
        DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)
        torrc = DATA_DIRECTORY / "torrc"
        torrc.write_text(self.configuration(list(listeners), transports))

        self.process = subprocess.Popen(
            [binary, "-f", str(torrc)],
            stdout=subprocess.PIPE,
            text=True,
            env={**os.environ, **environment},
        )
        atexit.register(self.stop)
        self.wait_for_bootstrap()

        if not listeners:
            return None
        address = (self.directory / "hostname").read_text().strip()
        print(f" * Onion service on http://{address}", flush=True)
        return address

    def wait_for_bootstrap(self) -> None:
        errors = []
        for line in self.process.stdout:
            if "[err]" in line or "[warn]" in line:
                errors.append(line.strip())
            if "Bootstrapped 100%" in line:
                threading.Thread(target=self.process.stdout.read, daemon=True).start()
                return
        raise RuntimeError("Tor exited before bootstrapping:\n" + "\n".join(errors))

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait()

    def flask_run(self, app, host: str = "127.0.0.1", port: int = 5000, **options):
        if os.environ.get("WERKZEUG_RUN_MAIN") != "true":
            threading.Thread(target=self.start, args=([(80, port)],), daemon=True).start()
        app.run(host=host, port=port, **options)


def delete_data() -> None:
    shutil.rmtree(DATA_DIRECTORY, ignore_errors=True)
