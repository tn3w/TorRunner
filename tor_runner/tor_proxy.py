import socket
from contextlib import contextmanager
from typing import Optional, Generator, List

try:
    from .tor_runner import TorRunner
    from .libraries import socks
except ImportError:
    from tor_runner import TorRunner
    from libraries import socks


class TorProxy:
    """
    A class to manage a Tor proxy instance, allowing control over Tor 
    bridge configurations and proxy handling through start, stop, 
    and restart methods.
    
    Attributes:
        tor_runner (TorRunner): An instance of the TorRunner class to manage Tor connections.
        socks_port (Optional[int]): The port for the SOCKS proxy or None if the proxy isn't running.
    """


    def __init__(self, bridges: Optional[List[str]] = None,
                 default_bridge_type: Optional[str] = None,
                 bridge_quantity: Optional[int] = None) -> None:
        """
        Initializes a TorProxy instance with specified bridge settings.
        
        Args:
            bridges (Optional[List[str]]): A list of bridge addresses to use for the Tor connection.
            default_bridge_type (Optional[str]): The default bridge type, if none are specified.
            bridge_quantity (Optional[int]): The number of bridges to configure (default is None).
        
        Returns:
            None
        """

        self.tor_runner = TorRunner(
            [], bridges, default_bridge_type=default_bridge_type,
            bridge_quantity=bridge_quantity
        )
        self.socks_port = None


    def start(self, quite: bool = True) -> None:
        """
        Starts the Tor proxy, initializing a SOCKS port for proxying.

        Args:
            quite (bool): If True, runs Tor in quiet mode with minimal output.
        
        Returns:
            None
        """

        socks_port = self.tor_runner.get_ports()[1]
        self.tor_runner.run([], socks_port, quite, False)
        self.socks_port = socks_port


    def stop(self) -> None:
        """
        Stops the Tor proxy and releases the SOCKS port.

        Returns:
            None
        """

        self.socks_port = None
        self.tor_runner.exit()


    def restart(self, quite: bool = True) -> None:
        """
        Restarts the Tor proxy by stopping and starting it again.

        Args:
            quite (bool): If True, runs Tor in quiet mode with minimal output.
        
        Returns:
            None
        """

        self.stop()
        self.start(quite)


    @contextmanager
    def urllib(self, quite: bool = True) -> Generator[None, None, None]:
        """
        Context manager to set up SOCKS proxy for urllib requests.

        Args:
            quite (bool): If True, runs Tor in quiet mode with minimal output.

        Yields:
            None
        """

        if self.socks_port is None:
            self.start(quite)

        original_socket = socket.socket

        try:
            socket.setdefaulttimeout(3)
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", self.socks_port)
            socket.socket = socks.socksocket
            yield
        finally:
            socks.setdefaultproxy(None)
            socket.socket = original_socket
