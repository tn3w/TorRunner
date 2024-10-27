"""
tor_proxy.py

Sets up a Tor SOCKS connection for proxy usage.

License: GNU General Public License v3.0
    https://github.com/tn3w/TorRunner/blob/master/LICENSE
Source: https://github.com/tn3w/TorRunner
"""

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

        if self.socks_port is not None:
            return

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
    def urllib(self, timeout: int = 3, quiet: bool = True) -> Generator:
        """
        Context manager to set up SOCKS proxy for urllib requests.

        Args:
            timeout (int): 
            quiet (bool): If True, runs Tor in quiet mode with minimal output.

        Yields:
            None
        """

        self.start(quiet)
        original_socket = socket.socket

        try:
            socket.setdefaulttimeout(timeout)
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", self.socks_port)
            socket.socket = socks.socksocket
            yield

        finally:
            socks.setdefaultproxy(None)
            socket.socket = original_socket


    @contextmanager
    def requests(self, timeout: int = 3, quiet: bool = True) \
            -> Generator["requests.Session", None, None]:
        """
        Context manager to set up SOCKS proxy for requests library.

        Args:
            timeout (int): Timeout for the request.
            quiet (bool): If True, runs the proxy in quiet mode with minimal output.

        Yields:
            requests.Session: A session object configured with the SOCKS proxy.
        """

        self.start(quiet)
        original_socket = socket.socket

        import requests
        session = requests.Session()

        try:
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", self.socks_port)
            socket.socket = socks.socksocket

            session.timeout = timeout
            yield session

        finally:
            socks.setdefaultproxy(None)
            socket.socket = original_socket
            session.close()
