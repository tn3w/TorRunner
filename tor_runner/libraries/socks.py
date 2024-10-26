"""
socks.py

Enables SOCKS proxy connections to be established in Python applications.
It provides an interface for establishing connections via different SOCKS
versions. By using SOCKS, applications can establish anonymous or secure
connections via proxies. The library facilitates the integration of proxy
functionality in network applications.

License: BSD https://github.com/Anorov/PySocks/blob/master/LICENSE
Source: PySocks PyPi Package https://github.com/Anorov/PySocks
"""

from base64 import b64encode
from typing import Callable
from errno import EOPNOTSUPP, EINVAL, EAGAIN
import functools
from io import BytesIO
import logging
import os
from os import SEEK_CUR
import socket
import struct


__version__ = "1.7.1"

if os.name == "nt" and not hasattr(socket, "inet_pton"):
    try:
        from win_inet_pton import inject_into_socket
    except ImportError:
        from libraries.win_inet_pton import inject_into_socket

    try:
        inject_into_socket()
    except (SystemError, TypeError, OSError,
            socket.error, ValueError):
        pass

log = logging.getLogger(__name__)

PROXY_TYPE_SOCKS4 = SOCKS4 = 1
PROXY_TYPE_SOCKS5 = SOCKS5 = 2
PROXY_TYPE_HTTP = HTTP = 3

PROXY_TYPES = {"SOCKS4": SOCKS4, "SOCKS5": SOCKS5, "HTTP": HTTP}
PRINTABLE_PROXY_TYPES = dict(zip(PROXY_TYPES.values(), PROXY_TYPES.keys()))

_orgsocket = _orig_socket = socket.socket


def set_self_blocking(function: Callable) -> Callable:
    """
    A decorator to temporarily set the blocking behavior of a function's first argument
    (presumably a socket object) to non-blocking, execute the wrapped function, and then
    reset the original blocking behavior.
    
    :param function: The function to be wrapped.
    :return: The wrapper function.
    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        self = args[0]
        try:
            _is_blocking = self.gettimeout()
            if _is_blocking == 0:
                self.setblocking(True)
            return function(*args, **kwargs)
        finally:
            if _is_blocking == 0:
                self.setblocking(False)
    return wrapper


class ProxyError(IOError):
    """
    Socket_err contains original socket.error exception.
    """

    def __init__(self, msg: str, socket_err: str | None = None):
        self.msg = msg
        self.socket_err = socket_err

        if socket_err:
            self.msg += f': {socket_err}'

    def __str__(self):
        return self.msg


class GeneralProxyError(ProxyError):
    """
    An error that represents a general problem encountered with a proxy connection.
    This could include issues such as inability to establish a connection,
    unexpected behavior, or other generic errors.
    """

class ProxyConnectionError(ProxyError):
    """
    An error that occurs when there is a problem establishing a connection with the proxy server.
    This could be due to network issues, server unavailability, or incorrect proxy settings.
    """

class SOCKS5AuthError(ProxyError):
    """
    An error specific to SOCKS5 proxy authentication failure.
    This error occurs when the proxy server requires authentication,
    but the provided credentials are invalid or missing.
    """

class SOCKS5Error(ProxyError):
    """
    An error specific to SOCKS5 proxy connections.
    This could include errors such as protocol violations, unsupported
    features, or other issues specific to the SOCKS5 protocol.
    """

class SOCKS4Error(ProxyError):
    """
    An error specific to SOCKS4 proxy connections.
    This could include errors such as protocol violations, unsupported
    features, or other issues specific to the SOCKS4 protocol.
    """

class HTTPError(ProxyError):
    """
    An error specific to HTTP proxy connections.
    This could include errors such as HTTP status codes indicating
    problems with the proxy server or the HTTP request.
    """

SOCKS4_ERRORS = {
    0x5B: "Request rejected or failed",
    0x5C: ("Request rejected because SOCKS server cannot connect to identd on"
           " the client"),
    0x5D: ("Request rejected because the client program and identd report"
           " different user-ids")
}

SOCKS5_ERRORS = {
    0x01: "General SOCKS server failure",
    0x02: "Connection not allowed by ruleset",
    0x03: "Network unreachable",
    0x04: "Host unreachable",
    0x05: "Connection refused",
    0x06: "TTL expired",
    0x07: "Command not supported, or protocol error",
    0x08: "Address type not supported"
}

DEFAULT_PORTS = {SOCKS4: 1080, SOCKS5: 1080, HTTP: 8080}


def set_default_proxy(proxy_type=None, addr=None, port=None, rdns=True,
                      username=None, password=None):
    """
    Sets a default proxy.

    All further socksocket objects will use the default unless explicitly
    changed. All parameters are as for socket.set_proxy().
    """

    socksocket.default_proxy = (proxy_type, addr, port, rdns,
                                username.encode() if username else None,
                                password.encode() if password else None)


def setdefaultproxy(*args, **kwargs):
    """
    A function that acts as a wrapper around set_default_proxy function, 
    with the ability to modify the proxy_type argument.

    :param *args: Positional arguments passed to set_default_proxy.
    :param **kwargs: Keyword arguments passed to set_default_proxy.
    :return: Whatever is returned by set_default_proxy function.
    """

    if "proxytype" in kwargs:
        kwargs["proxy_type"] = kwargs.pop("proxytype")
    return set_default_proxy(*args, **kwargs)


def get_default_proxy():
    """
    Returns the default proxy, set by set_default_proxy.
    """

    return socksocket.default_proxy

getdefaultproxy = get_default_proxy


def wrap_module(module):
    """
    Attempts to replace a module's socket library with a SOCKS socket.

    Must set a default proxy using set_default_proxy(...) first. This will
    only work on modules that import socket directly into the namespace;
    most of the Python Standard Library falls into this category.
    """

    if socksocket.default_proxy:
        module.socket.socket = socksocket
    else:
        raise GeneralProxyError("No default proxy specified")

wrapmodule = wrap_module


def create_connection(dest_pair,
                      timeout=None, source_address=None,
                      proxy_type=None, proxy_addr=None,
                      proxy_port=None, proxy_rdns=True,
                      proxy_username=None, proxy_password=None,
                      socket_options=None):
    """
    create_connection(dest_pair, *[, timeout], **proxy_args) -> socket object

    Like socket.create_connection(), but connects to proxy
    before returning the socket object.

    dest_pair - 2-tuple of (IP/hostname, port).
    **proxy_args - Same args passed to socksocket.set_proxy() if present.
    timeout - Optional socket timeout value, in seconds.
    source_address - tuple (host, port) for the socket to bind to as its source
    address before connecting (only for compatibility)
    """

    remote_host, remote_port = dest_pair
    if remote_host.startswith("["):
        remote_host = remote_host.strip("[]")
    if proxy_addr and proxy_addr.startswith("["):
        proxy_addr = proxy_addr.strip("[]")

    err = None

    for r in socket.getaddrinfo(proxy_addr, proxy_port, 0, socket.SOCK_STREAM):
        family, socket_type, proto = r[:3]
        sock = None
        try:
            sock = socksocket(family, socket_type, proto)

            if socket_options:
                for opt in socket_options:
                    sock.setsockopt(*opt)

            if isinstance(timeout, (int, float)):
                sock.settimeout(timeout)

            if proxy_type:
                sock.set_proxy(proxy_type, proxy_addr, proxy_port, proxy_rdns,
                               proxy_username, proxy_password)
            if source_address:
                sock.bind(source_address)

            sock.connect((remote_host, remote_port))
            return sock

        except (socket.error, ProxyError) as e:
            err = e
            if sock:
                sock.close()
                sock = None

    if err:
        raise err

    raise socket.error("gai returned empty list.")


class _BaseSocket(socket.socket):
    """
    Allows Python 2 delegated methods such as send() to be overridden.
    """

    def __init__(self, *pos, **kw):
        _orig_socket.__init__(self, *pos, **kw)

        self._savedmethods = {}
        for save_name in self._savenames:
            self._savedmethods[save_name] = getattr(self, save_name)
            delattr(self, save_name)

    _savenames = []


def _makemethod(save_name):
    return lambda self, *pos, **kw: self._savedmethods[save_name](*pos, **kw)


for name in ("sendto", "send", "recvfrom", "recv"):
    method = getattr(_BaseSocket, name, None)

    if not isinstance(method, Callable):
        _BaseSocket._savenames.append(name)
        setattr(_BaseSocket, name, _makemethod(name))


class socksocket(_BaseSocket):
    """
    socksocket([family[, type[, proto]]]) -> socket object

    Open a SOCKS enabled socket. The parameters are the same as
    those of the standard socket init. In order for SOCKS to work,
    you must specify family=AF_INET and proto=0.
    The "type" argument must be either SOCK_STREAM or SOCK_DGRAM.
    """

    default_proxy = None

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM,
                 proto=0, *args, **kwargs):
        if type not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            msg = "Socket type must be stream or datagram, not {!r}"
            raise ValueError(msg.format(type))

        super(socksocket, self).__init__(family, type, proto, *args, **kwargs)
        self._proxyconn = None

        if self.default_proxy:
            self.proxy = self.default_proxy
        else:
            self.proxy = (None, None, None, None, None, None)
        self.proxy_sockname = None
        self.proxy_peername = None

        self._timeout = None

    def _readall(self, file, count):
        """
        Receive EXACTLY the number of bytes requested from the file object.
        Blocks until the required number of bytes have been received.
        """

        data = b""
        while len(data) < count:
            d = file.read(count - len(data))
            if not d:
                raise GeneralProxyError("Connection closed unexpectedly")
            data += d
        return data

    def settimeout(self, timeout):
        self._timeout = timeout
        try:
            self.get_proxy_peername()
            super(socksocket, self).settimeout(self._timeout)
        except socket.error:
            pass

    def gettimeout(self):
        return self._timeout

    def setblocking(self, v):
        if v:
            self.settimeout(None)
        else:
            self.settimeout(0.0)

    def set_proxy(self, proxy_type=None, addr=None, port=None, rdns=True,
                  username=None, password=None):
        """
        Sets the proxy to be used.

        proxy_type -  The type of the proxy to be used. Three types
                        are supported: PROXY_TYPE_SOCKS4 (including socks4a),
                        PROXY_TYPE_SOCKS5 and PROXY_TYPE_HTTP
        addr -        The address of the server (IP or DNS).
        port -        The port of the server. Defaults to 1080 for SOCKS
                        servers and 8080 for HTTP proxy servers.
        rdns -        Should DNS queries be performed on the remote side
                       (rather than the local side). The default is True.
                       Note: This has no effect with SOCKS4 servers.
        username -    Username to authenticate with to the server.
                       The default is no authentication.
        password -    Password to authenticate with to the server.
                       Only relevant when username is also provided.
        """

        self.proxy = (proxy_type, addr, port, rdns,
                      username.encode() if username else None,
                      password.encode() if password else None)

    def setproxy(self, *args, **kwargs):
        if "proxytype" in kwargs:
            kwargs["proxy_type"] = kwargs.pop("proxytype")
        return self.set_proxy(*args, **kwargs)

    def bind(self, *pos, **kw):
        """
        Implements proxy connection for UDP sockets.
        Happens during the bind() phase.
        """

        proxy_type = self.proxy[1]
        if not proxy_type or self.type != socket.SOCK_DGRAM:
            return _orig_socket.bind(self, *pos, **kw)

        if self._proxyconn:
            raise socket.error(EINVAL, "Socket already bound to an address")
        if proxy_type != SOCKS5:
            msg = "UDP only supported by SOCKS5 proxy type"
            raise socket.error(EOPNOTSUPP, msg)
        super(socksocket, self).bind(*pos, **kw)

        _, port = self.getsockname()
        dst = ("0", port)

        self._proxyconn = _orig_socket()
        proxy = self._proxy_addr()
        self._proxyconn.connect(proxy)

        UDP_ASSOCIATE = b"\x03"
        _, relay = self._SOCKS5_request(self._proxyconn, UDP_ASSOCIATE, dst)

        host, _ = proxy
        _, port = relay
        super(socksocket, self).connect((host, port))
        super(socksocket, self).settimeout(self._timeout)
        self.proxy_sockname = ("0.0.0.0", 0)

    def sendto(self, bytes, *args, **kwargs):
        if self.type != socket.SOCK_DGRAM:
            return super(socksocket, self).sendto(bytes, *args, **kwargs)
        if not self._proxyconn:
            self.bind(("", 0))

        address = args[-1]
        flags = args[:-1]

        header = BytesIO()
        RSV = b"\x00\x00"
        header.write(RSV)
        STANDALONE = b"\x00"
        header.write(STANDALONE)
        self._write_SOCKS5_address(address, header)

        sent = super(socksocket, self).send(header.getvalue() + bytes, *flags,
                                            **kwargs)
        return sent - header.tell()

    def send(self, bytes, flags=0, **kwargs):
        if self.type == socket.SOCK_DGRAM:
            return self.sendto(bytes, flags, self.proxy_peername, **kwargs)
        else:
            return super(socksocket, self).send(bytes, flags, **kwargs)

    def recvfrom(self, bufsize, flags=0):
        if self.type != socket.SOCK_DGRAM:
            return super(socksocket, self).recvfrom(bufsize, flags)
        if not self._proxyconn:
            self.bind(("", 0))

        buf = BytesIO(super(socksocket, self).recv(bufsize + 1024, flags))
        buf.seek(2, SEEK_CUR)
        frag = buf.read(1)
        if ord(frag):
            raise NotImplementedError("Received UDP packet fragment")
        fromhost, fromport = self._read_SOCKS5_address(buf)

        if self.proxy_peername:
            peerhost, peerport = self.proxy_peername
            if fromhost != peerhost or peerport not in (0, fromport):
                raise socket.error(EAGAIN, "Packet filtered")

        return (buf.read(bufsize), (fromhost, fromport))

    def recv(self, *pos, **kw):
        bytes, _ = self.recvfrom(*pos, **kw)
        return bytes

    def close(self):
        if self._proxyconn:
            self._proxyconn.close()
        return super(socksocket, self).close()

    def get_proxy_sockname(self):
        """
        Returns the bound IP address and port number at the proxy.
        """
        return self.proxy_sockname

    getproxysockname = get_proxy_sockname

    def get_proxy_peername(self):
        """
        Returns the IP and port number of the proxy.
        """
        return self.getpeername()

    getproxypeername = get_proxy_peername

    def get_peername(self):
        """Returns the IP address and port number of the destination machine.

        Note: get_proxy_peername returns the proxy."""
        return self.proxy_peername

    getpeername = get_peername

    def _negotiate_SOCKS5(self, *dest_addr):
        """
        Negotiates a stream connection through a SOCKS5 server.
        """
        CONNECT = b"\x01"
        self.proxy_peername, self.proxy_sockname = self._SOCKS5_request(
            self, CONNECT, dest_addr)

    def _SOCKS5_request(self, conn, cmd, dst):
        """
        Send SOCKS5 request with given command (CMD field) and
        address (DST field). Returns resolved DST address that was used.
        """
        username, password = self.proxy[4:6]

        writer = conn.makefile("wb")
        reader = conn.makefile("rb", 0)
        try:
            if username and password:
                writer.write(b"\x05\x02\x00\x02")
            else:
                writer.write(b"\x05\x01\x00")

            writer.flush()
            chosen_auth = self._readall(reader, 2)

            if chosen_auth[0:1] != b"\x05":

                raise GeneralProxyError(
                    "SOCKS5 proxy server sent invalid data")


            if chosen_auth[1:2] == b"\x02":
                if not (username and password):
                    raise SOCKS5AuthError("No username/password supplied. "
                                          "Server requested username/password"
                                          " authentication")

                writer.write(b"\x01" + chr(len(username)).encode()
                             + username
                             + chr(len(password)).encode()
                             + password)
                writer.flush()
                auth_status = self._readall(reader, 2)
                if auth_status[0:1] != b"\x01":
                    raise GeneralProxyError(
                        "SOCKS5 proxy server sent invalid data")
                if auth_status[1:2] != b"\x00":
                    raise SOCKS5AuthError("SOCKS5 authentication failed")


            elif chosen_auth[1:2] != b"\x00":
                if chosen_auth[1:2] == b"\xFF":
                    raise SOCKS5AuthError(
                        "All offered SOCKS5 authentication methods were"
                        " rejected")
                raise GeneralProxyError("SOCKS5 proxy server sent invalid data")

            writer.write(b"\x05" + cmd + b"\x00")
            resolved = self._write_SOCKS5_address(dst, writer)
            writer.flush()

            resp = self._readall(reader, 3)
            if resp[0:1] != b"\x05":
                raise GeneralProxyError("SOCKS5 proxy server sent invalid data")

            status = ord(resp[1:2])
            if status != 0x00:
                error = SOCKS5_ERRORS.get(status, "Unknown error")
                raise SOCKS5Error(f"{status:#04x}: {error}")

            bnd = self._read_SOCKS5_address(reader)

            super(socksocket, self).settimeout(self._timeout)
            return (resolved, bnd)
        finally:
            reader.close()
            writer.close()

    def _write_SOCKS5_address(self, addr, file):
        """
        Return the host and port packed for the SOCKS5 protocol,
        and the resolved address as a tuple object.
        """

        host, port = addr
        rdns = self.proxy[3]
        family_to_byte = {socket.AF_INET: b"\x01", socket.AF_INET6: b"\x04"}

        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                addr_bytes = socket.inet_pton(family, host)
                file.write(family_to_byte[family] + addr_bytes)
                host = socket.inet_ntop(family, addr_bytes)
                file.write(struct.pack(">H", port))
                return host, port
            except socket.error:
                continue

        if rdns:
            host_bytes = host.encode("idna")
            file.write(b"\x03" + chr(len(host_bytes)).encode() + host_bytes)
        else:
            addresses = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                           socket.SOCK_STREAM,
                                           socket.IPPROTO_TCP,
                                           socket.AI_ADDRCONFIG)
            target_addr = addresses[0]
            family = target_addr[0]
            host = target_addr[4][0]

            addr_bytes = socket.inet_pton(family, host)
            file.write(family_to_byte[family] + addr_bytes)
            host = socket.inet_ntop(family, addr_bytes)
        file.write(struct.pack(">H", port))
        return host, port

    def _read_SOCKS5_address(self, file):
        atyp = self._readall(file, 1)
        if atyp == b"\x01":
            addr = socket.inet_ntoa(self._readall(file, 4))
        elif atyp == b"\x03":
            length = self._readall(file, 1)
            addr = self._readall(file, ord(length))
        elif atyp == b"\x04":
            addr = socket.inet_ntop(socket.AF_INET6, self._readall(file, 16))
        else:
            raise GeneralProxyError("SOCKS5 proxy server sent invalid data")

        port = struct.unpack(">H", self._readall(file, 2))[0]
        return addr, port

    def _negotiate_SOCKS4(self, dest_addr, dest_port):
        """
        Negotiates a connection through a SOCKS4 server.
        """
        rdns, username = self.proxy[3:5]

        writer = self.makefile("wb")
        reader = self.makefile("rb", 0)
        try:
            remote_resolve = False
            try:
                addr_bytes = socket.inet_aton(dest_addr)
            except socket.error:
                if rdns:
                    addr_bytes = b"\x00\x00\x00\x01"
                    remote_resolve = True
                else:
                    addr_bytes = socket.inet_aton(
                        socket.gethostbyname(dest_addr))

            writer.write(struct.pack(">BBH", 0x04, 0x01, dest_port))
            writer.write(addr_bytes)

            if username:
                writer.write(username)
            writer.write(b"\x00")

            if remote_resolve:
                writer.write(dest_addr.encode("idna") + b"\x00")
            writer.flush()

            resp = self._readall(reader, 8)
            if resp[0:1] != b"\x00":
                raise GeneralProxyError(
                    "SOCKS4 proxy server sent invalid data")

            status = ord(resp[1:2])
            if status != 0x5A:
                error = SOCKS4_ERRORS.get(status, "Unknown error")
                raise SOCKS4Error(f"{status:#04x}: {error}")

            self.proxy_sockname = (socket.inet_ntoa(resp[4:]),
                                   struct.unpack(">H", resp[2:4])[0])
            if remote_resolve:
                self.proxy_peername = socket.inet_ntoa(addr_bytes), dest_port
            else:
                self.proxy_peername = dest_addr, dest_port
        finally:
            reader.close()
            writer.close()

    def _negotiate_HTTP(self, dest_addr, dest_port):
        """
        Negotiates a connection through an HTTP server.
        NOTE: This currently only supports HTTP CONNECT-style proxies.
        """

        addr, rdns, username, password =\
            self.proxy[1], self.proxy[3], self.proxy[4], self.proxy[5]

        addr = dest_addr if rdns else socket.gethostbyname(dest_addr)

        http_headers = [
            (b"CONNECT " + addr.encode("idna") + b":"
             + str(dest_port).encode() + b" HTTP/1.1"),
            b"Host: " + dest_addr.encode("idna")
        ]

        if username and password:
            http_headers.append(b"Proxy-Authorization: basic "
                                + b64encode(username + b":" + password))

        http_headers.append(b"\r\n")

        self.sendall(b"\r\n".join(http_headers))

        fobj = self.makefile()
        status_line = fobj.readline()
        fobj.close()

        if not status_line:
            raise GeneralProxyError("Connection closed unexpectedly")

        try:
            proto, status_code, status_msg = status_line.split(" ", 2)
        except ValueError:
            raise GeneralProxyError("HTTP proxy server sent invalid response")

        if not proto.startswith("HTTP/"):
            raise GeneralProxyError(
                "Proxy server does not appear to be an HTTP proxy")

        try:
            status_code = int(status_code)
        except ValueError:
            raise HTTPError(
                "HTTP proxy server did not return a valid HTTP status")

        if status_code != 200:
            error = f"{status_code}: {status_msg}"
            if status_code in (400, 403, 405):
                error += ("\n[*] Note: The HTTP proxy server may not be"
                          " supported by PySocks (must be a CONNECT tunnel"
                          " proxy)")
            raise HTTPError(error)

        self.proxy_sockname = (b"0.0.0.0", 0)
        self.proxy_peername = addr, dest_port

    _proxy_negotiators = {
                           SOCKS4: _negotiate_SOCKS4,
                           SOCKS5: _negotiate_SOCKS5,
                           HTTP: _negotiate_HTTP
                         }

    @set_self_blocking
    def connect(self, dest_pair, catch_errors=None):
        """
        Connects to the specified destination through a proxy.
        Uses the same API as socket's connect().
        To select the proxy server, use set_proxy().

        dest_pair - 2-tuple of (IP/hostname, port).
        """

        if len(dest_pair) != 2 or dest_pair[0].startswith("["):
            raise socket.error("PySocks doesn't support IPv6: %s"
                               % str(dest_pair))

        dest_addr, dest_port = dest_pair

        if self.type == socket.SOCK_DGRAM:
            if not self._proxyconn:
                self.bind(("", 0))
            dest_addr = socket.gethostbyname(dest_addr)

            if dest_addr == "0.0.0.0" and not dest_port:
                self.proxy_peername = None
            else:
                self.proxy_peername = (dest_addr, dest_port)
            return

        proxy_type, proxy_addr, proxy_port = self.proxy[:3]

        if (not isinstance(dest_pair, (list, tuple))
                or len(dest_pair) != 2
                or not dest_addr
                or not isinstance(dest_port, int)):
            raise GeneralProxyError(
                "Invalid destination-connection (host, port) pair")

        super(socksocket, self).settimeout(self._timeout)

        if proxy_type is None:
            self.proxy_peername = dest_pair
            super(socksocket, self).settimeout(self._timeout)
            super(socksocket, self).connect((dest_addr, dest_port))
            return

        proxy_addr = self._proxy_addr()

        try:
            super(socksocket, self).connect(proxy_addr)

        except socket.error as error:
            self.close()
            if not catch_errors:
                proxy_addr, proxy_port = proxy_addr
                proxy_server = f"{proxy_addr}:{proxy_port}"
                printable_type = PRINTABLE_PROXY_TYPES[proxy_type]

                msg = f"Error connecting to {printable_type} proxy {proxy_server}"
                log.debug("%s due to: %s", msg, error)
                raise ProxyConnectionError(msg, error) from error
            else:
                raise error

        else:
            try:
                negotiate = self._proxy_negotiators[proxy_type]
                negotiate(self, dest_addr, dest_port)
            except (socket.error, ProxyError) as error:
                if not catch_errors:
                    self.close()
                    raise GeneralProxyError("Socket error", error) from error
                raise error

    @set_self_blocking
    def connect_ex(self, dest_pair):
        """
        https://docs.python.org/3/library/socket.html#socket.socket.connect_ex
        Like connect(address), but return an error indicator instead of raising an
        exception for errors returned by the C-level connect() call (other problems,
        such as "host not found" can still raise exceptions).
        """

        try:
            self.connect(dest_pair, catch_errors=True)
            return 0
        except OSError as e:
            if e.errno:
                return e.errno
            raise

    def _proxy_addr(self):
        """
        Return proxy address to connect to as tuple object
        """

        proxy_type, proxy_addr, proxy_port = self.proxy[:3]

        proxy_port = proxy_port or DEFAULT_PORTS.get(proxy_type)
        if not proxy_port:
            raise GeneralProxyError("Invalid proxy type")
        return proxy_addr, proxy_port
