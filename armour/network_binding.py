"""Read-only HTTP execution binding over a preconnected public socket."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
import http.client
import ipaddress
import math
import socket
import ssl
from threading import Lock
from urllib.parse import urlparse

from .binding import BindingConsumed, BindingError, BindingExpired, BindingRequest
from .verifiers import NetworkVerifier, Resolver, system_resolver


_SAFE_METHODS = frozenset({"GET", "HEAD"})
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _secure_tls_context(context: object) -> bool:
    return (
        isinstance(context, ssl.SSLContext)
        and context.verify_mode == ssl.CERT_REQUIRED
        and context.check_hostname is True
    )


@dataclass(frozen=True, slots=True)
class NetworkResponse:
    """Bound response data returned without exposing the underlying socket."""

    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    destination_ip: str


def _open_pinned_connection(
    *,
    scheme: str,
    hostname: str,
    destination_ip: str,
    port: int,
    timeout: float,
    ssl_context: ssl.SSLContext,
) -> http.client.HTTPConnection:
    """Connect to the selected numeric address without another DNS lookup."""

    if not _secure_tls_context(ssl_context):
        raise BindingError(
            "HTTPS requires certificate verification and hostname checking"
        )

    raw_socket = socket.create_connection((destination_ip, port), timeout=timeout)
    connected_socket: socket.socket | ssl.SSLSocket = raw_socket
    try:
        peer_ip = ipaddress.ip_address(raw_socket.getpeername()[0])
        if peer_ip != ipaddress.ip_address(destination_ip):
            raise BindingError("connected peer does not match verified destination")
        if scheme == "https":
            connected_socket = ssl_context.wrap_socket(
                raw_socket, server_hostname=hostname
            )
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                hostname, port=port, timeout=timeout, context=ssl_context
            )
        else:
            connected_socket = raw_socket
            connection = http.client.HTTPConnection(
                hostname, port=port, timeout=timeout
            )
        connection.sock = connected_socket
        return connection
    except Exception:
        connected_socket.close()
        raise


class BoundNetworkConnection:
    """A one-request HTTP capability fixed to an already-connected public peer."""

    def __init__(
        self,
        connection: http.client.HTTPConnection,
        *,
        method: str,
        request_target: str,
        destination_ip: str,
        deadline_ns: int,
        max_response_bytes: int,
        monotonic_ns: Callable[[], int],
    ):
        self.identity = (method, request_target, destination_ip)
        self.method = method
        self.request_target = request_target
        self.destination_ip = destination_ip
        self.deadline_ns = deadline_ns
        self._connection = connection
        self._max_response_bytes = max_response_bytes
        self._monotonic_ns = monotonic_ns
        self._consumed = False
        self._closed = False
        self._lock = Lock()

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def assert_usable(self) -> None:
        with self._lock:
            if self._closed:
                raise BindingExpired("bound network connection is closed")
            if self._consumed:
                raise BindingConsumed("bound network connection was already used")
            if self._monotonic_ns() >= self.deadline_ns:
                raise BindingExpired("bound network connection deadline expired")

    def request(self) -> NetworkResponse:
        """Issue exactly the verified request once; redirects are not followed."""

        with self._lock:
            if self._closed:
                raise BindingExpired("bound network connection is closed")
            if self._consumed:
                raise BindingConsumed("bound network connection was already used")
            if self._monotonic_ns() >= self.deadline_ns:
                raise BindingExpired("bound network connection deadline expired")
            self._consumed = True
            connection = self._connection
            method = self.method
            target = self.request_target

        try:
            connection.request(method, target)
            response = connection.getresponse()
            body = response.read(self._max_response_bytes + 1)
            if len(body) > self._max_response_bytes:
                raise BindingError("network response exceeds configured byte limit")
            return NetworkResponse(
                status=response.status,
                reason=response.reason or "",
                headers=tuple(response.getheaders()),
                body=body,
                destination_ip=self.destination_ip,
            )
        except BindingError:
            raise
        except Exception as exc:
            raise BindingError(
                f"bound network request failed: {type(exc).__name__}"
            ) from exc

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            connection = self._connection
        connection.close()


class NetworkBinder:
    """Bind an HTTP(S) proposal to one preconnected, verified public address."""

    kind = "network"

    def __init__(
        self,
        *,
        resolver: Resolver = system_resolver,
        timeout: float = 10.0,
        max_response_bytes: int = 8 * 1024 * 1024,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("network timeout must be finite and positive")
        if (
            not isinstance(max_response_bytes, int)
            or isinstance(max_response_bytes, bool)
            or max_response_bytes < 1
        ):
            raise ValueError("max_response_bytes must be a positive integer")
        self._resolver = resolver
        self._timeout = float(timeout)
        self._max_response_bytes = max_response_bytes
        candidate_context = ssl_context or ssl.create_default_context()
        if not _secure_tls_context(candidate_context):
            raise ValueError(
                "HTTPS requires certificate verification and hostname checking"
            )
        self._ssl_context = candidate_context
        self.last_capability: BoundNetworkConnection | None = None

    def _open_connection(
        self,
        *,
        scheme: str,
        hostname: str,
        destination_ip: str,
        port: int,
    ) -> http.client.HTTPConnection:
        """Open the pinned transport; isolated tests may override this seam."""

        return _open_pinned_connection(
            scheme=scheme,
            hostname=hostname,
            destination_ip=destination_ip,
            port=port,
            timeout=self._timeout,
            ssl_context=self._ssl_context,
        )

    def prepare(
        self, request: BindingRequest, *, monotonic_ns: Callable[[], int]
    ) -> BoundNetworkConnection:
        # SSLContext is mutable. Recheck it at use time so a context weakened
        # after construction cannot silently disable HTTPS authentication.
        if not _secure_tls_context(self._ssl_context):
            raise BindingError(
                "HTTPS requires certificate verification and hostname checking"
            )
        proposal = request.proposal
        url = (
            proposal.resource
            if proposal.resource
            and proposal.resource.startswith(("http://", "https://"))
            else proposal.payload.get("url")
        )
        if not isinstance(url, str) or not url or len(url) > 2048:
            raise BindingError("network-bound resource must be a valid URL")
        if any(ord(character) < 32 or ord(character) == 127 for character in url):
            raise BindingError("network URL contains control characters")

        parsed = urlparse(url)
        if parsed.scheme not in _DEFAULT_PORTS or not parsed.hostname:
            raise BindingError("only absolute HTTP(S) URLs can be network-bound")
        if parsed.username or parsed.password or parsed.fragment:
            raise BindingError("URL credentials and fragments cannot be network-bound")
        try:
            explicit_port = parsed.port
        except ValueError as exc:
            raise BindingError("network URL has an invalid port") from exc
        if explicit_port is not None and explicit_port < 1:
            raise BindingError("network URL has an invalid port")
        port = (
            explicit_port
            if explicit_port is not None
            else _DEFAULT_PORTS[parsed.scheme]
        )

        raw_method = proposal.method or proposal.payload.get("method") or "GET"
        if not isinstance(raw_method, str):
            raise BindingError("HTTP method must be a string")
        method = raw_method.upper()
        if (
            method not in _SAFE_METHODS
            or method not in request.policy.allowed_http_methods
        ):
            raise BindingError(f"HTTP method {method!r} cannot be network-bound")

        hostname = parsed.hostname.lower()
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            try:
                resolved: Iterable[str] = self._resolver(hostname)
                addresses = tuple(dict.fromkeys(resolved))
            except Exception as exc:
                raise BindingError(
                    f"DNS resolution failed: {type(exc).__name__}"
                ) from exc
        else:
            addresses = (str(literal),)
        if not addresses:
            raise BindingError("DNS returned no addresses")

        normalized: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for address in addresses:
            try:
                parsed_address = ipaddress.ip_address(address)
            except ValueError as exc:
                raise BindingError("DNS returned an invalid address") from exc
            if not parsed_address.is_global:
                raise BindingError(
                    f"non-public destination rejected: {parsed_address}"
                )
            normalized.append(parsed_address)

        # Reuse the gate's network-policy decision with the exact cached DNS
        # answers. This does not trigger a second, potentially different lookup.
        verified = NetworkVerifier(resolver=lambda _host: addresses).check(
            proposal, request.policy
        )
        if not verified.passed:
            raise BindingError("network policy verification failed")

        selected = min(normalized, key=lambda item: (item.version, int(item)))
        connection: http.client.HTTPConnection | None = None
        try:
            connection = self._open_connection(
                scheme=parsed.scheme,
                hostname=hostname,
                destination_ip=str(selected),
                port=port,
            )
            deadline_ns = monotonic_ns() + int(
                request.dependency_policy.max_age_ms * 1_000_000
            )
            target = parsed.path or "/"
            if parsed.query:
                target = f"{target}?{parsed.query}"
            capability = BoundNetworkConnection(
                connection,
                method=method,
                request_target=target,
                destination_ip=str(selected),
                deadline_ns=deadline_ns,
                max_response_bytes=self._max_response_bytes,
                monotonic_ns=monotonic_ns,
            )
        except Exception:
            if connection is not None:
                connection.close()
            raise
        self.last_capability = capability
        return capability
