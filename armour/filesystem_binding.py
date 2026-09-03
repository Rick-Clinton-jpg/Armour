"""Filesystem implementation of an execution-bound capability."""

from __future__ import annotations

from collections.abc import Callable
import os
from pathlib import Path
import stat
from threading import Lock

from .binding import BindingExpired, BindingRequest
from .safe_filesystem import UnsafePathError, open_beneath


class BoundFile:
    """An already-open regular file whose descriptor identity cannot be redirected."""

    def __init__(
        self,
        descriptor: int,
        *,
        deadline_ns: int,
        monotonic_ns: Callable[[], int],
    ):
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise UnsafePathError("opened object is not a regular file")
        self.identity = (status.st_dev, status.st_ino, stat.S_IFMT(status.st_mode))
        self.deadline_ns = deadline_ns
        self._descriptor = descriptor
        self._monotonic_ns = monotonic_ns
        self._closed = False
        self._lock = Lock()

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def assert_usable(self) -> None:
        with self._lock:
            if self._closed:
                raise BindingExpired("bound file is closed")
            if self._monotonic_ns() >= self.deadline_ns:
                raise BindingExpired("bound file deadline expired")

    def read_text(self, *, encoding: str = "utf-8") -> str:
        with self._lock:
            if self._closed:
                raise BindingExpired("bound file is closed")
            if self._monotonic_ns() >= self.deadline_ns:
                raise BindingExpired("bound file deadline expired")
            os.lseek(self._descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(self._descriptor, 64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks).decode(encoding)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            descriptor = self._descriptor
            self._descriptor = -1
        os.close(descriptor)


class FilesystemBinder:
    """Bind ``proposal.resource`` to a live descriptor beneath a policy root."""

    kind = "filesystem"

    def __init__(self) -> None:
        self.last_capability: BoundFile | None = None

    def prepare(
        self, request: BindingRequest, *, monotonic_ns: Callable[[], int]
    ) -> BoundFile:
        resource = request.proposal.resource
        if not isinstance(resource, str) or not resource or not os.path.isabs(resource):
            raise UnsafePathError("filesystem-bound resource must be an absolute path")

        candidate = Path(resource).expanduser()
        relative: Path | None = None
        selected_root: Path | None = None
        for root in sorted(request.policy.allowed_roots, key=lambda path: len(path.parts), reverse=True):
            # Compare the identity of candidate ancestors with the canonical
            # host-owned root. This permits OS aliases such as /var ->
            # /private/var without resolving any proposal-controlled child.
            for ancestor in candidate.parents:
                try:
                    same_root = os.path.samefile(ancestor, root)
                except OSError:
                    continue
                if same_root:
                    relative = candidate.relative_to(ancestor)
                    selected_root = root
                    break
            if selected_root is not None:
                break
        if selected_root is None or relative is None:
            raise UnsafePathError("resource is outside policy roots")

        descriptor = open_beneath(
            selected_root, relative, flags=os.O_RDONLY | os.O_NONBLOCK
        )
        try:
            deadline_ns = monotonic_ns() + int(
                request.dependency_policy.max_age_ms * 1_000_000
            )
            capability = BoundFile(
                descriptor, deadline_ns=deadline_ns, monotonic_ns=monotonic_ns
            )
        except Exception:
            os.close(descriptor)
            raise
        self.last_capability = capability
        return capability
