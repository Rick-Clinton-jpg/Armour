"""Capability-style filesystem helpers for high-assurance handlers.

Path verification followed by a later path-based open is vulnerable to local
symlink races. These helpers walk from an already-open trusted directory and
refuse symlinks at every component, so the returned descriptor identifies the
same object the helper checked.
"""

from __future__ import annotations

import os
from pathlib import Path
import stat


class UnsafePathError(ValueError):
    """Raised when a path cannot be opened beneath the trusted root safely."""


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if not isinstance(value, int):
        raise NotImplementedError(
            f"this platform does not provide the required {name} filesystem flag"
        )
    return value


def open_beneath(
    root: str | Path,
    relative_path: str | Path,
    *,
    flags: int = os.O_RDONLY,
    mode: int = 0o600,
) -> int:
    """Open ``relative_path`` beneath ``root`` without following symlinks.

    The caller owns the returned file descriptor and must close it. ``root``
    must be an absolute, real directory path and ``relative_path`` must contain
    ordinary child components only. Platforms without directory-relative
    ``os.open`` and no-follow support fail closed with ``NotImplementedError``.

    This protects the open itself from path-component replacement. The trusted
    handler remains responsible for choosing suitable flags, validating the
    opened file type when relevant, and using the returned descriptor instead
    of reopening the original path.
    """

    root_text = os.fspath(root)
    relative_text = os.fspath(relative_path)
    if not isinstance(root_text, str) or not isinstance(relative_text, str):
        raise TypeError("root and relative_path must be text paths")
    if not os.path.isabs(root_text):
        raise UnsafePathError("trusted root must be absolute")
    if os.path.isabs(relative_text):
        raise UnsafePathError("path beneath root must be relative")

    components = relative_text.split("/")
    if not components or any(component in {"", ".", ".."} for component in components):
        raise UnsafePathError("relative path contains an empty, dot, or traversal component")
    if any("\x00" in component or "\\" in component for component in components):
        raise UnsafePathError("relative path contains a forbidden separator or NUL byte")
    if os.open not in os.supports_dir_fd:
        raise NotImplementedError("this platform does not support directory-relative os.open")

    nofollow = _required_flag("O_NOFOLLOW")
    directory = _required_flag("O_DIRECTORY")
    cloexec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | directory | nofollow | cloexec

    # Canonicalize the host-owned root once (macOS commonly exposes /var and
    # /tmp through system symlinks), then walk that concrete target without
    # following any further path components supplied by the proposal.
    root_text = os.path.realpath(root_text)
    root_components = Path(root_text).parts
    if any(component in {".", ".."} for component in root_components[1:]):
        raise UnsafePathError("trusted root contains a dot or traversal component")

    current_fd: int | None = None
    try:
        # Walk the configured root from the filesystem root as well. O_NOFOLLOW
        # on one absolute-path open would protect only its final component.
        current_fd = os.open(os.path.sep, directory_flags)
        for component in root_components[1:]:
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        for component in components[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return os.open(
            components[-1],
            flags | nofollow | cloexec,
            mode,
            dir_fd=current_fd,
        )
    except (OSError, ValueError) as exc:
        raise UnsafePathError("path could not be opened safely beneath the trusted root") from exc
    finally:
        if current_fd is not None:
            os.close(current_fd)


def read_text_beneath(
    root: str | Path,
    relative_path: str | Path,
    *,
    encoding: str = "utf-8",
) -> str:
    """Read a regular file through ``open_beneath`` without reopening its path."""

    descriptor = open_beneath(root, relative_path, flags=os.O_RDONLY | os.O_NONBLOCK)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise UnsafePathError("opened object is not a regular file")
        with os.fdopen(descriptor, "r", encoding=encoding) as handle:
            descriptor = -1  # ownership transferred to the file object
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
