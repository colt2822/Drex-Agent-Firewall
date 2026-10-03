"""Descriptor-relative filesystem access; no path reopen after validation.

All intermediate components and final files reject symlinks. Regular files with
multiple hardlinks are rejected because a writable alias can be outside policy.
Linux/POSIX only: callers must fail closed if dir_fd support is unavailable.
"""
from contextlib import contextmanager
import hashlib
import os
import stat


@contextmanager
def parent_fd(path, roots, create=False):
    path = os.path.abspath(path)
    candidates = [os.path.realpath(os.path.abspath(os.path.expanduser(r))) for r in roots]
    candidates = [r for r in candidates if os.path.commonpath([path, r]) == r]
    if not candidates:
        raise PermissionError("PATH_OUTSIDE_POLICY")
    root = max(candidates, key=len)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        # Walk from / rather than opening an absolute pathname with symlink parents.
        parts = [p for p in root.split('/') if p]
        relative = os.path.relpath(path, root)
        if relative == '.':
            # Root itself: return its parent and basename, without granting ../.
            parts = parts[:-1]
            leaf = os.path.basename(root) or '.'
        else:
            components = relative.split('/')
            parts += components[:-1]
            leaf = components[-1]
        for component in parts:
            try:
                next_fd = os.open(component, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, mode=0o700, dir_fd=fd)
                next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd, leaf
    finally:
        os.close(fd)


def regular_fd(parent, name, write=False):
    flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= os.O_RDWR | os.O_CREAT if write else os.O_RDONLY
    fd = os.open(name, flags, 0o600, dir_fd=parent)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise PermissionError('UNSAFE_FILE_TYPE_OR_HARDLINK')
    return fd


def digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    result = hashlib.sha256()
    while data := os.read(fd, 65536):
        result.update(data)
    os.lseek(fd, 0, os.SEEK_SET)
    return result.hexdigest()


def validate_workspace_tree(fd):
    """Refuse preexisting host socket/device capabilities and hardlink aliases.

    The trusted launcher must own staging until the bind completes. Symlinks are
    permitted as data: namespace resolution cannot reach an unmounted host tree.
    This reads inode metadata only, never file contents.
    """
    for entry in os.scandir(fd):
        info = entry.stat(follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                validate_workspace_tree(child)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise PermissionError('WORKSPACE_HARDLINK_ALIAS')
        elif not stat.S_ISLNK(info.st_mode):
            raise PermissionError('WORKSPACE_HOST_IPC_OR_DEVICE')
