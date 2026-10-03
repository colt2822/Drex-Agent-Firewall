"""Trusted bootstrap: enter the cgroup before executing any guest code."""
import os
import resource
import sys

try:
    fd, nofile, fsize = map(int, sys.argv[1:4])
    os.write(fd, str(os.getpid()).encode('ascii'))
    os.close(fd)
    resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
    resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.execv(sys.argv[4], sys.argv[4:])
except Exception as exc:
    print('RESOURCE_BOOTSTRAP_FAILURE: '+type(exc).__name__, file=sys.stderr)
    sys.exit(125)
