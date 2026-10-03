"""Fail-closed cgroup-v2 controls for the full Bubblewrap descendant tree."""
import os
from pathlib import Path
import uuid
import time

class ResourceGuard:
    def __init__(self, limits):
        current = Path('/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().split('0::', 1)[1].strip().lstrip('/')
        candidates = [Path(limits.cgroup_root)] if limits.cgroup_root else [current, *current.parents]
        self.path = None
        for parent in candidates:
            try:
                enabled = set((parent/'cgroup.subtree_control').read_text().split())
                if not {'cpu', 'memory', 'pids'} <= enabled:
                    continue
                path=parent/('drex-fw-'+uuid.uuid4().hex)
                path.mkdir(mode=0o700)
                self.path=path
                (path/'memory.max').write_text(str(limits.memory_mb*1024*1024))
                (path/'memory.swap.max').write_text('0')
                (path/'memory.oom.group').write_text('1')
                (path/'pids.max').write_text(str(limits.pids))
                (path/'cpu.max').write_text(f'{max(1000,int(limits.cpus*100000))} 100000')
                self.fd=os.open(path/'cgroup.procs', os.O_WRONLY | os.O_CLOEXEC)
                return
            except OSError:
                if self.path:
                    self.close()
                self.path=None
        raise RuntimeError('RESOURCE_LIMIT_UNAVAILABLE: delegated cgroup-v2 cpu/memory/pids controllers required')

    def wrap(self, command, limits):
        helper=str(Path(__file__).with_name('resource_launcher.py'))
        return ['/usr/bin/python3', '-I', helper, str(self.fd), str(limits.max_open_files), str(limits.max_file_bytes), *command]

    def kill(self):
        if self.path:
            (self.path/'cgroup.kill').write_text('1')

    def close(self):
        if hasattr(self, 'fd'):
            os.close(self.fd)
            del self.fd
        if self.path:
            try:
                self.kill()
                for _ in range(50):
                    try:
                        self.path.rmdir()
                        break
                    except OSError:
                        time.sleep(.01)
            except OSError:
                pass
