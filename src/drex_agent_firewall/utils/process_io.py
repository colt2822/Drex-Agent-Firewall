"""Bounded output collection for child processes with piped output."""

from __future__ import annotations

from dataclasses import dataclass
import subprocess
import threading
import os
import signal
from typing import Optional


@dataclass
class BoundedProcessOutput:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    limit_exceeded: bool


def bounded_communicate(
    process: subprocess.Popen,
    *,
    input: Optional[str] = None,
    timeout: Optional[float] = None,
    max_output_bytes: int = 1024 * 1024,
    encoding: str = "utf-8",
) -> BoundedProcessOutput:
    """Drain both pipes while retaining no more than the configured bytes each.

    Reader threads continue draining after each buffer reaches its limit so a
    verbose child cannot block on a full pipe. Only retained bytes occupy
    memory; excess output is discarded as it arrives.
    """
    limit = max(0, int(max_output_bytes))
    output = {"stdout": bytearray(), "stderr": bytearray()}
    truncated = {"stdout": False, "stderr": False}

    def drain(name: str, stream) -> None:
        if stream is None:
            return
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            if isinstance(chunk, str):
                chunk = chunk.encode(encoding, errors="replace")
            remaining = limit - len(output[name])
            if remaining > 0:
                output[name].extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated[name] = True

    readers = [
        threading.Thread(target=drain, args=(name, getattr(process, name)), daemon=True)
        for name in ("stdout", "stderr")
        if getattr(process, name, None) is not None
    ]
    for reader in readers:
        reader.start()

    def send_input() -> None:
        stream = getattr(process, "stdin", None)
        if stream is None:
            return
        try:
            if input is not None:
                payload = input.encode(encoding)
                for offset in range(0, len(payload), 64 * 1024):
                    stream.write(payload[offset:offset + 64 * 1024])
                stream.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    writer = threading.Thread(target=send_input, daemon=True)
    writer.start()

    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            process.kill()
        process.wait()

    writer.join(timeout=1.0)
    for reader in readers:
        reader.join(timeout=0.25 if timed_out else 1.0)
    # Do not close a BufferedReader while another thread is blocked in read();
    # inherited pipe writers can otherwise hold its internal lock indefinitely.
    for name in ("stdout", "stderr"):
        stream = getattr(process, name, None)
        if stream is not None and all(not r.is_alive() for r in readers):
            try:
                stream.close()
            except OSError:
                pass

    rendered = {}
    for name in ("stdout", "stderr"):
        text = output[name].decode(encoding, errors="replace")
        if truncated[name]:
            text += f"\n... [TRUNCATED at {limit} bytes]"
        rendered[name] = text

    return BoundedProcessOutput(
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=rendered["stdout"],
        stderr=rendered["stderr"],
        timed_out=timed_out,
        limit_exceeded=any(truncated.values()),
    )
