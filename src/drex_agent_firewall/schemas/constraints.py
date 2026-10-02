"""Machine-enforceable constraint schemas for Drex Agent Firewall."""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class Constraints(BaseModel):
    """Machine-enforceable execution constraints returned with ALLOW_WITH_CONSTRAINTS."""

    allowed_paths: List[str] = Field(default_factory=list, description="Permitted canonical directory paths")
    denied_paths: List[str] = Field(default_factory=list, description="Explicitly forbidden canonical paths")
    allowed_commands: List[str] = Field(default_factory=list, description="Explicitly allowed commands or prefixes")
    command_prefix: Optional[str] = Field(default=None, description="Enforced command prefix")
    max_runtime_seconds: Optional[float] = Field(default=30.0, description="Max process runtime before SIGKILL")
    max_output_bytes: Optional[int] = Field(default=1024 * 1024, description="Max capture stdout/stderr bytes")
    allowed_domains: List[str] = Field(default_factory=list, description="Permitted network hostnames/IPs")
    denied_domains: List[str] = Field(default_factory=list, description="Explicitly denied network hostnames/IPs")
    read_only: bool = Field(default=False, description="Mutations forbidden during execution")
    no_external_write: bool = Field(default=False, description="Disallow remote mutations")
    no_secret_access: bool = Field(default=True, description="Mask or block reading secret files/env")
    branch_only: bool = Field(default=False, description="Git operations allowed only on non-main branches")
    no_force_push: bool = Field(default=True, description="Strictly forbid git push --force or +ref")
    max_files_changed: Optional[int] = Field(default=50, description="Max number of files modified")
    max_bytes_written: Optional[int] = Field(default=10 * 1024 * 1024, description="Max bytes written to disk")
