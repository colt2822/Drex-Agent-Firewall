"""Action Envelope schema for Drex Agent Firewall.

Every requested agent action is normalized into this strongly-typed structure
before evaluation and policy checks.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ActionEnvelope(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Identity & Tracing

    action_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    parent_action_id: Optional[str] = None
    agent_id: str = Field(default="agent")
    session_id: str = Field(default="session-default")

    # Action definition
    tool: str = Field(description="Tool being targeted (e.g. shell, filesystem, git, github, http, mcp)")
    operation: str = Field(description="Specific operation (e.g. execute, read, write, commit, push, call)")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Operation arguments (secrets redacted)")

    # Target & Resource Classification
    resource_type: str = Field(
        default="unknown",
        description="Type of resource: file, directory, command, repository, url, mcp_tool, issue, pr, api_endpoint, unknown"
    )
    resource_target: str = Field(
        default="",
        description="Normalized target: resolved path, command, destination URL, or identifier"
    )

    # Inherent property flags (pre-evaluated / inferred)
    read_only: bool = Field(default=False)
    external_effect: bool = Field(default=False)
    destructive: bool = Field(default=False)
    reversible: bool = Field(default=True)
    credential_access: bool = Field(default=False)
    network_access: bool = Field(default=False)
    filesystem_write: bool = Field(default=False)
    process_execution: bool = Field(default=False)
    external_write: bool = Field(default=False)

    # Environment context
    repository: Optional[str] = None
    working_directory: Optional[str] = None
    requested_at: float = Field(default_factory=time.time)

    # Contextual fields
    previous_actions: List[Dict[str, Any]] = Field(default_factory=list)
    current_task: Optional[str] = None
    known_policy: Optional[str] = None
    repository_scope: Optional[str] = None
    allowed_paths: List[str] = Field(default_factory=list)
    blocked_paths: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    blocked_domains: List[str] = Field(default_factory=list)
    git_branch: Optional[str] = None
    git_status: Optional[str] = None
    human_approval_state: Optional[str] = None

    # Extensible metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)

