"""Pin tests to this checkout and fail if an editable install shadows it."""
from pathlib import Path
import os
import subprocess
import sys
from importlib.machinery import PathFinder
from importlib.util import module_from_spec

EXPECTED_REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_HEAD = subprocess.check_output(
    ["git", "-C", str(EXPECTED_REPO_ROOT), "rev-parse", "HEAD"], text=True
).strip()
os.environ["DREX_EXPECTED_REPO_ROOT"] = str(EXPECTED_REPO_ROOT)
os.environ["DREX_EXPECTED_HEAD"] = EXPECTED_HEAD
EXPECTED_SOURCE_ROOT = EXPECTED_REPO_ROOT / "src"

# Editable-install meta finders may point at another checkout even when src is
# first on sys.path. Remove any preloaded package and load this package through
# PathFinder with an explicit source search path.
for module_name in tuple(sys.modules):
    if module_name == "drex_agent_firewall" or module_name.startswith("drex_agent_firewall."):
        del sys.modules[module_name]
spec = PathFinder.find_spec("drex_agent_firewall", [str(EXPECTED_SOURCE_ROOT)])
if spec is None or spec.loader is None:
    raise RuntimeError(f"Cannot load Drex source from {EXPECTED_SOURCE_ROOT} (HEAD {EXPECTED_HEAD})")
drex_module = module_from_spec(spec)
sys.modules["drex_agent_firewall"] = drex_module
spec.loader.exec_module(drex_module)

import drex_agent_firewall  # noqa: E402
import pytest  # noqa: E402
from drex_agent_firewall import DrexFirewall  # noqa: E402
from drex_agent_firewall.schemas.config import FirewallConfig  # noqa: E402

IMPORTED_DREX_MODULE_PATH = Path(drex_agent_firewall.__file__).resolve()
EXPECTED_MODULE_PATH = (EXPECTED_REPO_ROOT / "src/drex_agent_firewall/__init__.py").resolve()
if IMPORTED_DREX_MODULE_PATH != EXPECTED_MODULE_PATH:
    raise RuntimeError(
        f"Drex test source mismatch: expected {EXPECTED_MODULE_PATH}, "
        f"imported {IMPORTED_DREX_MODULE_PATH} (HEAD {EXPECTED_HEAD})"
    )


@pytest.fixture
def temp_workspace(tmp_path):
    """Provides a temporary, hermetic directory for filesystem and shell tests."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "README.md").write_text("# Test Workspace\n")
    src = ws / "src"
    src.mkdir()
    (src / "app.py").write_text("print('hello world')\n")
    return ws


@pytest.fixture
def hermetic_config(temp_workspace, tmp_path):
    cfg = FirewallConfig.load_default()
    cfg.provider.type = "replay"
    cfg.filesystem.allowed_roots = [str(temp_workspace)]
    cfg.filesystem.blocked_paths = [str(temp_workspace / "forbidden")]
    cfg.database_path = str(tmp_path / "test_firewall.db")
    return cfg


@pytest.fixture
def hermetic_firewall(hermetic_config):
    return DrexFirewall(config=hermetic_config)
