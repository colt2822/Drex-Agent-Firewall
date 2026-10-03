"""Mandatory live Docker job. No availability skip and no host network opt-out.

Reuses actual native attack payloads against the OCI outer boundary. Nested
Bubblewrap is unsupported without delegated controllers and kernel permissions;
no privileged/seccomp-unconfined flag is used to bypass that constraint.
"""
import importlib.util
import os
from pathlib import Path
import pytest
from drex_agent_firewall.sandbox.manager import SandboxManager
from drex_agent_firewall.sandbox.container import DockerBackend
from drex_agent_firewall.sandbox.backend import SandboxSpec

path=Path(__file__).parents[2]/'tests/test_v013_boundary.py'
spec=importlib.util.spec_from_file_location('host_boundary',path)
host=importlib.util.module_from_spec(spec); spec.loader.exec_module(host)
for name in [
    'test_host_secret_classes_inaccessible','test_obfuscated_native_reads_and_writes_still_blocked',
    'test_filtered_env_survives_subprocess_retry_and_proc','test_network_namespace_blocks_controlled_listener_and_destinations',
    'test_unix_sockets_host_proc_and_devices_absent','test_inherited_host_fd_is_closed',
    'test_descendants_remain_confined_and_die_on_parent_exit','test_self_tamper_and_prompt_injection_capabilities_blocked',
]:
    globals()[name]=getattr(host,name)

@pytest.fixture
def boundary(tmp_path, monkeypatch):
    home=tmp_path/'home'; home.mkdir(); monkeypatch.setenv('HOME',str(home))
    ws=tmp_path/'workspace'; ws.mkdir(); private=tmp_path/'private'; private.mkdir(mode=0o700)
    for name in ['.ssh/id_rsa','.config/canary','.aws/credentials','.kube/config','.git-credentials']:
        p=home/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_text('SYNTHETIC_CANARY')
    protected=private/'protected'; protected.write_text('SYNTHETIC_UNCHANGED')
    for name in ['TEST_SECRET_TOKEN','TEST_GITHUB_TOKEN','TEST_AWS_SECRET','TEST_COOKIE']:
        monkeypatch.setenv(name,'SYNTHETIC_ENV_CANARY')
    manager=SandboxManager('docker',str(private/'history.db'))
    sid=manager.create_session(str(ws),agent_type='generic',network_mode='none').session_id
    try: yield manager,sid,ws,home,protected
    finally: manager.destroy_session(sid); manager.repository.conn.close()

def test_installed_package_mcp_and_outer_cgroup_limits(boundary):
    manager,sid,*_=boundary
    result=manager.exec_command(sid,['python3','-c','import drex_agent_firewall,resource; assert drex_agent_firewall.__version__=="0.1.3rc1"; assert resource.getrlimit(resource.RLIMIT_NOFILE)==(256,256); print("INSTALLED_WHEEL_OK")'])
    assert result.returncode==0,result.stderr
    mcp='import json,subprocess; c=json.load(open("/tmp/.drex_mcp_config.json"))["mcpServers"]["drex_firewall"]; p=subprocess.run([c["command"],*c["args"]],input=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/list"})+"\\n",text=True,capture_output=True); assert p.returncode==0,p.stderr; assert "write_file" in p.stdout'
    result=manager.exec_command(sid,['python3','-c',mcp]); assert result.returncode==0,result.stderr

def test_nested_bubblewrap_fails_closed_instead_of_downgrading(boundary):
    manager,sid,*_=boundary
    code='from drex_agent_firewall.sandbox.manager import SandboxManager;\ntry: m=SandboxManager("bubblewrap"); m.create_session("/workspace",agent_type="generic",network_mode="none")\nexcept Exception: print("NESTED_UNAVAILABLE_FAIL_CLOSED")\nelse: raise AssertionError("unexpected nested availability")'
    result=manager.exec_command(sid,['python3','-c',code]); assert result.returncode==0,result.stderr
    assert 'NESTED_UNAVAILABLE_FAIL_CLOSED' in result.stdout

def test_oci_timeout_kills_descendants_and_rejects_reuse(boundary):
    manager,sid,ws,*_=boundary
    result=manager.exec_command(sid,['sh','-c','sleep 2; touch /workspace/survivor'],timeout=.3)
    assert result.timed_out
    import time
    time.sleep(2.2)
    assert not (ws/'survivor').exists()
    with pytest.raises(RuntimeError,match='SESSION_NOT_RUNNING'): manager.exec_command(sid,['touch','/workspace/not-run'])
