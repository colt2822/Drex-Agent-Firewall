"""Dependency, mount, policy, bootstrap and audit failures never run host payloads."""
import json
import os
import pytest
from drex_agent_firewall.sandbox.backend import SandboxSpec
from drex_agent_firewall.sandbox.bubblewrap import BubblewrapBackend
from drex_agent_firewall.sandbox.manager import SandboxManager
from drex_agent_firewall.schemas.config import FirewallConfig, SandboxLimits, SandboxMount

@pytest.mark.parametrize('failure',['missing','not-executable','namespace','mount','network','bootstrap','cwd'])
def test_broken_runtime_cannot_run_unsandboxed(tmp_path, failure):
    ws=tmp_path/'ws'; ws.mkdir(); marker=tmp_path/'UNSANDBOXED'
    runtime='/usr/bin/bwrap'
    if failure in ['missing','not-executable','namespace','mount','network']:
        fake=tmp_path/'bwrap'
        if failure!='missing':
            fake.write_text('#!/bin/sh\necho NAMESPACE_FAILURE >&2\nexit 125\n')
            fake.chmod(0o600 if failure=='not-executable' else 0o700)
        runtime=str(fake)
    backend=BubblewrapBackend(runtime); spec=SandboxSpec(session_id='fail-'+failure,workspace_path=str(ws))
    backend.prepare(spec)
    try:
        command=['sh','-c',f'touch {marker}']
        if failure=='bootstrap': command=['/missing/child-bootstrap']
        result=backend.exec(spec.session_id,command,cwd='/missing/cwd' if failure=='cwd' else None)
        assert result.returncode!=0
        assert not marker.exists()
        assert result.stderr
    finally: backend.destroy(spec.session_id)

def test_missing_required_mount_refuses_execution(tmp_path):
    ws=tmp_path/'ws'; ws.mkdir()
    backend=BubblewrapBackend(); spec=SandboxSpec(session_id='mount-missing',workspace_path=str(ws),extra_mounts=[SandboxMount(host_path=str(tmp_path/'absent'),container_path='/opt/required')])
    backend.prepare(spec)
    try:
        with pytest.raises(RuntimeError,match='MOUNT_SETUP_FAILURE'): backend.exec(spec.session_id,['touch','/workspace/not-run'])
        assert not (ws/'not-run').exists()
    finally: backend.destroy(spec.session_id)

def test_cgroup_unavailable_refuses_prepare(tmp_path):
    ws=tmp_path/'ws'; ws.mkdir()
    spec=SandboxSpec(session_id='resource-unavailable',workspace_path=str(ws),limits=SandboxLimits(cgroup_root=str(tmp_path/'missing-controller')))
    with pytest.raises(RuntimeError,match='RESOURCE_LIMIT_UNAVAILABLE'): BubblewrapBackend().prepare(spec)

@pytest.mark.parametrize('failure',['unknown-policy','logging-init','logging-write','missing-policy','malformed-policy'])
def test_manager_dependencies_fail_before_native_effect(tmp_path, monkeypatch, failure):
    ws=tmp_path/'ws'; ws.mkdir(); private=tmp_path/'private'; private.mkdir(mode=0o700)
    manager=SandboxManager('bubblewrap',str(private/'history.db'))
    sid=None
    try:
        if failure=='unknown-policy':
            with pytest.raises((KeyError,ValueError)): manager.create_session(str(ws),policy_pack='missing')
            return
        if failure=='logging-init':
            def fail(*a,**k): raise OSError('SYNTHETIC_LOG_INIT_FAILURE')
            monkeypatch.setattr('drex_agent_firewall.sandbox.manager.AuditBroker',fail)
            with pytest.raises(OSError): manager.create_session(str(ws))
            return
        sid=manager.create_session(str(ws),agent_type='generic',network_mode='none').session_id
        if failure=='logging-write':
            def fail(*a,**k): raise OSError('SYNTHETIC_LOG_WRITE_FAILURE')
            monkeypatch.setattr(manager.repository,'update_sandbox_session',fail)
        else:
            path=manager._mcp_config_paths[sid]
            if failure=='missing-policy': os.unlink(path)
            else: open(path,'w').write('{malformed')
        with pytest.raises((RuntimeError,OSError)): manager.exec_command(sid,['touch','/workspace/not-run'])
        assert not (ws/'not-run').exists()
    finally:
        if sid:
            monkeypatch.undo(); manager.destroy_session(sid)
        manager.repository.conn.close()

def test_effective_policy_is_pinned_and_custom_limits_reach_guest(tmp_path):
    ws=tmp_path/'ws'; ws.mkdir(); private=tmp_path/'private'; private.mkdir(mode=0o700)
    manager=SandboxManager('bubblewrap',str(private/'history.db'))
    cfg=FirewallConfig(); cfg.filesystem.max_bytes_written=7
    info=manager.create_session(str(ws),config=cfg,agent_type='generic',network_mode='none')
    try:
        data=json.load(open(manager._mcp_config_paths[info.session_id]))
        assert data['drexPolicy']['config']['filesystem']['max_bytes_written']==7
        assert data['drexPolicy']['digest']==info.metadata['policy_digest']
        args=data['mcpServers']['drex_firewall']['args']
        assert '--policy-file' in args and '--policy-digest' in args
        result=manager.exec_command(info.session_id,['python3','-c','import json; p=json.load(open("/tmp/.drex_mcp_config.json")); assert p["drexPolicy"]["config"]["filesystem"]["max_bytes_written"]==7'])
        assert result.returncode==0,result.stderr
    finally: manager.destroy_session(info.session_id); manager.repository.conn.close()

def test_valid_stale_policy_substitution_and_logging_storage_failure_block_execution(tmp_path):
    ws=tmp_path/'ws'; ws.mkdir(); private=tmp_path/'private'; private.mkdir(mode=0o700)
    manager=SandboxManager('bubblewrap',str(private/'history.db'))
    sid=manager.create_session(str(ws),agent_type='generic',network_mode='none').session_id
    path=manager._mcp_config_paths[sid]
    try:
        original=open(path).read(); data=json.loads(original)
        data['drexPolicy']['config']['filesystem']['max_bytes_written']=999
        import hashlib
        data['drexPolicy']['digest']=hashlib.sha256(json.dumps(data['drexPolicy']['config'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        open(path,'w').write(json.dumps(data))
        with pytest.raises(RuntimeError,match='POLICY_INVALID'): manager.exec_command(sid,['touch','/workspace/not-run'])
        open(path,'w').write(original)
        manager.repository.conn.execute('PRAGMA query_only=ON')
        with pytest.raises(Exception): manager.exec_command(sid,['touch','/workspace/not-run'])
        assert not (ws/'not-run').exists()
    finally:
        manager.repository.conn.execute('PRAGMA query_only=OFF')
        manager.destroy_session(sid); manager.repository.conn.close()

def test_read_only_policy_cannot_be_overridden_by_launcher_defaults(tmp_path):
    ws=tmp_path/'ws'; ws.mkdir(); private=tmp_path/'private'; private.mkdir(mode=0o700)
    manager=SandboxManager('bubblewrap',str(private/'history.db'))
    sid=manager.create_session(str(ws),policy_pack='read-only-research',agent_type='generic',network_mode='none').session_id
    try:
        result=manager.exec_command(sid,['touch','/workspace/not-run']); assert result.returncode!=0
        with pytest.raises(ValueError,match='read-only'): manager.create_session(str(ws),policy_pack='read-only-research',workspace_mode='rw')
        assert not (ws/'not-run').exists()
    finally: manager.destroy_session(sid); manager.repository.conn.close()

@pytest.mark.parametrize('kind',['firewall-code','system-tools','readonly-alias'])
def test_writable_alias_cannot_modify_readonly_security_boundary(tmp_path,kind):
    ws=tmp_path/'ws'; ws.mkdir(); mounts=[]
    if kind=='firewall-code':
        import drex_agent_firewall
        workspace=str(__import__('pathlib').Path(drex_agent_firewall.__file__).parent)
    elif kind=='system-tools': workspace='/usr'
    else:
        workspace=str(ws); mounts=[SandboxMount(host_path=str(ws),container_path='/opt/readonly-alias',mode='ro')]
    spec=SandboxSpec(session_id='self-tamper-alias',workspace_path=workspace,extra_mounts=mounts)
    with pytest.raises(ValueError,match='SELF_TAMPER_MOUNT_OVERLAP'): BubblewrapBackend().prepare(spec)
