"""Synthetic TOCTOU and hardlink reproductions against real adapter effects."""
import os
import pytest
from drex_agent_firewall.adapters.filesystem_adapter import FilesystemAdapter
from drex_agent_firewall.constraints.enforcer import ConstraintEnforcer
from drex_agent_firewall.policy.engine import DeterministicPolicyEngine
from drex_agent_firewall.schemas.config import FirewallConfig

@pytest.mark.parametrize('operation', ['read', 'modify', 'create', 'mkdir', 'delete', 'list_dir'])
def test_parent_symlink_swap_cannot_reach_outside(tmp_path, monkeypatch, operation):
    ws=tmp_path/'ws'; ws.mkdir(); parent=ws/'parent'; parent.mkdir()
    outside=tmp_path/'outside'; outside.mkdir(); canary=outside/'canary'; canary.write_text('SYNTHETIC_CANARY')
    cfg=FirewallConfig(); cfg.filesystem.allowed_roots=[str(ws)]
    adapter=FilesystemAdapter(DeterministicPolicyEngine(config=cfg))
    original=ConstraintEnforcer.verify_path
    def swap(*args, **kwargs):
        result=original(*args, **kwargs)
        parent.rmdir(); parent.symlink_to(outside, target_is_directory=True)
        return result
    monkeypatch.setattr(ConstraintEnforcer, 'verify_path', swap)
    target=str(parent/'canary')
    if operation in ['modify','create']:
        result=getattr(adapter, operation+'_file')(target, 'SYNTHETIC_ATTACK')
    elif operation=='mkdir':
        result=adapter.make_directory(str(parent/'new'))
    elif operation=='list_dir':
        result=adapter.list_dir(str(parent))
    else:
        result=getattr(adapter, operation+'_file')(target)
    assert not result.allowed
    assert canary.read_text()=='SYNTHETIC_CANARY'
    assert not (outside/'new').exists()
    assert result.content is None

@pytest.mark.parametrize('operation', ['read', 'modify'])
def test_preexisting_hardlink_cannot_alias_outside_file(tmp_path, operation):
    ws=tmp_path/'ws'; ws.mkdir(); outside=tmp_path/'canary'; outside.write_text('SYNTHETIC_CANARY')
    os.link(outside, ws/'alias')
    cfg=FirewallConfig(); cfg.filesystem.allowed_roots=[str(ws)]
    adapter=FilesystemAdapter(DeterministicPolicyEngine(config=cfg))
    result=adapter.read_file(str(ws/'alias')) if operation=='read' else adapter.modify_file(str(ws/'alias'), 'ATTACK')
    assert not result.allowed
    assert result.content is None
    assert outside.read_text()=='SYNTHETIC_CANARY'
