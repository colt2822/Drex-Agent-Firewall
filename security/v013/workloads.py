"""Representative offline coding workloads under explicit read-only tool grants."""
import importlib.util
import json
from pathlib import Path
import tempfile
from drex_agent_firewall.sandbox.manager import SandboxManager
from drex_agent_firewall.schemas.config import FirewallConfig, SandboxMount

with tempfile.TemporaryDirectory() as td:
    root=Path(td); ws=root/'ws'; ws.mkdir(); private=root/'private'; private.mkdir(mode=0o700)
    (ws/'app.py').write_text('def add(a,b): return a+b\n')
    (ws/'test_app.py').write_text('from app import add\ndef test_add(): assert add(2,3)==5\n')
    (ws/'package.json').write_text(json.dumps({'name':'canary','version':'1.0.0','scripts':{'test':'node test.js'}}))
    (ws/'test.js').write_text('const assert=require("assert"); const {add}=require("./app.js"); assert.equal(add(2,3),5);')
    (ws/'main.c').write_text('int main(void){return 0;}\n')
    cfg=FirewallConfig()
    for name in ['pytest','_pytest','pluggy','packaging','iniconfig','pygments','py']:
        spec=importlib.util.find_spec(name); source=Path(spec.origin)
        if spec.submodule_search_locations: source=source.parent
        cfg.sandbox.extra_mounts.append(SandboxMount(host_path=str(source),container_path='/opt/drex-python/'+source.name,mode='ro'))
    manager=SandboxManager('bubblewrap',str(private/'history.db'))
    sid=manager.create_session(str(ws),agent_type='generic',network_mode='none',config=cfg).session_id
    results={}
    tasks={
        'python':['sh','-c','python3 -c "from pathlib import Path; Path(\'app.py\').write_text(\'def add(a,b): return a+b\\n\')" && python3 -m pytest -q -p no:cacheprovider'],
        'node':['sh','-c','printf "exports.add=(a,b)=>a+b;\\n" > app.js && npm test && npm install --offline --ignore-scripts --package-lock=false'],
        'git':['sh','-c','git init -q && git status --porcelain && git add app.py app.js && git -c user.name=Canary -c user.email=canary@example.invalid commit -qm canary && git diff --exit-code'],
        'compiler':['sh','-c','gcc main.c -o /workspace/canary && /workspace/canary'],
    }
    try:
        for name,command in tasks.items():
            result=manager.exec_command(sid,command,timeout=30)
            results[name]={'status':'PASS' if result.returncode==0 else 'FAIL','returncode':result.returncode,'stderr':result.stderr[-300:] if result.returncode else ''}
        results['rust']={'status':'UNAVAILABLE','reason':'No configured host Rust toolchain'}
        print(json.dumps(results,indent=2))
        assert all(value['status']=='PASS' for name,value in results.items() if name!='rust')
    finally: manager.destroy_session(sid); manager.repository.conn.close()
