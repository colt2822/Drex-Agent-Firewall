"""Fresh public Git checkout, uncached dependency install, credential-free canary.

Invoke with --revision <public commit>. A branch is allowed for development but
release evidence must record the immutable revision returned by git.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

CANARY = r'''
import json, socket, tempfile
from pathlib import Path
from drex_agent_firewall.sandbox.manager import SandboxManager
with tempfile.TemporaryDirectory() as td:
    root=Path(td); ws=root/'workspace'; ws.mkdir(); private=root/'private'; private.mkdir(mode=0o700)
    canary=private/'synthetic-secret'; canary.write_text('SYNTHETIC_SECRET')
    manager=SandboxManager('bubblewrap',str(private/'history.db'))
    sid=manager.create_session(str(ws),agent_type='generic',network_mode='none').session_id
    try:
        safe=manager.exec_command(sid,['python3','-c','from pathlib import Path; Path("app.py").write_text("def add(a,b): return a+b"+chr(10)); import app; assert app.add(2,3)==5'])
        assert safe.returncode==0,safe.stderr
        for command in [['cat',str(canary)],['sh','-c','echo attack > /etc/firewall-canary']]:
            result=manager.exec_command(sid,command); assert result.returncode!=0; assert 'SYNTHETIC_SECRET' not in result.stdout
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0)); listener.listen(); port=listener.getsockname()[1]
            result=manager.exec_command(sid,['python3','-c',f'import socket; socket.create_connection(("127.0.0.1",{port}),timeout=.2)'])
            assert result.returncode!=0
        result=manager.exec_command(sid,['python3','-c','import drex_agent_firewall; print(drex_agent_firewall.__version__)'])
        assert result.returncode==0,result.stderr
        # Exercise the installed MCP package, not a mounted editable checkout.
        code='import json,subprocess; c=json.load(open("/tmp/.drex_mcp_config.json"))["mcpServers"]["drex_firewall"]; p=subprocess.run([c["command"],*c["args"]],input=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/list"})+chr(10),text=True,capture_output=True); assert p.returncode==0,p.stderr; assert "write_file" in p.stdout'
        result=manager.exec_command(sid,['python3','-c',code]); assert result.returncode==0,result.stderr
        print(json.dumps({'safe_coding':'PASS','denied_secret':'PASS','denied_path':'PASS','denied_network':'PASS','installed_mcp':'PASS'}))
    finally: manager.destroy_session(sid); manager.repository.conn.close()
'''

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--revision',required=True); args=parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='drex-clean-public-') as td:
        root=Path(td); home=root/'home'; home.mkdir(); checkout=root/'source'; venv=root/'venv'
        # No inherited tokens, proxies, HOME configs, editable install or pip cache.
        env={'PATH':'/usr/bin:/bin','HOME':str(home),'XDG_CONFIG_HOME':str(home/'config'),'LANG':'C.UTF-8','DREX_API_KEY':'','PYTHONNOUSERSITE':'1','PIP_NO_CACHE_DIR':'1','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null'}
        subprocess.run(['git','clone','--no-checkout','https://github.com/colt2822/Drex-Agent-Firewall.git',str(checkout)],env=env,check=True,capture_output=True)
        subprocess.run(['git','checkout','--detach',args.revision],cwd=checkout,env=env,check=True,capture_output=True)
        head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=checkout,env=env,text=True).strip()
        subprocess.run(['/usr/bin/python3','-m','venv',str(venv)],env=env,check=True)
        subprocess.run([str(venv/'bin/pip'),'install','--no-cache-dir','-r',str(checkout/'requirements.lock')],cwd=root,env=env,check=True,capture_output=True)
        subprocess.run([str(venv/'bin/pip'),'install','--no-cache-dir','--no-deps',str(checkout)],cwd=root,env=env,check=True,capture_output=True)
        subprocess.run([str(venv/'bin/drex-firewall'),'--help'],cwd=root,env=env,check=True,capture_output=True)
        result=subprocess.run([str(venv/'bin/python'),'-c',CANARY],cwd=root,env=env,check=True,capture_output=True,text=True)
        print(json.dumps({'public_head':head,'clean_install':'PASS','canary':json.loads(result.stdout)}))

if __name__=='__main__': main()
