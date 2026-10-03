"""Local synthetic narrow egress grant and bounded hostile broker clients."""
import socket
import threading
import time
from drex_agent_firewall.sandbox.controlled_egress import ControlledEgressBroker
from drex_agent_firewall.sandbox.manager import SandboxManager
from drex_agent_firewall.schemas.config import FirewallConfig, SandboxMount


def test_authorized_fixture_request_and_unapproved_host_rejection(tmp_path, monkeypatch):
    # Only this test supplies a trusted fixture connector; production DNS/SSRF
    # validation is exercised independently and remains unchanged.
    listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(); port=listener.getsockname()[1]
    def serve():
        connection,_=listener.accept()
        with connection:
            assert connection.recv(128)==b'GET /canary HTTP/1.0\r\n\r\n'
            connection.sendall(b'HTTP/1.0 200 OK\r\n\r\nSYNTHETIC_APPROVED_RESPONSE')
    thread=threading.Thread(target=serve,daemon=True); thread.start()
    def fixture_connector(host, requested_port):
        assert host=='approved.example.test' and requested_port==443
        return socket.create_connection(('127.0.0.1',port),timeout=1)
    monkeypatch.setattr('drex_agent_firewall.sandbox.controlled_egress._connect_public',fixture_connector)
    bridge=ControlledEgressBroker(str(tmp_path/'fixture.sock'),frozenset({'approved.example.test'})); bridge.start()
    ws=tmp_path/'ws'; ws.mkdir(); private=tmp_path/'private'; private.mkdir(mode=0o700)
    cfg=FirewallConfig(); cfg.sandbox.extra_mounts=[SandboxMount(host_path=bridge.socket_path,container_path='/run/fixture-egress.sock',mode='ro')]
    manager=SandboxManager('bubblewrap',str(private/'history.db')); sid=manager.create_session(str(ws),config=cfg,agent_type='generic',network_mode='none').session_id
    try:
        code='import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/fixture-egress.sock"); s.sendall(b"CONNECT unapproved.example.test 443\\n"); assert s.recv(128)==b"ERR policy\\n"; s.close(); s=socket.socket(socket.AF_UNIX); s.connect("/run/fixture-egress.sock"); s.sendall(b"CONNECT approved.example.test 443\\n"); assert s.recv(3)==b"OK\\n"; s.sendall(b"GET /canary HTTP/1.0\\r\\n\\r\\n"); s.shutdown(socket.SHUT_WR); response=b""\nwhile True:\n chunk=s.recv(1024)\n if not chunk: break\n response+=chunk\nassert b"SYNTHETIC_APPROVED_RESPONSE" in response'
        result=manager.exec_command(sid,['python3','-c',code]); assert result.returncode==0,result.stderr
    finally:
        manager.destroy_session(sid); manager.repository.conn.close(); bridge.close(); listener.close(); thread.join(timeout=1)


def test_slow_egress_clients_cannot_create_unbounded_host_threads(tmp_path):
    bridge=ControlledEgressBroker(str(tmp_path/'fixture.sock'),frozenset()); bridge.start()
    clients=[]
    try:
        for _ in range(40):
            client=socket.socket(socket.AF_UNIX); client.settimeout(.2)
            try:
                client.connect(bridge.socket_path); clients.append(client)
            except (BlockingIOError, socket.timeout):
                client.close()  # Refusal/backpressure is the expected safe result.
        time.sleep(.15)
        with bridge._active_lock: assert len(bridge._active)<=16
        time.sleep(4.1)
        with bridge._active_lock: assert not bridge._active
    finally:
        for client in clients: client.close()
        bridge.close()
