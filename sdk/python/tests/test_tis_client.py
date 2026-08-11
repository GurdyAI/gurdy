"""The TIS client tests."""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import pytest

import gurdy
from gurdy._tis import TISClient, Scope

class UnixHTTPServer(HTTPServer):
    address_family = socket.AF_UNIX

class StubTIS(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        if body:
            self.server.requests.append((self.path, json.loads(body.decode())))
        else:
            self.server.requests.append((self.path, None))
            
        status, resp_body = self.server.responses.pop(0)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(resp_body)
        
    def log_message(self, format, *args):
        pass

import os
import tempfile

@pytest.fixture
def stub_tis():
    sock_dir = tempfile.mkdtemp(prefix="tis_")
    sock_path = os.path.join(sock_dir, "tis.sock")
    server = UnixHTTPServer(sock_path, StubTIS)
    server.requests = []
    server.responses = []
    
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    
    yield server, sock_path
    
    server.shutdown()
    server.server_close()
    try:
        os.unlink(sock_path)
        os.rmdir(sock_dir)
    except OSError:
        pass

@pytest.fixture(autouse=True)
def _reset_config():
    yield
    gurdy._config.reset()

def test_mint_and_derive_send_correct_requests(stub_tis):
    """Client sends correct path and JSON body to the TIS socket, and extracts the token."""
    server, sock_path = stub_tis
    server.responses.append((200, b'{"txn": "mint-token"}'))
    server.responses.append((200, b'{"txn": "derive-token"}'))
    
    client = TISClient(sock_path)
    t1 = client.mint(agent="app", human_actor="alice", scope={"purpose": "read"}, ttl_seconds=60)
    assert t1 == "mint-token"
    
    t2 = client.derive(parent="mint-token", agent="sub", scope={"purpose": "write"})
    assert t2 == "derive-token"
    
    assert len(server.requests) == 2
    assert server.requests[0] == (
        "/mint",
        {"agent": "app", "human_actor": "alice", "scope": {"purpose": "read"}, "ttl_seconds": 60}
    )
    assert server.requests[1] == (
        "/derive",
        {"parent": "mint-token", "agent": "sub", "scope": {"purpose": "write"}}
    )

def test_derive_422_raises_scope_narrowing_refused(stub_tis):
    """HTTP 422 specifically means the requested scope was not a valid narrowing."""
    server, sock_path = stub_tis
    server.responses.append((422, b'{"error": "not a narrowing"}'))
    
    client = TISClient(sock_path)
    with pytest.raises(gurdy.ScopeNarrowingRefused) as exc:
        client.derive(parent="tok", agent="sub")
    assert "not a narrowing" in str(exc.value)

def test_400_and_500_raise_tis_unavailable_not_refused(stub_tis):
    """Other errors raise TISUnavailable, not ScopeNarrowingRefused."""
    server, sock_path = stub_tis
    server.responses.append((400, b'{"error": "bad"}'))
    server.responses.append((500, b'{"error": "boom"}'))
    
    client = TISClient(sock_path)
    
    with pytest.raises(gurdy.TISUnavailable) as exc1:
        client.mint(agent="app")
    assert type(exc1.value) is gurdy.TISUnavailable
    
    with pytest.raises(gurdy.TISUnavailable) as exc2:
        client.mint(agent="app")
    assert type(exc2.value) is gurdy.TISUnavailable

def test_200_without_txn_raises_tis_unavailable(stub_tis):
    """A missing token in a 200 OK would install an empty binding, so it must fail."""
    server, sock_path = stub_tis
    server.responses.append((200, b'{"other": "stuff"}'))
    
    client = TISClient(sock_path)
    with pytest.raises(gurdy.TISUnavailable, match="unusable txn"):
        client.mint(agent="app")

def test_undecodable_body_raises_tis_unavailable(stub_tis):
    """A 200 OK that isn't JSON is unusable and must be reported."""
    server, sock_path = stub_tis
    server.responses.append((200, b'definitely not json'))
    
    client = TISClient(sock_path)
    with pytest.raises(gurdy.TISUnavailable, match="undecodable body"):
        client.mint(agent="app")

def test_missing_socket_raises_tis_unavailable(tmp_path):
    """A socket path that does not exist raises TISUnavailable."""
    client = TISClient(str(tmp_path / "nope.sock"))
    with pytest.raises(gurdy.TISUnavailable, match="unreachable"):
        client.mint(agent="app")

def test_scope_coerce():
    """Scope fills its wildcards; a dict is sent verbatim, missing keys and all.

    The asymmetry is the interesting part, and it is deliberate. An absent
    dimension decodes server-side to an empty list, which the narrow-only
    algebra treats as the bottom of that dimension — a partial scope narrows a
    wildcard one, and the reverse is false. So a dict that omits "actions"
    grants nothing there.

    Filling the gaps with "*" here would silently widen what the caller wrote
    and turn a typo into a grant, which is precisely what narrow-only exists to
    prevent. Scope() is how you ask for wildcards, and it spells them out.
    """
    wildcards = {
        "compartments": ["*"],
        "resource_types": ["*"],
        "actions": ["*"],
        "purpose": "*",
    }
    assert Scope.coerce(None) == wildcards
    assert Scope.coerce(Scope()) == wildcards
    assert Scope.coerce(Scope(purpose="read")) == {**wildcards, "purpose": "read"}

    assert Scope.coerce({"purpose": "write"}) == {"purpose": "write"}
    assert Scope.coerce({}) == {}
