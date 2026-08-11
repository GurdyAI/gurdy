"""Tests for task and sub-agent spawning."""

import asyncio
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import pytest

import gurdy

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
    
    # Configure gurdy to use the stub TIS
    gurdy.configure(tis_socket=sock_path)
    
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

def test_task_is_decorator_and_context_manager(stub_tis):
    """task(...) can wrap a block, a sync function, or an async function."""
    server, sock_path = stub_tis
    server.responses.append((200, b'{"txn": "tok1"}'))
    server.responses.append((200, b'{"txn": "tok2"}'))
    server.responses.append((200, b'{"txn": "tok3"}'))
    
    # Context manager
    with gurdy.task(agent="ctx"):
        assert gurdy.current().txn == "tok1"
        
    # Sync decorator
    @gurdy.task(agent="sync")
    def sync_fn():
        return gurdy.current().txn
        
    assert sync_fn() == "tok2"
    
    # Async decorator
    @gurdy.task(agent="async")
    async def async_fn():
        return gurdy.current().txn
        
    assert asyncio.run(async_fn()) == "tok3"

def test_task_decorator_mints_fresh_credential(stub_tis):
    """The decorator acquires a token when called, not when imported."""
    server, _ = stub_tis
    server.responses.append((200, b'{"txn": "t1"}'))
    server.responses.append((200, b'{"txn": "t2"}'))
    
    @gurdy.task(agent="reused")
    def work():
        return gurdy.current().txn
        
    assert work() == "t1"
    assert work() == "t2"

def test_spawn_derives_and_restores(stub_tis):
    """A sub-agent gets a derived token, and parent token is restored on exit."""
    server, _ = stub_tis
    server.responses.append((200, b'{"txn": "parent"}'))
    server.responses.append((200, b'{"txn": "child"}'))
    
    with gurdy.task(agent="parent"):
        assert gurdy.current().txn == "parent"
        with gurdy.spawn(agent="child"):
            assert gurdy.current().txn == "child"
        assert gurdy.current().txn == "parent"

def test_spawn_without_task_raises(stub_tis):
    """Spawning outside a task raises NotConfigured."""
    with pytest.raises(gurdy.NotConfigured, match="outside a task context"):
        with gurdy.spawn(agent="child"):
            pass

def test_spawn_refused_leaves_parent_and_bypasses_body(stub_tis):
    """A refused spawn skips the block body and restores parent binding immediately."""
    server, _ = stub_tis
    server.responses.append((200, b'{"txn": "parent"}'))
    server.responses.append((422, b'{"error": "nope"}'))
    
    executed = False
    with gurdy.task(agent="parent"):
        with pytest.raises(gurdy.ScopeNarrowingRefused):
            with gurdy.spawn(agent="child"):
                executed = True
        assert gurdy.current().txn == "parent"
        
    assert not executed

def test_start_task_derive_no_socket_raises():
    """start_task and derive raise NotConfigured if tis_socket is unset."""
    gurdy.configure(tis_socket="")
    
    with pytest.raises(gurdy.NotConfigured, match="no TIS socket configured"):
        gurdy.start_task(agent="a")
        
    # For derive, we need a parent binding
    parent = gurdy.Binding(txn="t", agent="a")
    with pytest.raises(gurdy.NotConfigured, match="no TIS socket configured"):
        gurdy.derive(parent=parent, agent="b")

def test_derive_inherits_human_actor(stub_tis):
    """Sub-agents operate on behalf of the same human as the parent transaction."""
    server, _ = stub_tis
    server.responses.append((200, b'{"txn": "parent"}'))
    server.responses.append((200, b'{"txn": "child"}'))
    
    with gurdy.task(agent="parent", human_actor="alice"):
        with gurdy.spawn(agent="child"):
            assert gurdy.current().human_actor == "alice"
