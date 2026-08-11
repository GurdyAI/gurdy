"""Tests for the configuration machinery."""

import os
import pytest

import gurdy
from gurdy import _config

@pytest.fixture(autouse=True)
def _reset_config():
    yield
    _config.reset()

def test_reads_from_environment(monkeypatch):
    """Config defaults to environment variables GURDY_PROXY_URL and GURDY_TIS_SOCKET."""
    monkeypatch.setenv("GURDY_PROXY_URL", "http://env-proxy")
    monkeypatch.setenv("GURDY_TIS_SOCKET", "/env.sock")
    
    cfg = _config.current()
    assert cfg.proxy_url == "http://env-proxy"
    assert cfg.tis_socket == "/env.sock"

def test_configure_overrides_environment(monkeypatch):
    """gurdy.configure overrides the environment; partial override leaves other field intact."""
    monkeypatch.setenv("GURDY_PROXY_URL", "http://env-proxy")
    monkeypatch.setenv("GURDY_TIS_SOCKET", "/env.sock")
    
    gurdy.configure(proxy_url="http://explicit-proxy")
    
    cfg = _config.current()
    assert cfg.proxy_url == "http://explicit-proxy"
    assert cfg.tis_socket == "/env.sock"
    
    gurdy.configure(tis_socket="/explicit.sock")
    cfg2 = _config.current()
    assert cfg2.proxy_url == "http://explicit-proxy"
    assert cfg2.tis_socket == "/explicit.sock"

def test_trailing_slash_stripped(monkeypatch):
    """A trailing slash on proxy_url is normalised away."""
    monkeypatch.setenv("GURDY_PROXY_URL", "http://proxy/")
    assert _config.current().proxy_url == "http://proxy"
    
    _config.reset()
    
    cfg = gurdy.configure(proxy_url="http://other/")
    assert cfg.proxy_url == "http://other"

def test_reset_rereads_environment(monkeypatch):
    """_config.reset() causes a re-read of the environment."""
    monkeypatch.setenv("GURDY_TIS_SOCKET", "/first.sock")
    assert _config.current().tis_socket == "/first.sock"
    
    monkeypatch.setenv("GURDY_TIS_SOCKET", "/second.sock")
    _config.reset()
    assert _config.current().tis_socket == "/second.sock"
