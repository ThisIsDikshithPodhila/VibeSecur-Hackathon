"""The local Docker runtime is opt-in and always labeled as unmeasured."""
import pytest

from vibesecur import local_runtime


def test_local_runtime_is_opt_in(monkeypatch):
    monkeypatch.delenv("VIBESECUR_WORKER_RUNTIME", raising=False)
    assert local_runtime.local_runtime_from_env(object()) is None


def test_local_runtime_requires_explicit_unmeasured_acknowledgement(monkeypatch):
    monkeypatch.setenv("VIBESECUR_WORKER_RUNTIME", "local-docker")
    monkeypatch.delenv("VIBESECUR_LOCAL_UNMEASURED_BOUNDARY", raising=False)
    with pytest.raises(ValueError):
        local_runtime.local_runtime_from_env(object())
    assert local_runtime.BOUNDARY == "unmeasured_local_docker"
