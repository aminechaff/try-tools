import pytest
from pydantic import ValidationError

from try_tools.schemas.finding import (
    Confidence,
    Finding,
    Severity,
)


def _make(**kw):
    base = dict(
        id="net-001",
        title="Port ouvert",
        target="127.0.0.1",
        scope_profile="lab-passif",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        description="Un service écoute.",
        tool_name="core.inventory",
    )
    base.update(kw)
    return Finding(**base)


def test_finding_minimal_valid():
    f = _make()
    assert f.id == "net-001"
    assert f.severity == Severity.LOW


def test_finding_empty_title_rejected():
    with pytest.raises(ValidationError):
        _make(title="   ")


def test_finding_json_roundtrip():
    f = _make()
    data = f.model_dump(mode="json")
    again = Finding.model_validate(data)
    assert again.dedup_key() == f.dedup_key()


def test_dedup_key_case_insensitive():
    a = _make(title="Port Ouvert", target="127.0.0.1")
    b = _make(title="port ouvert", target="127.0.0.1")
    assert a.dedup_key() == b.dedup_key()
