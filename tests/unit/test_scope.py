from datetime import date

import pytest

from try_tools.config.scope import (
    Authorization,
    ScopeConfig,
    ScopeError,
    TargetClass,
    classify_target,
)


@pytest.mark.parametrize(
    "target,expected",
    [
        ("127.0.0.1", TargetClass.LOOPBACK),
        ("::1", TargetClass.LOOPBACK),
        ("localhost", TargetClass.LOOPBACK),
        ("192.168.1.10", TargetClass.PRIVATE),
        ("10.0.0.5", TargetClass.PRIVATE),
        ("dvwa.local", TargetClass.LOCAL_NAME),
        ("app.test", TargetClass.LOCAL_NAME),
        ("8.8.8.8", TargetClass.PUBLIC),
        ("example.org", TargetClass.PUBLIC),
        # Formes avec port : l'hôte doit être extrait avant classification.
        ("127.0.0.1:8080", TargetClass.LOOPBACK),
        ("192.168.1.10:443", TargetClass.PRIVATE),
        ("[::1]:8080", TargetClass.LOOPBACK),
        ("dvwa.local:80", TargetClass.LOCAL_NAME),
        ("example.org:8443", TargetClass.PUBLIC),
    ],
)
def test_classify_target(target, expected):
    assert classify_target(target) == expected


def test_lab_targets_allowed():
    scope = ScopeConfig(owner="moi", targets=["127.0.0.1", "dvwa.local"])
    classes = scope.validate_all()
    assert classes["127.0.0.1"] == TargetClass.LOOPBACK
    assert classes["dvwa.local"] == TargetClass.LOCAL_NAME


def test_target_not_in_allowlist_rejected():
    scope = ScopeConfig(owner="moi", targets=["127.0.0.1"])
    with pytest.raises(ScopeError):
        scope.validate_target("192.168.1.1")


def test_excluded_target_rejected():
    scope = ScopeConfig(
        owner="moi", targets=["192.168.1.1"], exclusions=["192.168.1.1"]
    )
    with pytest.raises(ScopeError):
        scope.validate_target("192.168.1.1")


def test_public_target_rejected_without_allow_public():
    scope = ScopeConfig(owner="moi", targets=["example.org"])
    with pytest.raises(ScopeError):
        scope.validate_target("example.org")


def test_public_target_rejected_without_authorization():
    scope = ScopeConfig(owner="moi", targets=["example.org"], allow_public=True)
    with pytest.raises(ScopeError):
        scope.validate_target("example.org")


def test_public_target_allowed_with_valid_authorization():
    auth = Authorization(
        reference="mandat-1",
        granted_by="proprio",
        valid_from=date(2026, 1, 1),
        valid_until=date(2026, 12, 31),
    )
    scope = ScopeConfig(
        owner="moi",
        targets=["example.org"],
        allow_public=True,
        authorization=auth,
    )
    assert (
        scope.validate_target("example.org", when=date(2026, 6, 1))
        == TargetClass.PUBLIC
    )


def test_public_target_rejected_when_authorization_expired():
    auth = Authorization(
        reference="mandat-1",
        granted_by="proprio",
        valid_from=date(2026, 1, 1),
        valid_until=date(2026, 1, 31),
    )
    scope = ScopeConfig(
        owner="moi", targets=["example.org"], allow_public=True, authorization=auth
    )
    with pytest.raises(ScopeError):
        scope.validate_target("example.org", when=date(2026, 6, 1))
