"""Tests du pont sous-process.

On s'appuie sur le plugin C ``banner_analyzer`` : il est hors-ligne et
déterministe. Les tests sont ignorés proprement si le binaire n'est pas
compilé (toolchain absente sur la machine de CI).
"""

import os
from pathlib import Path

import pytest

from try_tools.plugins.external import ExternalPlugin, _BIN
from try_tools.plugins.base import PluginMeta
from try_tools.schemas.finding import RiskLevel, Severity

_EXE = ".exe" if os.name == "nt" else ""
_BANNER_BIN = _BIN / f"banner_analyzer{_EXE}"

pytestmark = pytest.mark.skipif(
    not Path(_BANNER_BIN).exists(),
    reason="banner_analyzer non compilé (lancer scripts/build_plugins)",
)


def _plugin() -> ExternalPlugin:
    meta = PluginMeta(
        id="c.banner_analyzer",
        version="0.0.1",
        maintainer="test",
        description="test",
        risk_level=RiskLevel.PASSIVE,
    )
    return ExternalPlugin(meta, [str(_BANNER_BIN)])


def test_banner_version_disclosure_detected():
    findings = _plugin().run("127.0.0.1", {"banner": "Apache/2.4.58 (Ubuntu)"})
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "version" in findings[0].title.lower()
    assert findings[0].tool_name == "c.banner_analyzer"


def test_banner_absent_is_informational():
    findings = _plugin().run("127.0.0.1", {})
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO


def test_findings_are_valid_schema():
    # Un JSON mal formé lèverait ; ici on vérifie le round-trip complet.
    findings = _plugin().run("host.local", {"banner": "nginx/1.25.3"})
    assert findings[0].target == "host.local"
    assert findings[0].model_dump(mode="json")["tool_name"] == "c.banner_analyzer"
