from try_tools.config.scope import ScopeConfig
from try_tools.core.orchestrator import Orchestrator
from try_tools.plugins.base import Plugin, PluginMeta
from try_tools.plugins.inventory import InventoryPlugin
from try_tools.schemas.finding import (
    Confidence,
    Finding,
    RiskLevel,
    Severity,
)


def test_run_produces_findings_for_each_target():
    scope = ScopeConfig(owner="moi", targets=["127.0.0.1", "dvwa.local"])
    orch = Orchestrator(scope)
    orch.register(InventoryPlugin())
    result = orch.run()
    assert len(result.findings) == 2
    assert not result.errors


class _IntrusivePlugin(Plugin):
    meta = PluginMeta(
        id="danger",
        version="0.0.1",
        maintainer="x",
        description="intrusif",
        risk_level=RiskLevel.INTRUSIVE,
    )

    def run(self, target, params):  # pragma: no cover - ne doit pas être appelé
        raise AssertionError("un plugin intrusif ne doit pas tourner par défaut")


def test_intrusive_plugin_skipped_by_default():
    scope = ScopeConfig(owner="moi", targets=["127.0.0.1"])
    orch = Orchestrator(scope, max_risk=RiskLevel.ACTIVE_SAFE)
    orch.register(_IntrusivePlugin())
    result = orch.run()
    assert result.findings == []
    assert any("danger" in s for s in result.skipped)


class _BrokenPlugin(Plugin):
    meta = PluginMeta(id="broken", version="0.0.1", maintainer="x", description="ko")

    def run(self, target, params):
        raise RuntimeError("boom")


def test_plugin_error_does_not_kill_run():
    scope = ScopeConfig(owner="moi", targets=["127.0.0.1"])
    orch = Orchestrator(scope)
    orch.register(_BrokenPlugin())
    orch.register(InventoryPlugin())
    result = orch.run()
    assert len(result.findings) == 1
    assert any("broken" in e for e in result.errors)


class _DupPlugin(Plugin):
    meta = PluginMeta(id="dup", version="0.0.1", maintainer="x", description="dup")

    def run(self, target, params):
        f = Finding(
            id="d1",
            title="Même constat",
            target=target,
            scope_profile="lab",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            description="x",
            tool_name="dup",
        )
        return [f, f]


def test_dedup_removes_duplicates():
    scope = ScopeConfig(owner="moi", targets=["127.0.0.1"])
    orch = Orchestrator(scope)
    orch.register(_DupPlugin())
    result = orch.run()
    assert len(result.findings) == 1
