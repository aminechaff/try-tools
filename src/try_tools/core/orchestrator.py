"""Orchestrateur central (squelette Phase 1).

Responsabilités : valider le périmètre, sélectionner les plugins compatibles,
les exécuter sur des cibles autorisées, collecter les constats, puis les
dédupliquer. La génération de rapport est traitée par un module dédié.

L'orchestrateur ne connaît aucun format propre à un scanner : il ne manipule
que des ``Finding``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from try_tools.config.scope import ScopeConfig, ScopeError
from try_tools.core.logging import get_logger
from try_tools.plugins.base import Plugin
from try_tools.schemas.finding import Finding, RiskLevel

_log = get_logger("try_tools.orchestrator")


@dataclass
class RunResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


class Orchestrator:
    def __init__(self, scope: ScopeConfig, *, max_risk: RiskLevel = RiskLevel.ACTIVE_SAFE):
        self.scope = scope
        self.max_risk = max_risk
        self._plugins: list[Plugin] = []

    def register(self, plugin: Plugin) -> None:
        self._plugins.append(plugin)

    def _risk_allowed(self, level: RiskLevel) -> bool:
        order = [RiskLevel.PASSIVE, RiskLevel.ACTIVE_SAFE, RiskLevel.INTRUSIVE]
        return order.index(level) <= order.index(self.max_risk)

    def run(self, params: dict[str, str] | None = None) -> RunResult:
        params = params or {}
        result = RunResult()

        # 1. Valider tout le périmètre avant d'exécuter quoi que ce soit.
        try:
            target_classes = self.scope.validate_all()
        except ScopeError as exc:
            result.errors.append(f"périmètre invalide : {exc}")
            _log.error("Validation du périmètre échouée : %s", exc)
            return result

        # 2. Pour chaque cible autorisée, lancer les plugins compatibles.
        for target, tclass in target_classes.items():
            for plugin in self._plugins:
                meta = plugin.meta

                if not self._risk_allowed(meta.risk_level):
                    msg = f"{meta.id} ignoré (risque {meta.risk_level.value} > max)"
                    result.skipped.append(msg)
                    _log.info(msg)
                    continue

                if meta.target_classes and tclass.value not in meta.target_classes:
                    result.skipped.append(
                        f"{meta.id} ignoré pour {target} (classe {tclass.value})"
                    )
                    continue

                try:
                    found = plugin.run(target, params)
                    result.findings.extend(found)
                    _log.info("%s a produit %d constat(s) sur %s", meta.id, len(found), target)
                except Exception as exc:  # un plugin ne doit pas tuer l'audit
                    result.errors.append(f"{meta.id} sur {target} : {exc}")
                    _log.error("Plugin %s en erreur sur %s : %s", meta.id, target, exc)

        result.findings = self._dedup(result.findings)
        return result

    @staticmethod
    def _dedup(findings: list[Finding]) -> list[Finding]:
        """Regroupe les doublons en conservant le premier de chaque clé."""
        seen: dict[tuple[str, str, str], Finding] = {}
        for f in findings:
            seen.setdefault(f.dedup_key(), f)
        return list(seen.values())
