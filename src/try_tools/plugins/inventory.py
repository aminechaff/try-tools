"""Plugin d'exemple : inventaire de périmètre (passif, hors-ligne).

Ne touche pas au réseau. Il transforme simplement chaque cible validée en un
constat informationnel. Son but est de démontrer le contrat de plugin et de
donner à l'orchestrateur quelque chose à produire dès la Phase 1, sans aucun
risque. Les vrais modules réseau/web viendront ensuite, derrière des
adaptateurs et avec des profils prudents.
"""

from __future__ import annotations

from try_tools.plugins.base import Plugin, PluginMeta
from try_tools.schemas.finding import (
    Confidence,
    Finding,
    RiskLevel,
    Severity,
    State,
)


class InventoryPlugin(Plugin):
    meta = PluginMeta(
        id="core.inventory",
        version="0.0.1",
        maintainer="Try_Tools",
        description="Inventaire passif des cibles du périmètre.",
        risk_level=RiskLevel.PASSIVE,
        target_classes=frozenset(
            {"loopback", "private", "nom-local", "public"}
        ),
    )

    def run(self, target: str, params: dict[str, str]) -> list[Finding]:
        return [
            Finding(
                id=f"inv-{abs(hash(target)) % 100000:05d}",
                title="Cible inscrite au périmètre d'audit",
                target=target,
                scope_profile="lab-passif",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                state=State.NEW,
                risk_level=RiskLevel.PASSIVE,
                description=(
                    "Cible déclarée et validée dans le périmètre. Aucun contrôle "
                    "actif n'a été exécuté par ce module."
                ),
                tool_name=self.meta.id,
                tool_version=self.meta.version,
            )
        ]
