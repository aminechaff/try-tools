"""Contrat de base des plugins Try_Tools.

Un plugin est une capacité autonome. Dès la Phase 1, le contrat est fixé pour
pouvoir accueillir plus tard des plugins écrits dans d'autres langages : un
plugin reçoit une cible déjà validée et un dictionnaire de paramètres, et
retourne une liste de ``Finding``. Les plugins hors-process (Go, Rust, C)
communiqueront via le même schéma sérialisé en JSON.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from try_tools.schemas.finding import Finding, RiskLevel


@dataclass(frozen=True)
class PluginMeta:
    """Déclaration obligatoire d'un plugin (cf. README « Plugins »)."""

    id: str
    version: str
    maintainer: str
    description: str
    risk_level: RiskLevel = RiskLevel.PASSIVE
    # Classes de cibles compatibles, ex. {"loopback", "private"}.
    target_classes: frozenset[str] = field(default_factory=frozenset)
    timeout_seconds: int = 30


class Plugin(abc.ABC):
    """Classe de base d'un plugin interne Python."""

    meta: PluginMeta

    @abc.abstractmethod
    def run(self, target: str, params: dict[str, str]) -> list[Finding]:
        """Exécute le contrôle sur une cible DÉJÀ validée par le périmètre.

        Ne doit jamais effectuer d'action destructive. Les plugins intrusifs
        doivent être désactivés par défaut et exiger une activation explicite.
        """
        raise NotImplementedError
