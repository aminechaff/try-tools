"""Pont sous-process : exécuter des plugins écrits dans d'autres langages.

Contrat « External Plugin Protocol v1 » (voir docs/plugin-protocol.md) :

- Invocation : ``<commande> <cible> [clé=valeur ...]``
- Entrée : la cible et les paramètres passent par les arguments de ligne de
  commande (simple à lire depuis n'importe quel langage, y compris C).
- Sortie : sur stdout, un JSON ``{"plugin": "...", "version": "...",
  "findings": [ <Finding> ... ]}`` où chaque ``Finding`` respecte le schéma
  commun (``schemas/finding.py``).
- stderr : diagnostics libres (masqués par le journal Python).
- Code de sortie : 0 = succès ; tout autre = erreur (consignée).

L'orchestrateur reste ainsi indépendant du langage : Python orchestre, les
modules peuvent être en Go, Rust, C, JS, etc., tant qu'ils rendent du JSON
conforme.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from try_tools.core.logging import get_logger, mask
from try_tools.plugins.base import Plugin, PluginMeta
from try_tools.schemas.finding import Finding

_log = get_logger("try_tools.plugins.external")

# Racine du dépôt (…/src/try_tools/plugins/external.py -> remonte de 4 niveaux).
_REPO_ROOT = Path(__file__).resolve().parents[3]
_BIN = _REPO_ROOT / "plugins_ext" / "bin"
_EXE = ".exe" if os.name == "nt" else ""


class ExternalPlugin(Plugin):
    """Enveloppe un exécutable externe comme un plugin Try_Tools."""

    def __init__(self, meta: PluginMeta, command: list[str]):
        self.meta = meta
        self._command = command

    def available(self) -> bool:
        """Vrai si la commande est lançable (binaire présent / interpréteur OK)."""
        head = self._command[0]
        p = Path(head)
        if p.exists():
            return True
        # Interpréteur (ex. "node") résolu via le PATH.
        from shutil import which

        return which(head) is not None

    def run(self, target: str, params: dict[str, str]) -> list[Finding]:
        argv = [*self._command, target]
        argv += [f"{k}={v}" for k, v in params.items()]

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.meta.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"délai dépassé ({self.meta.timeout_seconds}s)")
        except FileNotFoundError:
            raise RuntimeError(f"exécutable introuvable : {self._command[0]}")

        if proc.stderr.strip():
            _log.info("%s stderr: %s", self.meta.id, mask(proc.stderr.strip()))
        if proc.returncode != 0:
            raise RuntimeError(
                f"code de sortie {proc.returncode} : {mask(proc.stderr.strip())[:300]}"
            )

        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"sortie JSON invalide : {exc}")

        findings = []
        for raw in payload.get("findings", []):
            findings.append(Finding.model_validate(raw))
        return findings


@dataclass(frozen=True)
class _Spec:
    meta: PluginMeta
    command: list[str]


def _specs() -> list[_Spec]:
    from try_tools.schemas.finding import RiskLevel

    net = frozenset({"loopback", "private", "nom-local"})
    web = frozenset({"loopback", "private", "nom-local"})
    any_ = frozenset({"loopback", "private", "nom-local", "public"})
    ext = _REPO_ROOT / "plugins_ext"

    return [
        _Spec(
            PluginMeta(
                id="go.tcp_probe",
                version="0.0.1",
                maintainer="Try_Tools",
                description="Découverte de ports par connexion TCP (sans payload).",
                risk_level=RiskLevel.ACTIVE_SAFE,
                target_classes=net,
                timeout_seconds=30,
            ),
            [str(_BIN / f"tcp_probe{_EXE}")],
        ),
        _Spec(
            PluginMeta(
                id="rust.http_headers",
                version="0.0.1",
                maintainer="Try_Tools",
                description="Contrôle des en-têtes HTTP de sécurité.",
                risk_level=RiskLevel.ACTIVE_SAFE,
                target_classes=web,
                timeout_seconds=20,
            ),
            [str(_BIN / f"http_headers{_EXE}")],
        ),
        _Spec(
            PluginMeta(
                id="node.cookie_check",
                version="0.0.1",
                maintainer="Try_Tools",
                description="Analyse des attributs de cookies (Secure/HttpOnly/SameSite).",
                risk_level=RiskLevel.ACTIVE_SAFE,
                target_classes=web,
                timeout_seconds=20,
            ),
            ["node", str(ext / "node" / "cookie_check.js")],
        ),
        _Spec(
            PluginMeta(
                id="c.banner_analyzer",
                version="0.0.1",
                maintainer="Try_Tools",
                description="Détection de divulgation de version dans une bannière (hors-ligne).",
                risk_level=RiskLevel.PASSIVE,
                target_classes=any_,
                timeout_seconds=10,
            ),
            [str(_BIN / f"banner_analyzer{_EXE}")],
        ),
    ]


def discover_external_plugins() -> list[ExternalPlugin]:
    """Retourne les plugins externes effectivement disponibles sur la machine.

    Un plugin dont le binaire n'est pas compilé (ou l'interpréteur absent) est
    simplement ignoré, avec une trace. L'outil reste utilisable avec ce qui est
    présent.
    """
    plugins: list[ExternalPlugin] = []
    for spec in _specs():
        plugin = ExternalPlugin(spec.meta, spec.command)
        if plugin.available():
            plugins.append(plugin)
            _log.info("plugin externe disponible : %s", spec.meta.id)
        else:
            _log.info("plugin externe absent (ignoré) : %s", spec.meta.id)
    return plugins
