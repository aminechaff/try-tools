"""Modèle de résultat commun (« constat ») partagé par tous les plugins.

Ce schéma est le contrat central de Try_Tools : chaque plugin, quel que soit
son langage, doit produire un ou plusieurs ``Finding`` sérialisables en JSON.
Il reprend le standard de rapport décrit dans le README (section « Standard
des rapports »).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Gravité d'un constat."""

    CRITICAL = "critique"
    HIGH = "haute"
    MEDIUM = "moyenne"
    LOW = "faible"
    INFO = "informationnelle"


class Confidence(str, Enum):
    """Niveau de confiance accordé au constat.

    ``CONFIRMED`` est réservé à une vérification humaine : un résultat
    purement automatisé ne doit jamais être marqué comme confirmé.
    """

    CONFIRMED = "confirmee"
    HIGH = "elevee"
    MEDIUM = "moyenne"
    LOW = "faible"


class State(str, Enum):
    """État du constat dans le cycle de vie d'un audit."""

    NEW = "nouveau"
    TO_CONFIRM = "a_confirmer"
    ACCEPTED = "accepte"
    FIXED = "corrige"
    FALSE_POSITIVE = "faux_positif"


class RiskLevel(str, Enum):
    """Niveau de risque de l'action ayant produit le constat.

    Reprend la classification des plugins : passif, actif mais sûr, intrusif.
    """

    PASSIVE = "passif"
    ACTIVE_SAFE = "actif-sur"
    INTRUSIVE = "intrusif"


class Reference(BaseModel):
    """Référence externe (CWE, CVE, CVSS, documentation)."""

    kind: str = Field(description="Type de référence : cwe, cve, cvss, doc, url")
    value: str = Field(description="Identifiant ou URL, ex. CVE-2024-1234")
    note: Optional[str] = Field(default=None, description="Précision facultative")


class Evidence(BaseModel):
    """Preuve minimale, horodatée et expurgée de tout secret.

    La preuve ne doit jamais contenir de cookie, jeton, mot de passe ou donnée
    personnelle réelle. Le masquage est appliqué en amont par le journal ;
    ici on ne stocke qu'un extrait déjà nettoyé.
    """

    summary: str = Field(description="Description courte de la preuve")
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Horodatage UTC de collecte",
    )
    excerpt: Optional[str] = Field(
        default=None,
        description="Extrait brut minimal, déjà masqué des secrets",
        max_length=4000,
    )


class Finding(BaseModel):
    """Un constat unique, unité de base de tout rapport Try_Tools."""

    # Identité
    id: str = Field(description="Référence stable du constat, ex. net-001")
    title: str = Field(description="Description courte et factuelle")

    # Cible et périmètre
    target: str = Field(description="Hôte, service, URL ou composant concerné")
    scope_profile: str = Field(
        description="Profil de test et autorisation utilisés, ex. 'lab-passif'"
    )

    # Classification
    severity: Severity
    confidence: Confidence
    state: State = State.NEW
    risk_level: RiskLevel = RiskLevel.PASSIVE

    # Détails
    description: str = Field(description="Explication du constat")
    impact: Optional[str] = Field(
        default=None, description="Conséquences techniques et métier réalistes"
    )
    reproduction: Optional[str] = Field(
        default=None, description="Étapes sûres, précises, adaptées au périmètre"
    )
    remediation: Optional[str] = Field(
        default=None, description="Correction priorisée et moyen de validation"
    )

    references: list[Reference] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

    # Traçabilité de l'outil
    tool_name: str = Field(description="Module ou adaptateur ayant produit le constat")
    tool_version: Optional[str] = Field(default=None)
    tool_params: dict[str, str] = Field(
        default_factory=dict,
        description="Paramètres utilisés (déjà masqués des secrets)",
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Horodatage UTC de création du constat",
    )

    @field_validator("id", "title", "target", "tool_name")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("champ obligatoire vide")
        return v.strip()

    def dedup_key(self) -> tuple[str, str, str]:
        """Clé de déduplication : même titre, même cible, même sévérité.

        Utilisée par l'étape de corrélation pour regrouper les doublons
        produits par des plugins différents.
        """
        return (self.title.lower(), self.target.lower(), self.severity.value)
