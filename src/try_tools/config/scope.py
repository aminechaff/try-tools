"""Validation du périmètre et de l'autorisation.

C'est le garde-fou central de Try_Tools : aucun module ne reçoit de cible qui
n'a pas franchi cette validation. Par défaut, seules les cibles de laboratoire
(boucle locale, plages privées, domaines de test) sont acceptées. Une cible
publique exige une autorisation explicite et un drapeau ``allow_public`` armé
intentionnellement.

La classification est volontairement *hors-ligne* : on ne résout pas le DNS ici
(une résolution est déjà une action réseau). Les adresses IP littérales sont
classées directement ; les noms d'hôtes ne sont acceptés sans autorisation
publique que s'ils sont de toute évidence locaux.
"""

from __future__ import annotations

import ipaddress
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator

# Suffixes réservés aux usages locaux / labo (RFC 6761, RFC 8375, usage courant).
_LOCAL_SUFFIXES = (".localhost", ".local", ".test", ".example", ".invalid", ".lab")
_LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain"}


class ScopeError(Exception):
    """Levée quand une cible sort du périmètre autorisé."""


class TargetClass(str, Enum):
    LOOPBACK = "loopback"
    PRIVATE = "private"
    LOCAL_NAME = "nom-local"
    PUBLIC = "public"


class Authorization(BaseModel):
    """Preuve d'autorisation rattachée à un périmètre.

    Sans autorisation valide couvrant la date du jour, aucune cible publique
    ne peut être acceptée, quel que soit ``allow_public``.
    """

    reference: str = Field(description="Référence du mandat ou du contexte de lab")
    granted_by: str = Field(description="Personne ou entité ayant accordé l'accès")
    valid_from: date
    valid_until: date

    @field_validator("reference", "granted_by")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("champ d'autorisation vide")
        return v.strip()

    def covers(self, when: date) -> bool:
        return self.valid_from <= when <= self.valid_until


def classify_target(target: str) -> TargetClass:
    """Classe une cible (IP littérale ou nom d'hôte) sans toucher au réseau."""

    host = target.strip().lower()
    if not host:
        raise ScopeError("cible vide")

    # Extrait l'hôte seul, sans port, en gérant les trois formes :
    #   [::1]:8080  (IPv6 entre crochets)  -> ::1
    #   host:8080   (un seul ':')          -> host
    #   ::1 / host  (IPv6 nu ou nom)        -> inchangé
    if host.startswith("[") and "]" in host:
        bare = host[1 : host.index("]")]
    elif host.count(":") == 1:
        bare = host.split(":", 1)[0]
    else:
        bare = host

    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        ip = None

    if ip is not None:
        if ip.is_loopback:
            return TargetClass.LOOPBACK
        if ip.is_private or ip.is_link_local:
            return TargetClass.PRIVATE
        return TargetClass.PUBLIC

    # Nom d'hôte.
    if bare in _LOCAL_HOSTNAMES:
        return TargetClass.LOOPBACK
    if any(bare.endswith(sfx) for sfx in _LOCAL_SUFFIXES):
        return TargetClass.LOCAL_NAME
    return TargetClass.PUBLIC


class ScopeConfig(BaseModel):
    """Configuration d'un périmètre d'audit."""

    owner: str = Field(description="Propriétaire ou porteur de l'audit")
    targets: list[str] = Field(description="Liste d'autorisation des cibles")
    exclusions: list[str] = Field(
        default_factory=list, description="Cibles ou routes à ne jamais tester"
    )
    authorization: Optional[Authorization] = None
    allow_public: bool = Field(
        default=False,
        description="Doit être armé explicitement pour toute cible publique",
    )

    @field_validator("owner")
    @classmethod
    def _owner_set(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("propriétaire obligatoire")
        return v.strip()

    @field_validator("targets")
    @classmethod
    def _targets_present(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("au moins une cible est requise")
        return v

    def validate_target(self, target: str, when: Optional[date] = None) -> TargetClass:
        """Vérifie qu'une cible est dans le périmètre. Lève ``ScopeError`` sinon.

        Retourne la classe de la cible si elle est autorisée.
        """
        when = when or date.today()
        host = target.strip().lower()

        if host in {e.strip().lower() for e in self.exclusions}:
            raise ScopeError(f"cible explicitement exclue : {target}")

        allow = {t.strip().lower() for t in self.targets}
        if host not in allow:
            raise ScopeError(f"cible hors liste d'autorisation : {target}")

        cls_ = classify_target(host)
        if cls_ is TargetClass.PUBLIC:
            if not self.allow_public:
                raise ScopeError(
                    f"cible publique refusée (allow_public désarmé) : {target}"
                )
            if self.authorization is None or not self.authorization.covers(when):
                raise ScopeError(
                    f"cible publique sans autorisation valide à la date {when} : {target}"
                )
        return cls_

    def validate_all(self, when: Optional[date] = None) -> dict[str, TargetClass]:
        """Valide toutes les cibles déclarées et retourne leur classe."""
        return {t: self.validate_target(t, when) for t in self.targets}


def load_scope(path: str | Path) -> ScopeConfig:
    """Charge un périmètre depuis un fichier YAML et le valide."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return ScopeConfig.model_validate(data)
