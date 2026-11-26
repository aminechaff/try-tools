"""Journalisation avec masquage automatique des secrets.

La traçabilité est un principe du projet, mais aucun secret ne doit fuiter
dans les journaux ou les rapports. Ce module fournit :

- ``mask`` : masque les motifs sensibles dans une chaîne arbitraire ;
- ``SecretMaskingFilter`` : un filtre logging qui applique ``mask`` à chaque
  enregistrement ;
- ``get_logger`` : un logger configuré avec ce filtre.
"""

from __future__ import annotations

import logging
import re

_REDACTED = "***masqué***"

# Motifs courants : clé=valeur pour des noms sensibles, en-têtes d'auth,
# cookies, et jetons de forme connue.
_PATTERNS: tuple[re.Pattern[str], ...] = (
    # token=..., password: ..., api_key = "...", secret='...'
    re.compile(
        r"(?i)\b(pass(word)?|pwd|secret|token|api[_-]?key|auth|cookie|session)\b"
        r"\s*[=:]\s*(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),
    # En-tête Authorization: Bearer xxx / Basic xxx
    re.compile(r"(?i)(authorization:\s*)(bearer|basic)\s+[A-Za-z0-9._\-+/=]+"),
    # Jetons JWT (trois segments base64url)
    re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
)


def mask(text: str) -> str:
    """Remplace les secrets reconnus par un marqueur."""
    if not text:
        return text
    out = text
    # Préserve le nom du champ, masque la valeur.
    out = _PATTERNS[0].sub(lambda m: f"{m.group(1)}={_REDACTED}", out)
    out = _PATTERNS[1].sub(lambda m: f"{m.group(1)}{m.group(2)} {_REDACTED}", out)
    out = _PATTERNS[2].sub(_REDACTED, out)
    return out


class SecretMaskingFilter(logging.Filter):
    """Filtre qui masque les secrets dans le message formaté."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = mask(record.getMessage())
            record.args = ()
        except Exception:
            # Un masquage qui échoue ne doit jamais faire tomber l'audit ;
            # en dernier recours on neutralise le message.
            record.msg = _REDACTED
            record.args = ()
        return True


def get_logger(name: str = "try_tools") -> logging.Logger:
    """Retourne un logger configuré avec le masquage des secrets."""
    logger = logging.getLogger(name)
    if not any(isinstance(f, SecretMaskingFilter) for f in logger.filters):
        logger.addFilter(SecretMaskingFilter())
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        handler.addFilter(SecretMaskingFilter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger
