"""Génération de rapport Markdown et JSON à partir de constats.

Formats de la Phase 1 : JSON (modèle brut, réutilisable par d'autres outils)
et Markdown (lisible). Le HTML/Jinja2 viendra en Phase 2.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from try_tools.schemas.finding import Finding, Severity

_SEV_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def to_json(findings: list[Finding], *, indent: int = 2) -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(findings),
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=indent)


def to_markdown(findings: list[Finding], *, title: str = "Rapport Try_Tools") -> str:
    ordered = sorted(findings, key=lambda f: _SEV_ORDER[f.severity])
    lines: list[str] = [f"# {title}", ""]
    lines.append(f"_Généré le {datetime.now(timezone.utc).isoformat()}_")
    lines.append("")

    # Synthèse par sévérité.
    counts: dict[str, int] = {}
    for f in ordered:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    lines.append("## Synthèse par sévérité")
    lines.append("")
    lines.append("| Sévérité | Nombre |")
    lines.append("|---|---|")
    for sev in Severity:
        lines.append(f"| {sev.value} | {counts.get(sev.value, 0)} |")
    lines.append("")

    # Constats détaillés.
    lines.append("## Constats détaillés")
    lines.append("")
    if not ordered:
        lines.append("_Aucun constat._")
    for f in ordered:
        lines.append(f"### [{f.id}] {f.title}")
        lines.append("")
        lines.append(f"- **Cible** : {f.target}")
        lines.append(f"- **Sévérité** : {f.severity.value}")
        lines.append(f"- **Confiance** : {f.confidence.value}")
        lines.append(f"- **État** : {f.state.value}")
        lines.append(f"- **Outil** : {f.tool_name} {f.tool_version or ''}".rstrip())
        lines.append("")
        lines.append(f.description)
        if f.impact:
            lines.append("")
            lines.append(f"**Impact** : {f.impact}")
        if f.remediation:
            lines.append("")
            lines.append(f"**Remédiation** : {f.remediation}")
        lines.append("")
    return "\n".join(lines)
