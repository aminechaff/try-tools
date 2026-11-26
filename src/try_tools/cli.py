"""Interface en ligne de commande minimale (Phase 1).

Sous-commandes :
  validate   valide un fichier de périmètre et affiche la classe de chaque cible
  run        valide le périmètre, exécute les plugins enregistrés et produit un rapport

Par défaut, l'exécution est non destructive et limitée aux plugins passifs ou
actifs-sûrs. Aucune cible hors du périmètre validé n'est touchée.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from try_tools.config.scope import ScopeError, load_scope
from try_tools.core.logging import get_logger
from try_tools.core.orchestrator import Orchestrator
from try_tools.plugins.external import discover_external_plugins
from try_tools.plugins.inventory import InventoryPlugin
from try_tools.report import markdown
from try_tools.schemas.finding import RiskLevel

_log = get_logger("try_tools.cli")


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        scope = load_scope(args.scope)
        classes = scope.validate_all()
    except (ScopeError, OSError, ValueError) as exc:
        _log.error("Périmètre invalide : %s", exc)
        return 2
    print(f"Périmètre valide — propriétaire : {scope.owner}")
    for target, tclass in classes.items():
        print(f"  {target:<24} {tclass.value}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    try:
        scope = load_scope(args.scope)
    except (OSError, ValueError) as exc:
        _log.error("Chargement du périmètre impossible : %s", exc)
        return 2

    max_risk = RiskLevel.PASSIVE if args.passive_only else RiskLevel.ACTIVE_SAFE
    orch = Orchestrator(scope, max_risk=max_risk)
    orch.register(InventoryPlugin())
    for plugin in discover_external_plugins():
        orch.register(plugin)

    params: dict[str, str] = {}
    for item in args.param or []:
        if "=" in item:
            k, v = item.split("=", 1)
            params[k.strip()] = v
        else:
            _log.error("paramètre ignoré (format attendu clé=valeur) : %s", item)

    result = orch.run(params)
    for err in result.errors:
        _log.error(err)
    if result.errors and not result.findings:
        return 1

    if args.format == "json":
        output = markdown.to_json(result.findings)
    else:
        output = markdown.to_markdown(result.findings)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Rapport écrit : {args.out} ({len(result.findings)} constat(s))")
    else:
        print(output)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="try-tools", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_val = sub.add_parser("validate", help="valide un fichier de périmètre")
    p_val.add_argument("scope", help="chemin du fichier scope YAML")
    p_val.set_defaults(func=_cmd_validate)

    p_run = sub.add_parser("run", help="exécute l'audit non destructif")
    p_run.add_argument("scope", help="chemin du fichier scope YAML")
    p_run.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p_run.add_argument("--out", help="fichier de sortie (sinon stdout)")
    p_run.add_argument(
        "--param",
        action="append",
        metavar="CLÉ=VALEUR",
        help="paramètre transmis aux plugins (répétable), ex. --param ports=80,443",
    )
    p_run.add_argument(
        "--passive-only",
        action="store_true",
        help="n'exécute que les plugins passifs (aucune connexion réseau)",
    )
    p_run.set_defaults(func=_cmd_run)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
