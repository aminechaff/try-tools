# Try_Tools

Un outil en ligne de commande pour regrouper des contrôles de laboratoire dans un même rapport.

Le socle est écrit en Python. Il valide une liste de cibles, sélectionne les plugins, rassemble leurs observations et supprime les doublons. Des exemples de plugins externes sont présents en C, Go, Rust et JavaScript.

## État du projet

Prototype : validation du périmètre, inventaire, interface de plugins et export Markdown/JSON sont présents. Ce n'est pas un scanner exhaustif. Un rapport sans observation ne prouve pas qu'une cible est sûre.

## Essayer le socle

Python 3.11 ou plus récent :

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\try-tools.exe validate config/examples/scope.example.yaml
.\.venv\Scripts\try-tools.exe run config/examples/scope.example.yaml --passive-only
.\.venv\Scripts\python.exe -m pytest
```

L'exemple utilise uniquement la boucle locale. Les plugins compilés ne sont pas fournis ; les scripts de compilation sont dans `scripts/`. Lancer les contrôles réseau uniquement dans son laboratoire ou sur un périmètre autorisé.

## Organisation

- `src/try_tools/core/` : orchestration et journalisation.
- `src/try_tools/plugins/` : inventaire et exécution des plugins externes.
- `src/try_tools/schemas/` : format commun des observations.
- `src/try_tools/report/` : exports.
- `tests/unit/` : tests du périmètre, de la déduplication et des composants.

La prochaine étape utile est de documenter un scénario complet avec un résultat reproductible, puis de préciser les limites de chaque contrôle.
