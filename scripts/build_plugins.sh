#!/usr/bin/env bash
# Compile les plugins externes présents sur la machine.
# Chaque toolchain absente est signalée puis ignorée (build non bloquant).
# Usage : bash scripts/build_plugins.sh
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXT="$ROOT/plugins_ext"
BIN="$EXT/bin"
mkdir -p "$BIN"

# Suffixe exécutable selon l'OS.
EXE=""
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }

if have go; then
  echo "[go]   build tcp_probe..."
  ( cd "$EXT/go" && go build -o "$BIN/tcp_probe$EXE" . ) && echo "[go]   OK"
else
  echo "[go]   SKIP (go introuvable — voir README_PREREQUIS.md)"
fi

if have rustc; then
  echo "[rust] build http_headers..."
  rustc -O "$EXT/rust/http_headers.rs" -o "$BIN/http_headers$EXE" && echo "[rust] OK"
else
  echo "[rust] SKIP (rustc introuvable)"
fi

if have gcc; then
  echo "[c]    build banner_analyzer..."
  gcc -O2 -Wall "$EXT/c/banner_analyzer.c" -o "$BIN/banner_analyzer$EXE" && echo "[c]    OK"
else
  echo "[c]    SKIP (gcc introuvable)"
fi

if have node; then
  echo "[node] OK (exécuté depuis la source, aucune compilation)"
else
  echo "[node] SKIP (node introuvable)"
fi

echo
echo "Termine. Binaires dans plugins_ext/bin/"
