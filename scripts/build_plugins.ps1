# Compile les plugins externes présents sur la machine.
# Chaque toolchain absente est signalée puis ignorée (build non bloquant).
# Usage : powershell -ExecutionPolicy Bypass -File scripts/build_plugins.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$ext = Join-Path $root "plugins_ext"
$bin = Join-Path $ext "bin"
New-Item -ItemType Directory -Force -Path $bin | Out-Null

function Have($cmd) { return [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# --- Go ---
if (Have "go") {
    Write-Host "[go]   build tcp_probe..."
    Push-Location (Join-Path $ext "go")
    & go build -o (Join-Path $bin "tcp_probe.exe") .
    Pop-Location
    Write-Host "[go]   OK -> plugins_ext/bin/tcp_probe.exe"
} else {
    Write-Host "[go]   SKIP (go introuvable — voir README_PREREQUIS.md)"
}

# --- Rust ---
if (Have "rustc") {
    Write-Host "[rust] build http_headers..."
    & rustc -O (Join-Path $ext "rust\http_headers.rs") -o (Join-Path $bin "http_headers.exe")
    Write-Host "[rust] OK -> plugins_ext/bin/http_headers.exe"
} else {
    Write-Host "[rust] SKIP (rustc introuvable)"
}

# --- C ---
if (Have "gcc") {
    Write-Host "[c]    build banner_analyzer..."
    & gcc -O2 -Wall (Join-Path $ext "c\banner_analyzer.c") -o (Join-Path $bin "banner_analyzer.exe")
    Write-Host "[c]    OK -> plugins_ext/bin/banner_analyzer.exe"
} else {
    Write-Host "[c]    SKIP (gcc introuvable)"
}

# --- Node (pas de compilation) ---
if (Have "node") {
    Write-Host "[node] OK (exécuté depuis la source, aucune compilation)"
} else {
    Write-Host "[node] SKIP (node introuvable)"
}

Write-Host "`nTermine. Binaires dans plugins_ext/bin/"
