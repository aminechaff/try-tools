#!/usr/bin/env node
// cookie_check — plugin externe Try_Tools (Node.js, modules intégrés).
//
// Effectue une requête GET sur la cible et analyse les cookies renvoyés
// (en-têtes Set-Cookie) : présence des attributs Secure, HttpOnly et SameSite.
// Contrôle « actif-sûr », non intrusif. Aucune dépendance npm.
//
// Usage : node cookie_check.js <cible> [port=80] [scheme=http] [timeout_ms=4000]
// Sortie : JSON {"plugin","version","findings":[...]} sur stdout.

'use strict';

const TOOL_NAME = 'node.cookie_check';
const TOOL_VERSION = '0.0.1';

function parseArgs(argv) {
  if (argv.length < 1) {
    process.stderr.write('usage: cookie_check <cible> [clé=valeur ...]\n');
    process.exit(2);
  }
  const target = argv[0];
  const params = {};
  for (const a of argv.slice(1)) {
    const i = a.indexOf('=');
    if (i > 0) params[a.slice(0, i)] = a.slice(i + 1);
  }
  return { target, params };
}

function hostOnly(target) {
  const i = target.lastIndexOf(':');
  if (i > 0 && !target.slice(0, i).includes(':')) return target.slice(0, i);
  return target;
}

function finding(f) {
  return {
    id: f.id,
    title: f.title,
    target: f.target,
    scope_profile: 'lab-actif-sur',
    severity: f.severity,
    confidence: 'elevee',
    state: 'nouveau',
    risk_level: 'actif-sur',
    description: f.description,
    remediation: f.remediation || undefined,
    tool_name: TOOL_NAME,
    tool_version: TOOL_VERSION,
  };
}

function emit(findings) {
  process.stdout.write(
    JSON.stringify({ plugin: TOOL_NAME, version: TOOL_VERSION, findings })
  );
}

function analyseCookies(target, setCookies) {
  const findings = [];
  if (!setCookies || setCookies.length === 0) {
    findings.push(
      finding({
        id: 'web-cookie-none',
        title: 'Aucun cookie défini',
        target,
        severity: 'informationnelle',
        description: "La réponse HTTP ne définit aucun cookie.",
      })
    );
    return findings;
  }
  setCookies.forEach((raw, idx) => {
    const name = raw.split('=', 1)[0].trim();
    const lower = raw.toLowerCase();
    const missing = [];
    if (!lower.includes('secure')) missing.push('Secure');
    if (!lower.includes('httponly')) missing.push('HttpOnly');
    if (!lower.includes('samesite')) missing.push('SameSite');
    if (missing.length === 0) {
      findings.push(
        finding({
          id: `web-cookie-ok-${idx}`,
          title: `Cookie '${name}' correctement durci`,
          target,
          severity: 'informationnelle',
          description: `Le cookie '${name}' porte Secure, HttpOnly et SameSite.`,
        })
      );
    } else {
      findings.push(
        finding({
          id: `web-cookie-${idx}`,
          title: `Cookie '${name}' sans ${missing.join(', ')}`,
          target,
          severity: missing.includes('HttpOnly') ? 'moyenne' : 'faible',
          description: `Le cookie '${name}' n'a pas : ${missing.join(', ')}.`,
          remediation:
            'Ajouter les attributs manquants (Secure, HttpOnly, SameSite) à ce cookie.',
        })
      );
    }
  });
  return findings;
}

function main() {
  const { target, params } = parseArgs(process.argv.slice(2));
  const host = hostOnly(target);
  const scheme = params.scheme === 'https' ? 'https' : 'http';
  const port = parseInt(params.port, 10) || (scheme === 'https' ? 443 : 80);
  const timeout = Math.min(parseInt(params.timeout_ms, 10) || 4000, 15000);

  const lib = require(`node:${scheme}`);
  const req = lib.request(
    {
      host,
      port,
      path: '/',
      method: 'GET',
      timeout,
      rejectUnauthorized: false, // labs : certificats auto-signés tolérés
      headers: { 'User-Agent': `Try_Tools/${TOOL_VERSION}` },
    },
    (res) => {
      const set = res.headers['set-cookie'] || [];
      res.resume(); // vide le corps sans le stocker
      emit(analyseCookies(target, set));
    }
  );
  req.on('timeout', () => req.destroy(new Error('délai dépassé')));
  req.on('error', (err) => {
    emit([
      finding({
        id: 'web-cookie-noconn',
        title: 'Aucune réponse HTTP',
        target,
        severity: 'informationnelle',
        description: `Connexion impossible sur ${host}:${port} (${err.message}).`,
      }),
    ]);
  });
  req.end();
}

main();
