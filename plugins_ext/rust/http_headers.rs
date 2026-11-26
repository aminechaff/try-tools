//! http_headers — plugin externe Try_Tools (Rust, std uniquement).
//!
//! Récupère les en-têtes HTTP d'une cible (une seule requête GET /, HTTP/1.0)
//! et vérifie la présence des en-têtes de sécurité recommandés. C'est un
//! contrôle « actif-sûr », non intrusif. La réponse réseau est une donnée non
//! fiable : Rust apporte ici la sûreté mémoire du parsing (justification du
//! choix de ce langage dans le README).
//!
//! Usage : http_headers <cible> [port=80] [timeout_ms=3000]
//! Sortie : JSON {"plugin","version","findings":[...]} sur stdout.
//!
//! Aucune dépendance externe : compile avec `rustc -O http_headers.rs`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

const TOOL_NAME: &str = "rust.http_headers";
const TOOL_VERSION: &str = "0.0.1";

/// En-têtes attendus : (nom canonique, sévérité si absent).
const EXPECTED: &[(&str, &str)] = &[
    ("content-security-policy", "moyenne"),
    ("strict-transport-security", "moyenne"),
    ("x-content-type-options", "faible"),
    ("x-frame-options", "faible"),
    ("referrer-policy", "faible"),
];

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

struct Finding {
    id: String,
    title: String,
    severity: String,
    description: String,
    remediation: String,
}

fn parse_args() -> (String, HashMap<String, String>) {
    let mut args = std::env::args().skip(1);
    let target = args.next().unwrap_or_else(|| {
        eprintln!("usage: http_headers <cible> [clé=valeur ...]");
        std::process::exit(2);
    });
    let mut params = HashMap::new();
    for a in args {
        if let Some(i) = a.find('=') {
            params.insert(a[..i].to_string(), a[i + 1..].to_string());
        }
    }
    (target, params)
}

fn host_only(target: &str) -> &str {
    // Retire un éventuel :port (sans casser les IPv6 entre crochets, non gérées ici).
    match target.rfind(':') {
        Some(i) if !target[..i].contains(':') => &target[..i],
        _ => target,
    }
}

fn fetch_headers(host: &str, port: u16, timeout: Duration) -> std::io::Result<String> {
    let addr = format!("{host}:{port}");
    let sock = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "adresse introuvable"))?;
    let mut stream = TcpStream::connect_timeout(&sock, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let req = format!(
        "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Try_Tools/{TOOL_VERSION}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;

    // On ne lit que le début : les en-têtes suffisent (borné à 16 Kio).
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 16 * 1024 || buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn present_headers(raw: &str) -> Vec<String> {
    raw.lines()
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, _)| k.trim().to_ascii_lowercase())
        .collect()
}

fn main() {
    let (target, params) = parse_args();
    let host = host_only(&target).to_string();
    let port: u16 = params.get("port").and_then(|p| p.parse().ok()).unwrap_or(80);
    let timeout_ms: u64 = params
        .get("timeout_ms")
        .and_then(|p| p.parse().ok())
        .filter(|&ms| ms > 0 && ms <= 15000)
        .unwrap_or(3000);

    let mut findings: Vec<Finding> = Vec::new();

    match fetch_headers(&host, port, Duration::from_millis(timeout_ms)) {
        Ok(raw) => {
            let present = present_headers(&raw);
            for (name, sev) in EXPECTED {
                if !present.iter().any(|h| h == name) {
                    findings.push(Finding {
                        id: format!("web-hdr-{name}"),
                        title: format!("En-tête de sécurité absent : {name}"),
                        severity: sev.to_string(),
                        description: format!(
                            "La réponse HTTP ne définit pas l'en-tête '{name}'."
                        ),
                        remediation: format!(
                            "Configurer le serveur pour émettre l'en-tête '{name}'."
                        ),
                    });
                }
            }
            if findings.is_empty() {
                findings.push(Finding {
                    id: "web-hdr-ok".into(),
                    title: "En-têtes de sécurité présents".into(),
                    severity: "informationnelle".into(),
                    description: "Tous les en-têtes de sécurité vérifiés sont présents.".into(),
                    remediation: String::new(),
                });
            }
        }
        Err(e) => {
            findings.push(Finding {
                id: "web-hdr-noconn".into(),
                title: "Aucune réponse HTTP".into(),
                severity: "informationnelle".into(),
                description: format!("Connexion HTTP impossible sur {host}:{port} ({e})."),
                remediation: String::new(),
            });
        }
    }

    // Sérialisation JSON manuelle (pas de dépendance).
    let mut items = Vec::new();
    for f in &findings {
        items.push(format!(
            "{{\"id\":\"{}\",\"title\":\"{}\",\"target\":\"{}\",\"scope_profile\":\"lab-actif-sur\",\"severity\":\"{}\",\"confidence\":\"elevee\",\"state\":\"nouveau\",\"risk_level\":\"actif-sur\",\"description\":\"{}\",\"remediation\":\"{}\",\"tool_name\":\"{}\",\"tool_version\":\"{}\"}}",
            json_escape(&f.id),
            json_escape(&f.title),
            json_escape(&target),
            json_escape(&f.severity),
            json_escape(&f.description),
            json_escape(&f.remediation),
            TOOL_NAME,
            TOOL_VERSION,
        ));
    }
    println!(
        "{{\"plugin\":\"{TOOL_NAME}\",\"version\":\"{TOOL_VERSION}\",\"findings\":[{}]}}",
        items.join(",")
    );
}
