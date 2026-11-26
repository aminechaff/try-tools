/*
 * banner_analyzer — plugin externe Try_Tools (C, libc uniquement).
 *
 * Analyse HORS-LIGNE : prend une bannière de service fournie en paramètre et
 * détecte une divulgation de version (ex. "Apache/2.4.58", "OpenSSH_9.6").
 * Aucune I/O réseau. Contrôle « passif ». Sert aussi d'exercice de manipulation
 * de chaînes bornée (sécurité mémoire), conformément au README.
 *
 * Usage  : banner_analyzer <cible> banner="<texte>"
 * Sortie : JSON {"plugin","version","findings":[...]} sur stdout.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define TOOL_NAME "c.banner_analyzer"
#define TOOL_VERSION "0.0.1"
#define MAX_BANNER 2048

/* Écrit une chaîne échappée pour JSON sur le flux donné. Borné par la taille
 * de l'entrée ; aucune allocation. */
static void json_puts(FILE *out, const char *s) {
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  fputs("\\\"", out); break;
            case '\\': fputs("\\\\", out); break;
            case '\n': fputs("\\n", out);  break;
            case '\r': fputs("\\r", out);  break;
            case '\t': fputs("\\t", out);  break;
            default:
                if (c < 0x20) fprintf(out, "\\u%04x", c);
                else fputc(c, out);
        }
    }
}

/* Recherche un motif "nom/chiffres.chiffres" ou "nom_chiffres.chiffres"
 * révélant une version. Retourne 1 si trouvé. Lecture strictement bornée. */
static int has_version_disclosure(const char *b) {
    size_t n = strlen(b);
    for (size_t i = 0; i + 1 < n; ++i) {
        if ((b[i] == '/' || b[i] == '_' || b[i] == '-' || b[i] == ' ')
            && isdigit((unsigned char)b[i + 1])) {
            /* au moins chiffre '.' chiffre à la suite ? */
            size_t j = i + 1;
            int digits = 0, dot = 0;
            while (j < n && (isdigit((unsigned char)b[j]) || b[j] == '.')) {
                if (b[j] == '.') dot = 1;
                else digits++;
                j++;
            }
            if (digits >= 2 && dot) return 1;
        }
    }
    return 0;
}

static const char *get_param(int argc, char **argv, const char *key) {
    size_t klen = strlen(key);
    for (int i = 2; i < argc; ++i) {
        if (strncmp(argv[i], key, klen) == 0 && argv[i][klen] == '=')
            return argv[i] + klen + 1;
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: banner_analyzer <cible> banner=\"<texte>\"\n");
        return 2;
    }
    const char *target = argv[1];
    const char *banner = get_param(argc, argv, "banner");

    char safe[MAX_BANNER];
    if (banner) {
        /* copie bornée, toujours terminée par NUL */
        strncpy(safe, banner, MAX_BANNER - 1);
        safe[MAX_BANNER - 1] = '\0';
    } else {
        safe[0] = '\0';
    }

    FILE *out = stdout;
    fprintf(out, "{\"plugin\":\"%s\",\"version\":\"%s\",\"findings\":[",
            TOOL_NAME, TOOL_VERSION);

    if (!banner || safe[0] == '\0') {
        fprintf(out,
            "{\"id\":\"id-banner-none\",\"title\":\"Aucune bannière fournie\",\"target\":\"");
        json_puts(out, target);
        fprintf(out,
            "\",\"scope_profile\":\"lab-passif\",\"severity\":\"informationnelle\","
            "\"confidence\":\"elevee\",\"state\":\"nouveau\",\"risk_level\":\"passif\","
            "\"description\":\"Aucune bannière n'a été transmise au module (paramètre banner=).\","
            "\"tool_name\":\"%s\",\"tool_version\":\"%s\"}", TOOL_NAME, TOOL_VERSION);
    } else if (has_version_disclosure(safe)) {
        fprintf(out,
            "{\"id\":\"id-banner-version\",\"title\":\"Divulgation de version dans la bannière\",\"target\":\"");
        json_puts(out, target);
        fprintf(out,
            "\",\"scope_profile\":\"lab-passif\",\"severity\":\"faible\","
            "\"confidence\":\"moyenne\",\"state\":\"nouveau\",\"risk_level\":\"passif\","
            "\"description\":\"La bannière expose un numéro de version : ");
        json_puts(out, safe);
        fprintf(out,
            "\",\"remediation\":\"Masquer ou réduire les informations de version exposées par le service.\","
            "\"tool_name\":\"%s\",\"tool_version\":\"%s\"}", TOOL_NAME, TOOL_VERSION);
    } else {
        fprintf(out,
            "{\"id\":\"id-banner-ok\",\"title\":\"Pas de version évidente dans la bannière\",\"target\":\"");
        json_puts(out, target);
        fprintf(out,
            "\",\"scope_profile\":\"lab-passif\",\"severity\":\"informationnelle\","
            "\"confidence\":\"moyenne\",\"state\":\"nouveau\",\"risk_level\":\"passif\","
            "\"description\":\"Aucun motif de version évident détecté dans la bannière fournie.\","
            "\"tool_name\":\"%s\",\"tool_version\":\"%s\"}", TOOL_NAME, TOOL_VERSION);
    }

    fprintf(out, "]}");
    return 0;
}
