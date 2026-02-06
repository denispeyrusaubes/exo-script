# Methodologie d'analyse de logs web - Identification des attaques

## Comment identifier des motifs d'attaque sans les connaitre au prealable ?

Lorsqu'on analyse un fichier de logs web (Apache/Nginx), on ne connait pas forcement les signatures d'attaque comme `GponForm`, `Mozi` ou `Hakai`. Voici la demarche methodique pour les decouvrir.

---

## 1. Partir de l'anomalie, pas du motif connu

La demarche commence **sans connaitre les patterns**. On cherche d'abord ce qui est **anormal** dans les logs.

### Requetes en erreur (404, 400, 403)

Les attaquants testent des chemins qui n'existent pas. Les erreurs 404 en masse revelent du scanning :

```bash
# Top des URLs qui retournent un 404
awk '$9 == 404 {print $7}' access.log | sort | uniq -c | sort -rn | head -30

# IPs qui generent le plus d'erreurs
awk '$9 == 404 || $9 == 400 {print $1}' access.log | sort | uniq -c | sort -rn | head -20
```

> En executant ces commandes, on decouvre naturellement des chemins comme `/GponForm/diag_Form`, `/setup.cgi`, `/phpmyadmin/`, etc.

### User-agents inhabituels

Les bots et scanners utilisent des user-agents reconnaissables :

```bash
# Top des user-agents
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -rn | head -30
```

> On decouvre ainsi des agents comme `Hakai/2.0`, `zgrab/0.x`, `libwww-perl`, `Go-http-client` qui sont souvent associes a des outils de scan ou des botnets.

### Requetes POST suspectes

Sur un site web classique, les POST legitimes sont limites a quelques endpoints. Les POST inhabituels sont souvent malveillants :

```bash
# Top des requetes POST
grep "POST" access.log | awk -F'"' '{print $2}' | sort | uniq -c | sort -rn | head -20
```

---

## 2. Chercher les caracteres suspects dans les URLs

Les attaques laissent des traces syntaxiques reconnaissables dans les URLs. On peut les detecter sans connaitre l'exploit specifique.

### Caracteres d'injection

```bash
# Point-virgule, pipe, quote, backtick, dollar, chevrons (injection de commandes, XSS, SQLi)
grep -i ";\||\|'\|\`\|\${\|\.\./\|<script" access.log | head -20
```

### Commandes systeme dans les URLs

```bash
# Presence de commandes shell dans les requetes
grep -i "wget\|curl\|/bin/sh\|chmod\|rm -rf\|/tmp/" access.log | head -20
```

### Encodage URL suspect

Certains caracteres sont encodes pour contourner les filtres :

| Encodage | Caractere | Utilisation |
|----------|-----------|-------------|
| `%27`    | `'`       | SQL Injection |
| `%3B`    | `;`       | Injection de commandes |
| `%3C`    | `<`       | XSS |
| `%22`    | `"`       | Injection |
| `%00`    | NULL      | Null byte injection |

```bash
# Recherche d'encodages suspects
grep '%27\|%3B\|%3C\|%22\|%00' access.log | head -20
```

### Path traversal

```bash
# Tentatives de remonter l'arborescence
grep '\.\.\/' access.log | head -20
```

---

## 3. Bases de donnees de vulnerabilites publiques

Une fois qu'on a isole un chemin suspect (ex: `/GponForm/diag_Form`), on le recherche dans les bases publiques :

| Ressource | URL | Description |
|-----------|-----|-------------|
| **CVE (MITRE)** | https://cve.mitre.org | Base officielle des vulnerabilites |
| **NVD** | https://nvd.nist.gov | Base nationale US avec scores CVSS |
| **Exploit-DB** | https://www.exploit-db.com | Base de donnees d'exploits publics |
| **OWASP Top 10** | https://owasp.org/www-project-top-ten/ | 10 categories d'attaques web les plus courantes |
| **Vulners** | https://vulners.com | Moteur de recherche multi-sources |

### Exemple concret

1. On trouve dans les logs : `POST /GponForm/diag_Form?style/`
2. Recherche Google : `GponForm diag_Form exploit`
3. Resultat : **CVE-2018-10561** et **CVE-2018-10562** - vulnerabilite d'authentification bypass + injection de commandes sur les routeurs GPON

---

## 4. Listes de signatures connues (Threat Intelligence)

Des projets open-source maintiennent des listes de patterns d'attaque pretes a l'emploi :

### ModSecurity Core Rule Set (CRS)

Le WAF open-source le plus utilise. Ses regles contiennent des milliers de regex d'attaques :

```
# Exemple de regle ModSecurity pour GPON
SecRule REQUEST_URI "@contains /GponForm/diag_Form" "id:1001,deny,status:403"

# Exemple pour Netgear RCE
SecRule REQUEST_URI "@contains /setup.cgi" "id:1002,deny,status:403"
```

- Depot : https://github.com/coreruleset/coreruleset

### Suricata / Snort

Systemes de detection d'intrusion (IDS) avec des regles de signatures reseau :

- Suricata rules : https://rules.emergingthreats.net/
- Snort rules : https://www.snort.org/downloads#rule-downloads

### Fail2ban

Outil de bannissement automatique base sur des patterns dans les logs :

- Filtres integres pour Apache, Nginx, WordPress, phpMyAdmin
- Depot : https://github.com/fail2ban/fail2ban

### YARA Rules

Signatures de malwares et patterns malveillants :

- Depot communautaire : https://github.com/Yara-Rules/rules

---

## 5. Cheatsheets et ressources d'analyse

| Ressource | Description |
|-----------|-------------|
| **SANS SEC504** | Cours "Hacker Tools, Techniques, and Incident Handling" |
| **SANS Log Analysis Cheat Sheet** | Fiches de reference pour l'analyse de logs |
| **OWASP Testing Guide** | Methodologie complete de test de securite web |
| **CyberChef** (https://gchq.github.io/CyberChef/) | Outil de decodage d'URLs, base64, hex, etc. |

---

## 6. Resume de la methodologie

```
Etape 1 : Observer les anomalies
    - Codes HTTP en erreur (404, 400, 403, 500)
    - Volumes inhabituels par IP
    - User-agents suspects
            |
            v
Etape 2 : Isoler les requetes suspectes
    - Caracteres d'injection dans les URLs (; | ' ` $ < > ..)
    - Commandes systeme (wget, curl, /bin/sh, chmod)
    - Encodage URL suspect (%27, %3B, %3C, %00)
            |
            v
Etape 3 : Identifier l'exploit
    - Rechercher le chemin/payload dans Google
    - Consulter les bases CVE, Exploit-DB, NVD
            |
            v
Etape 4 : Classifier l'attaque
    - Type : RCE, SQLi, XSS, brute-force, scanning...
    - Gravite : critique, haute, moyenne, faible
    - CVE associe si applicable
            |
            v
Etape 5 : Documenter et creer des regles de detection
    - Regles WAF (ModSecurity)
    - Filtres fail2ban
    - Alertes SIEM
```

---

## 7. Application pratique : commandes d'analyse

Le script `analyse_logs.sh` fourni dans ce repertoire automatise la detection. Voici les commandes cles qu'il utilise :

```bash
# === STATISTIQUES GENERALES ===
wc -l access.log                                              # Nombre de lignes
awk '{print $1}' access.log | sort -u | wc -l                # IPs uniques
awk '{print $9}' access.log | sort | uniq -c | sort -rn      # Codes HTTP

# === DETECTION D'ATTAQUES ===

# Scan phpMyAdmin
grep -ci 'phpmyadmin\|/pma\|phpmy' access.log

# Injection de commandes / Botnets
grep -ci 'setup\.cgi.*cmd\|/shell?cd\|login\.cgi.*wget\|/bin/sh\|wget[+ ]' access.log

# Exploit GPON Router
grep -ci 'GponForm' access.log

# Brute-force WordPress
grep -ci 'wp-login\|wp-admin' access.log
grep -ci 'xmlrpc\.php' access.log

# SQL Injection
grep -ci "union.*select\|select.*from\|1=1\|information_schema" access.log

# Acces fichiers sensibles
grep -ci '\.env\|wp-config\|/etc/passwd\|\.git/\|\.htaccess' access.log

# Scanners automatises
grep -ci 'zgrab\|nmap\|nikto\|masscan\|censys\|shodan\|sqlmap\|nuclei' access.log
```

---

## Fichiers de ce repertoire

| Fichier | Description |
|---------|-------------|
| `calt.logs` | Fichier de logs brut a analyser |
| `analyse_logs.sh` | Script bash d'analyse automatique |
| `rapport_analyse_calt.md` | Rapport complet de l'analyse de calt.logs |
| `resultat_analyse.txt` | Sortie du script d'analyse |
| `README.md` | Ce fichier (methodologie) |
