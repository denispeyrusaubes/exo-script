# Rapport d’audit de sécurité  
## Analyse des logs Apache/Nginx : Société CALT

---

## 1. Rapport d’audit : Problèmes identifiés

### Problème 1 - Exploitation active : botnets / injection de commandes

**Constat (preuves logs)**  
Les logs contiennent des requêtes typiques d’**exécution de commandes** (chaînes `wget`, `sh`, `/bin/sh`, etc.) visant des endpoints connus de routeurs/équipements vulnérables, avec des signatures associées à des botnets (ex. **Mozi**, **Hakai**). Le rapport inclut des exemples complets montrant le téléchargement + exécution d’un binaire/script malveillant (ex : `wget … Mozi.m …; sh …`).

**Pourquoi c’est plus “abouti” qu’un scan ?**  
Parce que le payload observé cherche explicitement à **télécharger** puis **exécuter** un binaire, ce qui correspond à une tentative d’infection automatisée, pas juste une exploration.

**Impact potentiel**
- Compromission de l’hôte (exécution de commandes arbitraires)  
- Déploiement de malware / botnet (persistance, rebonds réseau)  
- Exfiltration, pivot interne, dégradation de service  

**Indicateurs concrets à afficher (si relance du script)**
- Nombre total détecté + exemples de lignes (extraits)  
- Top IPs sources pour ce motif  
- *(Placeholder : sortie `analyse_logs.sh` section “[5/10] Injection de commandes / Botnets”)*

---

### Problème 2 - Exploitation active : tentative GPON (CVE-2018-10561/10562)

**Constat (preuves logs)**  
Présence de requêtes ciblant `/GponForm/diag_Form`, motif caractéristique d’exploitation de routeurs GPON (bypass auth + injection selon les variantes). Le rapport classe ce point en **critique** et le relie aux CVE **2018-10561** / **2018-10562**.

**Pourquoi c’est “abouti” / à fort risque ?**  
Parce que ce chemin n’est pas un endpoint “web classique” : il correspond à une surface d’attaque connue de firmwares/équipements, souvent exploitée à grande échelle par des bots.

**Impact potentiel**
- Exécution de commandes à distance sur l’équipement vulnérable  
- Compromission réseau (si équipement en frontal/DMZ)

**Indicateurs concrets à afficher (si relance du script)**
- Volume total de requêtes `GponForm`  
- Top IPs sources  
- *(Placeholder : sortie `analyse_logs.sh` section “[6/10] Exploit GPON Router”)*

---

### Problème 3 - Tentatives d’injection SQL (SQLi) : risque élevé d’accès non autorisé

**Constat (preuves logs)**  
Le rapport identifie des requêtes suspectes de type SQLi (motifs `union select`, `information_schema`, `1=1`, etc.) et les classe en **critique**.

**Pourquoi c’est potentiellement “abouti” ?**  
Une SQLi n’a pas besoin de “beaucoup” de requêtes : quelques hits réussis peuvent suffire à **lire/modifier** des données. Le fait de voir des motifs d’injection ne prouve pas la réussite, mais le **risque** est structurel si l’application est vulnérable.

**Impact potentiel**
- Lecture/altération de données (clients, commandes, comptes)  
- Contournement d’authentification  
- Insertion de contenu malveillant / prise de contrôle applicative  

**Indicateurs à produire (si relance du script)**
- Comptage total SQLi + 3 exemples  
- Corrélation : codes HTTP (200/302 vs 404/403) sur ces lignes  
- *(Placeholder : `analyse_logs.sh` section “[8/10] SQL Injection” + extraction des codes HTTP associés)*

---

### Problème 4 - Brute-force WordPress / abus XML-RPC : risque de compromission comptes

**Constat (preuves logs)**  
Volume très important de trafic WordPress (`wp-login`, `wp-admin`, `xmlrpc.php`). Le rapport indique environ **165 000** requêtes liées à WordPress et qualifie la gravité de **haute** (bruteforce / abus XML-RPC).

**Pourquoi ça peut “aboutir” ?**
- Bruteforce / credential stuffing = réussite possible si mots de passe faibles / réutilisés  
- XML-RPC est souvent abusé (auth bruteforce et contournements selon config)

**Impact potentiel**
- Compromission d’un compte admin  
- Déploiement de plugin backdoor, modification contenu, redirections SEO spam  

**Indicateurs à afficher (si relance du script)**
- Top IPs sur `wp-login` / `xmlrpc.php`  
- Ratio 200/302/403 sur ces endpoints (estimation réussite vs blocage)  
- *(Placeholder : `analyse_logs.sh` section “[7/10] WordPress/XML-RPC” + tri par code HTTP)*

---

### Problème 5 - Exposition/fuite : accès à fichiers sensibles (.env, wp-config, .git…)

**Constat (preuves logs)**  
Requêtes vers `.env`, `wp-config`, `.git/`, `.htaccess`, `/etc/passwd`… classées en **haute** gravité (fuite d’information).

**Pourquoi c’est à surveiller comme “abouti” ?**  
Si une seule de ces ressources répond autrement qu’en 404/403, cela peut exposer : mots de passe DB, clés API, secrets, structure applicative.

**Impact potentiel**
- Compromission de base de données via secrets exposés  
- Reconstitution de code via `.git/`  
- Escalade vers intrusion applicative  

**Indicateurs à afficher (si relance du script)**
- Détail par fichier (prévu dans le script)  
- Codes HTTP associés  
- *(Placeholder : `analyse_logs.sh` section “[9/10] fichiers sensibles”)*

---

### Concentration temporelle de l’activité suspecte

Le rapport montre que le trafic est très concentré sur **décembre 2025** et surtout **janvier 2026** (volume massif sur janvier). C’est un signal fort d’une période d’activité automatisée intense à investiguer en priorité.

---

## 2. Comment les attaques ont été trouvées ?



### 2.1 Anomalies côté serveur (codes 404/400/403/500)
- Les scans se trahissent par des volumes de 404 (tests de chemins).  
- Les 400/403/500 peuvent signaler des probes, des payloads cassés, ou des blocages WAF.

### 2.2 Signaux côté client (User-Agent)
Les scanners/bots laissent des UAs typiques : `zgrab`, `libwww-perl`, `Go-http-client`, signatures botnet, etc.

### 2.3 Signaux dans les URLs / payloads
Recherche de caractères et motifs typiques :
- Injection : `; | ' \` $ < >`  
- Commandes : `wget`, `curl`, `/bin/sh`, `rm -rf`, `/tmp/`  
- Encodages suspects : `%27`, `%3B`, `%3C` etc.

### 2.4 Attribution (CVE / Threat Intel)
Une fois un endpoint isolé (ex : `GponForm`), le mapping se fait via bases publiques (CVE/NVD/Exploit-DB) + listes de signatures (ModSecurity CRS, Suricata/Snort, fail2ban, YARA…).

---

## 3. Scripts utilisés pour l’analyse (ce qu’ils font + comment ils fonctionnent)

### 3.1 `00_check_input_and_banner.sh` - Validation des entrées + en-tête d’exécution

**But**  
Sécuriser l’exécution (fichier présent, script robuste) et afficher un en-tête clair (fichier analysé, date).

**Comment ça marche (extraits clés)**  
- Mode strict Bash : stoppe sur erreurs et variables non définies.
- Vérification d’arguments et existence du fichier.

```bash
set -uo pipefail

if [ $# -lt 1 ]; then
  echo "Usage: $0 <fichier_log>"
  exit 1
fi

LOGFILE="$1"
if [ ! -f "$LOGFILE" ]; then
  echo "Erreur: Le fichier '$LOGFILE' n'existe pas."
  exit 1
fi
```

**Sortie attendue (placeholder)**
- `Fichier : <logfile>`
- `Date : <date>`

**Point critique**
- `pipefail` évite les faux “OK” quand une commande en pipeline échoue.

---

### 3.2 `01_general_stats.sh` - Statistiques globales (volume, période, IPs uniques)

**But**  
Donner le “contexte d’audit” : taille, nombre de lignes, première/dernière entrée, nombre d’IPs uniques.

**Comment ça marche (extraits clés)**  
- `wc -l` pour le volume
- `head/tail` + extraction des dates dans `[...]`
- `awk` sur la première colonne (IP) + `sort -u` pour l’unicité

```bash
TOTAL_LINES=$(wc -l < "$LOGFILE")
FILE_SIZE=$(ls -lh "$LOGFILE" | awk '{print $5}')
FIRST_DATE=$(head -1 "$LOGFILE" | awk -F'[][]' '{print $2}')
LAST_DATE=$(tail -1 "$LOGFILE" | awk -F'[][]' '{print $2}')
UNIQUE_IPS=$(awk '{print $1}' "$LOGFILE" | sort -u | wc -l | tr -d ' ')
```

**Sortie attendue (placeholder)**
- Taille du fichier : `<...>`
- Nombre de lignes : `<...>`
- Période couverte : `<...>` → `<...>`
- IPs uniques : `<...>`

**Point critique**
- Les champs IP/date supposent un format “access log” standard ; si le format varie, il faut adapter l’extraction.

---

### 3.3 `02_http_status_top10.sh` - Distribution des codes HTTP (Top 10)

**But**  
Détecter des signaux :  
- **404** (scans / enum)  
- **403** (blocage)  
- **500** (erreurs serveur potentiellement exploitables)  
- **200/302** (réponses “utiles”, potentiellement indicatrices d’actions qui aboutissent)

**Comment ça marche (extrait clé)**  
- Le code HTTP est typiquement en colonne 9 dans beaucoup de formats.
- Comptage + tri décroissant.

```bash
awk '{print $9}' "$LOGFILE" | sort | uniq -c | sort -rn | head -10
```

**Sortie attendue (placeholder)**
- `200 : ...`
- `404 : ...`
- `403 : ...`

**Point critique**
- Le code n’est pas toujours en colonne 9 selon le format (combined/custom). À valider sur 10 lignes réelles.

---

### 3.4 `03_top_ips_20.sh` - Top 20 des IPs les plus actives

**But**  
Identifier rapidement les sources majeures de trafic (bots, scanners, IPs d’attaque).

**Comment ça marche (extrait clé)**  
- Extraction colonne 1 (IP) + comptage.

```bash
awk '{print $1}' "$LOGFILE" | sort | uniq -c | sort -rn | head -20
```

**Sortie attendue (placeholder)**
- `x.x.x.x : N requêtes`

**Point critique**
- “IP la plus active” ≠ “attaque réussie”, mais c’est un excellent pivot d’enquête.

---

### 3.5 `04_detect_phpmyadmin_scan.sh` - Détection scan phpMyAdmin

**But**  
Repérer l’énumération classique de panneaux d’admin (`/phpmyadmin`, `/pma`, etc.).

**Comment ça marche (extraits clés)**  
- Comptage global + top IPs sources si présent.

```bash
PMA_COUNT=$(grep -ci 'phpmyadmin\|/pma\|phpmy' "$LOGFILE" || true)

grep -i 'phpmyadmin\|/pma\|phpmy' "$LOGFILE"   | awk '{print $1}' | sort | uniq -c | sort -rn | head -5
```

**Sortie attendue (placeholder)**
- `Requêtes détectées : <...>`
- `Top 5 IPs : <...>`

**Point critique**
- Souvent du “scan” (fortement 404). Pour estimer l’impact : corréler avec codes HTTP.

---

### 3.6 `05_detect_cmd_injection_botnets.sh` - Détection injection de commandes / botnets (Mozi, Hakai)

**But**  
Cibler les requêtes les plus dangereuses : celles qui tentent de **télécharger/exécuter** (ex : `wget`, `/bin/sh`) ou qui matchent des signatures connues.

**Comment ça marche (extraits clés)**  
- `grep -ci` sur une expression regroupant plusieurs motifs typiques.
- Exemples limités à quelques lignes pour illustrer.

```bash
CMD_COUNT=$(grep -ci 'setup\.cgi.*cmd\|/shell?cd\|login\.cgi.*wget\|/bin/sh\|/bin/bash\|wget[+ ]\|curl.*-O\|Mozi\.\|Hakai' "$LOGFILE" || true)

grep -i 'setup\.cgi.*cmd\|/shell?cd\|login\.cgi.*wget\|Mozi\.' "$LOGFILE"   | head -3 | cut -c1-200
```

**Sortie attendue (placeholder)**
- `Requêtes détectées : <...>`
- `Exemples : <3 lignes>`

**Point critique**
- Pour statuer “abouti” : chercher des **200/302** et corréler à d’autres logs (système, applicatifs).

---

### 3.7 `06_detect_gpon_exploit.sh` - Détection exploit GPON (CVE-2018-10561/10562)

**But**  
Repérer des tentatives ciblant `GponForm` (exploitation très répandue sur équipements).

**Comment ça marche (extraits clés)**  
- Comptage + top IPs sources.

```bash
GPON_COUNT=$(grep -ci 'GponForm' "$LOGFILE" || true)

grep -i 'GponForm' "$LOGFILE"   | awk '{print $1}' | sort | uniq -c | sort -rn | head -5
```

**Sortie attendue (placeholder)**
- `Requêtes détectées : <...>`
- `Top 5 IPs : <...>`

**Point critique**
- Endpoint très spécifique : signal fort d’attaque automatisée.
- Comme toujours : codes HTTP + contexte d’infrastructure pour conclure.

---

### 3.8 `07_detect_wordpress_bruteforce.sh` - Détection WordPress / XML-RPC

**But**  
Détecter bruteforce / credential stuffing sur `wp-login`, activité admin (`wp-admin`) et abus `xmlrpc.php`.

**Comment ça marche (extraits clés)**  
- Deux compteurs distincts.
- Top IPs sur `wp-login` (pointe les botnets).

```bash
WP_LOGIN=$(grep -ci 'wp-login\|wp-admin' "$LOGFILE" || true)
XMLRPC=$(grep -ci 'xmlrpc\.php' "$LOGFILE" || true)

grep -i 'wp-login' "$LOGFILE"   | awk '{print $1}' | sort | uniq -c | sort -rn | head -5
```

**Sortie attendue (placeholder)**
- `wp-login/wp-admin : <...>`
- `xmlrpc.php : <...>`
- `Top IPs wp-login : <...>`

**Point critique**
- Pour estimer la réussite : comparer `POST /wp-login.php` et codes `200/302` vs `401/403`, et regarder des patterns de sessions.

---

### 3.9 `08_detect_sqli.sh` - Détection SQL injection (motifs connus)

**But**  
Repérer des patterns SQLi (`union select`, `information_schema`, `1=1`, etc.).

**Comment ça marche (extraits clés)**  
- Expression multi-motifs + exemples.

```bash
SQLI_COUNT=$(grep -ci "union.*select\|select.*from\|drop.*table\|insert.*into\|or%201=1\|1=1\|information_schema" "$LOGFILE" || true)

grep -i "union.*select\|1=1\|information_schema" "$LOGFILE"   | head -3 | cut -c1-200
```

**Sortie attendue (placeholder)**
- `Requêtes détectées : <...>`
- `Exemples : <...>`

**Point critique**
- “Détecté” ≠ “réussi”.  
- Pour prioriser : associer le motif SQLi à des retours `200/302` + endpoints sensibles.

---

### 3.10 `09_detect_sensitive_files.sh` - Détection accès fichiers sensibles

**But**  
Repérer les tentatives d’accès à des ressources à fort impact : `.env`, `wp-config`, `.git/`, `/etc/passwd`, etc.

**Comment ça marche (extraits clés)**  
- Comptage global + détail par motif.

```bash
SENSITIVE_COUNT=$(grep -ci '\.env\b\|wp-config\|/etc/passwd\|/etc/shadow\|\.git/\|\.htaccess\|\.htpasswd' "$LOGFILE" || true)

for pattern in '\.env' 'wp-config' '/etc/passwd' '\.git/' '\.htaccess'; do
  c=$(grep -ci "$pattern" "$LOGFILE" || true)
  printf "%-20s : %s\n" "$pattern" "$c"
done
```

**Sortie attendue (placeholder)**
- `Requêtes détectées : <...>`
- Détail par fichier : `.env : <...>`, `.git/ : <...>`, etc.

**Point critique**
- Ici, **un seul** `200` sur `.env` peut être un incident majeur.  
- À compléter par une extraction dédiée des **codes HTTP** pour ces motifs.

---

### 3.11 `10_detect_scanners_and_useragents.sh` - Scanners et user-agents suspects

**But**  
Identifier les outils de scan et botnets via User-Agent + mots-clés (“zgrab”, “nikto”, “sqlmap”, etc.).

**Comment ça marche (extraits clés)**  
- Extraction du champ User-Agent via séparation par guillemets (`"`).
- Détection de noms de scanners via `grep -ci`.

```bash
awk -F'"' '{print $6}' "$LOGFILE" | sort | uniq -c | sort -rn | head -15

for scanner in zgrab nmap nikto masscan censys shodan sqlmap nuclei dirbuster gobuster; do
  c=$(grep -ci "$scanner" "$LOGFILE" || true)
  if [ "$c" -gt 0 ]; then
    printf "%-15s : %s requetes\n" "$scanner" "$c"
  fi
done
```

**Sortie attendue (placeholder)**
- Top 15 User-Agents
- Compteurs par scanner détecté

**Point critique**
- Les UAs sont falsifiables, mais combinés aux URLs ciblées + volume, ça reste très utile.

---


## 4. Données chiffrées disponibles (issues du rapport existant)

Données déjà présentes dans `rapport_analyse_calt.md` :
- **2 384 117** lignes, **305 Mo**, période **03/May/2021 → 06/Jan/2026**, **18 117** IP uniques  
- Distribution HTTP (200 majoritaires, 404/301/302/403/500 présents)  
- Pic massif **décembre 2025 / janvier 2026**  
- Attaques listées + gravité (phpMyAdmin, Mozi/Hakai, GPON, WordPress, SQLi, fichiers sensibles, scanners…)

> Si vous voulez des chiffres “version finale audit” strictement alignés avec la sortie du script Bash, on peut poser des placeholders “Résultat du script : …” et les remplir dès que vous exportez la sortie console (`resultat_analyse.txt` par exemple).

---

## 5. Conclusion opérationnelle (pragmatique)

Priorité d’investigation (du plus critique au plus “scan”) :
1. **Injection commandes / botnets** (Mozi/Hakai) → suspicion d’exploitation active  
2. **GPON / endpoints équipements** → exploitation connue à grande échelle  
3. **SQLi** → risque direct sur les données  
4. **WordPress bruteforce/XML-RPC** → risque de compromission de comptes  
5. **Fichiers sensibles** → fuite de secrets si mauvaise configuration
