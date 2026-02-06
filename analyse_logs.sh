#!/bin/bash
# =============================================================================
# Script d'analyse de logs Apache/Nginx - Detection d'attaques
# Usage : ./analyse_logs.sh <fichier_log>
# =============================================================================

set -uo pipefail

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Verification des arguments
if [ $# -lt 1 ]; then
    echo -e "${RED}Usage: $0 <fichier_log>${NC}"
    exit 1
fi

LOGFILE="$1"

if [ ! -f "$LOGFILE" ]; then
    echo -e "${RED}Erreur: Le fichier '$LOGFILE' n'existe pas.${NC}"
    exit 1
fi

echo -e "${BOLD}${CYAN}"
echo "============================================================"
echo "  ANALYSE DE SECURITE - LOGS WEB"
echo "  Fichier : $LOGFILE"
echo "  Date    : $(date)"
echo "============================================================"
echo -e "${NC}"

# -------------------------------------------------------------------
# 1. INFORMATIONS GENERALES
# -------------------------------------------------------------------
echo -e "${BOLD}${GREEN}[1/10] INFORMATIONS GENERALES${NC}"
echo "------------------------------------------------------------"

TOTAL_LINES=$(wc -l < "$LOGFILE")
FILE_SIZE=$(ls -lh "$LOGFILE" | awk '{print $5}')
FIRST_DATE=$(head -1 "$LOGFILE" | awk -F'[][]' '{print $2}')
LAST_DATE=$(tail -1 "$LOGFILE" | awk -F'[][]' '{print $2}')
UNIQUE_IPS=$(awk '{print $1}' "$LOGFILE" | sort -u | wc -l | tr -d ' ')

echo "  Taille du fichier   : $FILE_SIZE"
echo "  Nombre de lignes    : $TOTAL_LINES"
echo "  Premiere entree     : $FIRST_DATE"
echo "  Derniere entree     : $LAST_DATE"
echo "  IPs uniques         : $UNIQUE_IPS"
echo ""

# -------------------------------------------------------------------
# 2. DISTRIBUTION DES CODES HTTP
# -------------------------------------------------------------------
echo -e "${BOLD}${GREEN}[2/10] DISTRIBUTION DES CODES HTTP${NC}"
echo "------------------------------------------------------------"
awk '{print $9}' "$LOGFILE" | sort | uniq -c | sort -rn | head -10 | while read count code; do
    printf "  %-8s : %s requetes\n" "$code" "$count"
done
echo ""

# -------------------------------------------------------------------
# 3. TOP 20 IPS LES PLUS ACTIVES
# -------------------------------------------------------------------
echo -e "${BOLD}${GREEN}[3/10] TOP 20 IPS LES PLUS ACTIVES${NC}"
echo "------------------------------------------------------------"
awk '{print $1}' "$LOGFILE" | sort | uniq -c | sort -rn | head -20 | while read count ip; do
    printf "  %-18s : %s requetes\n" "$ip" "$count"
done
echo ""

# -------------------------------------------------------------------
# 4. DETECTION : SCAN PHPMYADMIN
# -------------------------------------------------------------------
echo -e "${BOLD}${YELLOW}[4/10] ATTAQUE : Scan phpMyAdmin${NC}"
echo "------------------------------------------------------------"
PMA_COUNT=$(grep -ci 'phpmyadmin\|/pma\|phpmy' "$LOGFILE" || true)
echo "  Requetes detectees  : $PMA_COUNT"
echo "  Commande utilisee   : grep -ci 'phpmyadmin\|/pma\|phpmy' <logfile>"
if [ "$PMA_COUNT" -gt 0 ]; then
    echo "  IPs sources (top 5) :"
    grep -i 'phpmyadmin\|/pma\|phpmy' "$LOGFILE" | awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | while read count ip; do
        printf "    %-18s : %s requetes\n" "$ip" "$count"
    done
fi
echo ""

# -------------------------------------------------------------------
# 5. DETECTION : INJECTION DE COMMANDES / BOTNETS
# -------------------------------------------------------------------
echo -e "${BOLD}${RED}[5/10] ATTAQUE : Injection de commandes / Botnets (Mozi, Hakai)${NC}"
echo "------------------------------------------------------------"
CMD_COUNT=$(grep -ci 'setup\.cgi.*cmd\|/shell?cd\|login\.cgi.*wget\|/bin/sh\|/bin/bash\|wget[+ ]\|curl.*-O\|Mozi\.\|Hakai' "$LOGFILE" || true)
echo "  Requetes detectees  : $CMD_COUNT"
echo "  Commande utilisee   : grep -ci 'setup.cgi.*cmd|/shell?cd|login.cgi.*wget|/bin/sh|wget |Mozi.|Hakai' <logfile>"
if [ "$CMD_COUNT" -gt 0 ]; then
    echo "  Exemples :"
    grep -i 'setup\.cgi.*cmd\|/shell?cd\|login\.cgi.*wget\|Mozi\.' "$LOGFILE" | head -3 | while IFS= read -r line; do
        echo "    $line" | cut -c1-200
    done
fi
echo ""

# -------------------------------------------------------------------
# 6. DETECTION : EXPLOIT GPON ROUTER
# -------------------------------------------------------------------
echo -e "${BOLD}${RED}[6/10] ATTAQUE : Exploit GPON Router (CVE-2018-10561)${NC}"
echo "------------------------------------------------------------"
GPON_COUNT=$(grep -ci 'GponForm' "$LOGFILE" || true)
echo "  Requetes detectees  : $GPON_COUNT"
echo "  Commande utilisee   : grep -ci 'GponForm' <logfile>"
if [ "$GPON_COUNT" -gt 0 ]; then
    echo "  IPs sources (top 5) :"
    grep -i 'GponForm' "$LOGFILE" | awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | while read count ip; do
        printf "    %-18s : %s requetes\n" "$ip" "$count"
    done
fi
echo ""

# -------------------------------------------------------------------
# 7. DETECTION : BRUTE-FORCE WORDPRESS / XML-RPC
# -------------------------------------------------------------------
echo -e "${BOLD}${RED}[7/10] ATTAQUE : Brute-force WordPress / XML-RPC${NC}"
echo "------------------------------------------------------------"
WP_LOGIN=$(grep -ci 'wp-login\|wp-admin' "$LOGFILE" || true)
XMLRPC=$(grep -ci 'xmlrpc\.php' "$LOGFILE" || true)
echo "  wp-login/wp-admin   : $WP_LOGIN requetes"
echo "  xmlrpc.php          : $XMLRPC requetes"
echo "  Commande utilisee   : grep -ci 'wp-login|wp-admin' <logfile>"
echo "  IPs top attaquantes wp-login :"
grep -i 'wp-login' "$LOGFILE" | awk '{print $1}' | sort | uniq -c | sort -rn | head -5 | while read count ip; do
    printf "    %-18s : %s requetes\n" "$ip" "$count"
done
echo ""

# -------------------------------------------------------------------
# 8. DETECTION : SQL INJECTION
# -------------------------------------------------------------------
echo -e "${BOLD}${RED}[8/10] ATTAQUE : SQL Injection${NC}"
echo "------------------------------------------------------------"
SQLI_COUNT=$(grep -ci "union.*select\|select.*from\|drop.*table\|insert.*into\|or%201=1\|1=1\|information_schema" "$LOGFILE" || true)
echo "  Requetes detectees  : $SQLI_COUNT"
echo "  Commande utilisee   : grep -ci \"union.*select|select.*from|1=1|information_schema\" <logfile>"
if [ "$SQLI_COUNT" -gt 0 ]; then
    echo "  Exemples :"
    grep -i "union.*select\|1=1\|information_schema" "$LOGFILE" | head -3 | while IFS= read -r line; do
        echo "    $line" | cut -c1-200
    done
fi
echo ""

# -------------------------------------------------------------------
# 9. DETECTION : ACCES FICHIERS SENSIBLES
# -------------------------------------------------------------------
echo -e "${BOLD}${YELLOW}[9/10] ATTAQUE : Acces fichiers sensibles${NC}"
echo "------------------------------------------------------------"
SENSITIVE_COUNT=$(grep -ci '\.env\b\|wp-config\|/etc/passwd\|/etc/shadow\|\.git/\|\.htaccess\|\.htpasswd' "$LOGFILE" || true)
echo "  Requetes detectees  : $SENSITIVE_COUNT"
echo "  Commande utilisee   : grep -ci '.env|wp-config|/etc/passwd|.git/|.htaccess' <logfile>"
echo "  Detail par fichier :"
for pattern in '\.env' 'wp-config' '/etc/passwd' '\.git/' '\.htaccess'; do
    c=$(grep -ci "$pattern" "$LOGFILE" || true)
    printf "    %-20s : %s\n" "$pattern" "$c"
done
echo ""

# -------------------------------------------------------------------
# 10. DETECTION : SCANNERS AUTOMATISES
# -------------------------------------------------------------------
echo -e "${BOLD}${YELLOW}[10/10] SCANNERS ET BOTS${NC}"
echo "------------------------------------------------------------"
echo "  User-agents suspects (top 15) :"
awk -F'"' '{print $6}' "$LOGFILE" | sort | uniq -c | sort -rn | head -15 | while read count ua; do
    printf "    %8s : %s\n" "$count" "$ua"
done
echo ""
echo "  Scanners connus :"
for scanner in zgrab nmap nikto masscan censys shodan sqlmap nuclei dirbuster gobuster; do
    c=$(grep -ci "$scanner" "$LOGFILE" || true)
    if [ "$c" -gt 0 ]; then
        printf "    %-15s : %s requetes\n" "$scanner" "$c"
    fi
done
echo ""

# -------------------------------------------------------------------
# RESUME
# -------------------------------------------------------------------
echo -e "${BOLD}${CYAN}"
echo "============================================================"
echo "  RESUME"
echo "============================================================"
echo -e "${NC}"
echo "  Total lignes analysees : $TOTAL_LINES"
echo "  IPs uniques            : $UNIQUE_IPS"
echo ""
echo "  Attaques detectees :"
echo "    - Scan phpMyAdmin        : $PMA_COUNT"
echo "    - Injection de commandes : $CMD_COUNT"
echo "    - Exploit GPON           : $GPON_COUNT"
echo "    - Brute-force WordPress  : $WP_LOGIN"
echo "    - XML-RPC abuse          : $XMLRPC"
echo "    - SQL Injection          : $SQLI_COUNT"
echo "    - Fichiers sensibles     : $SENSITIVE_COUNT"
echo ""
echo -e "${GREEN}Rapport termine.${NC}"
