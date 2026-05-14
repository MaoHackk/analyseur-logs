#!/bin/bash
# ============================================================
#  MAO Log Analyzer — Détection d'intrusions dans logs web
#  Auteur  : MaoHackk
#  Usage   : bash log_analyzer.sh [fichier.log] [options]
# ============================================================

# ── Couleurs ─────────────────────────────────────────────────
RED='\033[0;31m'; ORANGE='\033[0;33m'; GREEN='\033[0;32m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; PURPLE='\033[0;35m'
BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

# ── Config par défaut ────────────────────────────────────────
REPORT_HTML=1
THRESHOLD_BRUTEFORCE=20   # requêtes/min pour déclencher alerte
THRESHOLD_SCAN=15         # 404 consécutifs pour détecter un scan

# ── Banner ───────────────────────────────────────────────────
banner() {
cat << 'EOF'
  __  __    _    ___     _                    _
 |  \/  |  / \  / _ \   | |    ___   __ _   / \   _ __   __ _
 | |\/| | / _ \| | | |  | |   / _ \ / _` | / _ \ | '_ \ / _` |
 | |  | |/ ___ \ |_| |  | |__| (_) | (_| |/ ___ \| | | | (_| |
 |_|  |_/_/   \_\___/   |_____\___/ \__, /_/   \_\_| |_|\__,_|
                                     |___/
EOF
  echo -e "${DIM}          Détecteur d'intrusions — Logs Apache/Nginx — v2.0 — by MaoHackk${RESET}\n"
}

# ── Usage ────────────────────────────────────────────────────
usage() {
  echo -e "${BOLD}Usage :${RESET}"
  echo -e "  bash log_analyzer.sh <fichier.log> [options]\n"
  echo -e "${BOLD}Options :${RESET}"
  echo -e "  -o <fichier>   Exporter le rapport HTML (défaut: rapport_YYYYMMDD.html)"
  echo -e "  -t <n>         Seuil brute force (défaut: $THRESHOLD_BRUTEFORCE req/min)"
  echo -e "  -s <n>         Seuil scan (défaut: $THRESHOLD_SCAN erreurs 404)"
  echo -e "  --no-html      Ne pas générer de rapport HTML"
  echo -e "  -h             Afficher cette aide\n"
  echo -e "${BOLD}Exemple :${RESET}"
  echo -e "  bash log_analyzer.sh /var/log/nginx/access.log"
  echo -e "  bash log_analyzer.sh access.log -o rapport.html -t 30\n"
}

# ── Vérifications ────────────────────────────────────────────
check_deps() {
  local missing=()
  for cmd in awk grep sort uniq sed cut date; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo -e "${RED}✗ Dépendances manquantes : ${missing[*]}${RESET}"
    exit 1
  fi
}

# ── Section header ───────────────────────────────────────────
section() {
  echo -e "\n${BOLD}${BLUE}┌─ $1 ${RESET}${DIM}$(printf '─%.0s' $(seq 1 $((50-${#1}))))${RESET}"
}

# ── Ligne résultat ───────────────────────────────────────────
result_line() {
  local color="$1" icon="$2" label="$3" value="$4"
  printf "${color}│${RESET}  ${icon}  ${DIM}%-30s${RESET}  ${color}${BOLD}%s${RESET}\n" "$label" "$value"
}

# ── Génération de logs fictifs si aucun fichier fourni ────────
generate_demo_log() {
  local file="/tmp/demo_access.log"
  echo -e "${CYAN}ℹ Génération d'un log de démonstration...${RESET}"

  local ips=("192.168.1.10" "10.0.0.5" "172.16.0.3" "185.220.101.42" "45.33.32.156" "203.0.113.99")
  local paths=("/" "/index.html" "/admin" "/login" "/.env" "/wp-login.php"
               "/phpmyadmin" "/api/users" "/config.php" "/../../../etc/passwd"
               "/shell.php" "/backup.zip" "/.git/config" "/xmlrpc.php")
  local codes=("200" "200" "200" "404" "404" "403" "500" "301")
  local agents=("Mozilla/5.0" "sqlmap/1.7" "Nikto/2.1.6" "curl/7.68" "python-requests/2.28" "masscan")

  > "$file"
  local now=$(date +%s)

  # Trafic normal
  for i in $(seq 1 80); do
    local ip="${ips[$((RANDOM % 3))]}"
    local path="${paths[$((RANDOM % 4))]}"
    local code="${codes[$((RANDOM % 3))]}"
    local agent="${agents[0]}"
    local ts=$((now - RANDOM % 86400))
    local date_str=$(date -d "@$ts" "+%d/%b/%Y:%H:%M:%S +0000" 2>/dev/null || date -r "$ts" "+%d/%b/%Y:%H:%M:%S +0000" 2>/dev/null)
    echo "$ip - - [$date_str] \"GET $path HTTP/1.1\" $code $((RANDOM % 5000 + 100)) \"-\" \"$agent\"" >> "$file"
  done

  # Brute force SSH simulé (beaucoup de 401 depuis une même IP)
  for i in $(seq 1 35); do
    local date_str=$(date -d "@$((now - 300))" "+%d/%b/%Y:%H:%M:%S +0000" 2>/dev/null || date "+%d/%b/%Y:%H:%M:%S +0000")
    echo "185.220.101.42 - - [$date_str] \"POST /login HTTP/1.1\" 401 245 \"-\" \"python-requests/2.28\"" >> "$file"
  done

  # Scan de répertoires (plein de 404)
  for path in /admin /administrator /phpmyadmin /wp-admin /backup /.env /config /.git /shell /test /old /tmp; do
    local date_str=$(date -d "@$((now - 600))" "+%d/%b/%Y:%H:%M:%S +0000" 2>/dev/null || date "+%d/%b/%Y:%H:%M:%S +0000")
    echo "45.33.32.156 - - [$date_str] \"GET $path HTTP/1.1\" 404 153 \"-\" \"Nikto/2.1.6\"" >> "$file"
  done

  # Tentatives d'injection SQL
  for payload in "' OR 1=1--" "1; DROP TABLE users" "UNION SELECT * FROM" "../../etc/passwd"; do
    local date_str=$(date -d "@$((now - 900))" "+%d/%b/%Y:%H:%M:%S +0000" 2>/dev/null || date "+%d/%b/%Y:%H:%M:%S +0000")
    local encoded=$(echo "$payload" | sed 's/ /%20/g; s/'\''/%27/g')
    echo "203.0.113.99 - - [$date_str] \"GET /search?q=$encoded HTTP/1.1\" 200 512 \"-\" \"sqlmap/1.7\"" >> "$file"
  done

  echo "$file"
}

# ── Analyse principale ───────────────────────────────────────
analyze() {
  local logfile="$1"

  if [ ! -f "$logfile" ]; then
    echo -e "${RED}✗ Fichier introuvable : $logfile${RESET}"
    exit 1
  fi

  local total=$(wc -l < "$logfile")
  local start_time=$(date +%s%N)

  echo -e "${DIM}Analyse de : ${RESET}${CYAN}$logfile${RESET}  ${DIM}($total lignes)${RESET}"

  # ── 1. Statistiques générales ────────────────────────────
  section "STATISTIQUES GÉNÉRALES"

  local req_200=$(grep -c '" 200 ' "$logfile" 2>/dev/null || echo 0)
  local req_404=$(grep -c '" 404 ' "$logfile" 2>/dev/null || echo 0)
  local req_403=$(grep -c '" 403 ' "$logfile" 2>/dev/null || echo 0)
  local req_500=$(grep -c '" 500 ' "$logfile" 2>/dev/null || echo 0)
  local req_post=$(grep -c '"POST ' "$logfile" 2>/dev/null || echo 0)
  local uniq_ips=$(awk '{print $1}' "$logfile" | sort -u | wc -l)

  result_line "$GREEN"  "📊" "Total requêtes"        "$total"
  result_line "$GREEN"  "✅" "Requêtes 200 OK"       "$req_200"
  result_line "$ORANGE" "⚠️ " "Erreurs 404"           "$req_404"
  result_line "$RED"    "🚫" "Erreurs 403"           "$req_403"
  result_line "$RED"    "💥" "Erreurs 500"           "$req_500"
  result_line "$BLUE"   "📮" "Requêtes POST"         "$req_post"
  result_line "$CYAN"   "🌐" "IPs uniques"           "$uniq_ips"

  # ── 2. Top IPs ───────────────────────────────────────────
  section "TOP 10 IPs PAR VOLUME"
  echo -e "${BLUE}│${RESET}"
  awk '{print $1}' "$logfile" | sort | uniq -c | sort -rn | head -10 | \
  while read count ip; do
    local bar_len=$((count * 30 / $(awk '{print $1}' "$logfile" | sort | uniq -c | sort -rn | head -1 | awk '{print $1}')))
    local bar=$(printf '█%.0s' $(seq 1 $bar_len 2>/dev/null) 2>/dev/null || printf '%0.s█' $(seq 1 $bar_len))
    printf "${BLUE}│${RESET}  ${CYAN}%-18s${RESET}  ${GREEN}%s${RESET}${DIM} %d req${RESET}\n" "$ip" "$bar" "$count"
  done

  # ── 3. Détection brute force ─────────────────────────────
  section "DÉTECTION BRUTE FORCE (POST + 401/403)"
  echo -e "${BLUE}│${RESET}"

  local bf_found=0
  # IPs avec beaucoup de POST
  awk '/POST/{print $1}' "$logfile" | sort | uniq -c | sort -rn | \
  while read count ip; do
    if [ "$count" -ge "$THRESHOLD_BRUTEFORCE" ]; then
      echo -e "${BLUE}│${RESET}  ${RED}${BOLD}🚨 ALERTE BRUTE FORCE${RESET}"
      echo -e "${BLUE}│${RESET}  ${RED}IP     : $ip${RESET}"
      echo -e "${BLUE}│${RESET}  ${RED}Volume : $count requêtes POST${RESET}"
      echo -e "${BLUE}│${RESET}  ${ORANGE}Action : Bloquer avec iptables -A INPUT -s $ip -j DROP${RESET}"
      echo -e "${BLUE}│${RESET}"
      bf_found=1
    fi
  done

  # IPs avec beaucoup de 401
  grep '" 401 \|" 403 "' "$logfile" 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | \
  while read count ip; do
    if [ "$count" -ge 10 ]; then
      echo -e "${BLUE}│${RESET}  ${RED}${BOLD}🚨 AUTHENTIFICATION RÉPÉTÉE ÉCHOUÉE${RESET}"
      echo -e "${BLUE}│${RESET}  ${RED}IP     : $ip  (${count}x 401/403)${RESET}"
    fi
  done

  [ $bf_found -eq 0 ] && echo -e "${BLUE}│${RESET}  ${GREEN}✓ Aucun brute force détecté${RESET}"

  # ── 4. Scan de répertoires ───────────────────────────────
  section "DÉTECTION SCAN DE RÉPERTOIRES (404)"
  echo -e "${BLUE}│${RESET}"

  awk '/" 404 "/{print $1}' "$logfile" | sort | uniq -c | sort -rn | head -5 | \
  while read count ip; do
    if [ "$count" -ge "$THRESHOLD_SCAN" ]; then
      echo -e "${BLUE}│${RESET}  ${ORANGE}${BOLD}⚠  SCAN DÉTECTÉ${RESET}"
      echo -e "${BLUE}│${RESET}  ${ORANGE}IP     : $ip${RESET}"
      echo -e "${BLUE}│${RESET}  ${ORANGE}Volume : $count erreurs 404${RESET}"
      # Chemins tentés
      local paths=$(grep "^$ip" "$logfile" | grep '" 404 "' | awk -F'"' '{print $2}' | awk '{print $2}' | head -5 | tr '\n' ' ')
      echo -e "${BLUE}│${RESET}  ${DIM}Chemins : $paths${RESET}"
    fi
  done

  # ── 5. Détection injections ──────────────────────────────
  section "DÉTECTION TENTATIVES D'INJECTION"
  echo -e "${BLUE}│${RESET}"

  local patterns=(
    "SQL:' OR |UNION SELECT|DROP TABLE|INSERT INTO|--$|1=1"
    "XSS:<script|javascript:|onerror=|onload="
    "LFI:\.\.\/|\/etc\/passwd|\/etc\/shadow|\/proc\/self"
    "RCE:;ls |;id |;cat |;wget |;curl |;bash"
    "SCAN:nikto|sqlmap|masscan|nmap|dirbuster|gobuster"
  )

  local inject_found=0
  for pattern_entry in "${patterns[@]}"; do
    local type="${pattern_entry%%:*}"
    local regex="${pattern_entry#*:}"
    local count=$(grep -iE "$regex" "$logfile" 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
      local color="$ORANGE"
      [ "$count" -gt 10 ] && color="$RED"
      echo -e "${BLUE}│${RESET}  ${color}${BOLD}[$type]${RESET} ${color}${count} occurrence(s) détectée(s)${RESET}"
      # Montrer les IPs sources
      grep -iE "$regex" "$logfile" 2>/dev/null | awk '{print $1}' | sort -u | \
        while read ip; do echo -e "${BLUE}│${RESET}    ${DIM}↳ Source : $ip${RESET}"; done
      inject_found=1
    fi
  done
  [ $inject_found -eq 0 ] && echo -e "${BLUE}│${RESET}  ${GREEN}✓ Aucune injection détectée${RESET}"

  # ── 6. User-Agents suspects ──────────────────────────────
  section "USER-AGENTS SUSPECTS"
  echo -e "${BLUE}│${RESET}"

  local suspicious_ua="sqlmap|nikto|masscan|nmap|dirbuster|gobuster|wfuzz|hydra|medusa|burpsuite|python-requests|curl/|wget/"
  grep -iE "$suspicious_ua" "$logfile" 2>/dev/null | \
    awk -F'"' '{print $6}' | sort | uniq -c | sort -rn | head -8 | \
  while read count ua; do
    echo -e "${BLUE}│${RESET}  ${RED}[$count x]${RESET} ${ORANGE}${ua}${RESET}"
  done

  # ── 7. Chemins les plus ciblés ───────────────────────────
  section "CHEMINS LES PLUS CIBLÉS"
  echo -e "${BLUE}│${RESET}"

  awk -F'"' '{print $2}' "$logfile" | awk '{print $2}' | \
    grep -v "^$" | sort | uniq -c | sort -rn | head -10 | \
  while read count path; do
    local color="$DIM"
    echo "$path" | grep -qiE "admin|login|wp|php|env|git|config|shell|backup" && color="$ORANGE"
    echo -e "${BLUE}│${RESET}  ${color}$(printf '%-35s' "$path")${RESET}  ${CYAN}$count${RESET}"
  done

  # ── 8. Résumé final ──────────────────────────────────────
  local end_time=$(date +%s%N)
  local elapsed=$(( (end_time - start_time) / 1000000 ))

  echo -e "\n${BOLD}${GREEN}┌─────────────────────────────────────────────────────┐${RESET}"
  echo -e "${BOLD}${GREEN}│              RÉSUMÉ DE L'ANALYSE                    │${RESET}"
  echo -e "${BOLD}${GREEN}└─────────────────────────────────────────────────────┘${RESET}"

  local bf_count=$(awk '/POST/{print $1}' "$logfile" | sort | uniq -c | sort -rn | awk -v t="$THRESHOLD_BRUTEFORCE" '$1>=t' | wc -l)
  local scan_count=$(awk '/" 404 "/{print $1}' "$logfile" | sort | uniq -c | sort -rn | awk -v t="$THRESHOLD_SCAN" '$1>=t' | wc -l)
  local inject_count=$(grep -icE "'|UNION|script|\.\.\/|sqlmap|nikto" "$logfile" 2>/dev/null || echo 0)

  echo -e "  ${DIM}Durée d'analyse  :${RESET} ${CYAN}${elapsed}ms${RESET}"
  echo -e "  ${DIM}Brute force      :${RESET} $([ "$bf_count" -gt 0 ] && echo "${RED}${BOLD}$bf_count IP(s) suspecte(s)${RESET}" || echo "${GREEN}Aucun${RESET}")"
  echo -e "  ${DIM}Scans détectés   :${RESET} $([ "$scan_count" -gt 0 ] && echo "${ORANGE}${BOLD}$scan_count IP(s)${RESET}" || echo "${GREEN}Aucun${RESET}")"
  echo -e "  ${DIM}Injections       :${RESET} $([ "$inject_count" -gt 0 ] && echo "${ORANGE}${BOLD}$inject_count ligne(s)${RESET}" || echo "${GREEN}Aucune${RESET}")"

  # Rapport HTML
  if [ "$REPORT_HTML" -eq 1 ]; then
    local report_file="${OUTPUT_FILE:-rapport_$(date +%Y%m%d_%H%M%S).html}"
    generate_html_report "$logfile" "$total" "$req_200" "$req_404" "$req_403" "$uniq_ips" "$bf_count" "$scan_count" "$inject_count" "$report_file"
    echo -e "\n  ${GREEN}✓ Rapport HTML :${RESET} ${CYAN}$report_file${RESET}"
  fi

  echo ""
}

# ── Rapport HTML ─────────────────────────────────────────────
generate_html_report() {
  local logfile="$1" total="$2" r200="$3" r404="$4" r403="$5"
  local uniq_ips="$6" bf="$7" scan="$8" inject="$9" outfile="${10}"
  local now=$(date "+%d/%m/%Y à %H:%M:%S")

  local top_ips=$(awk '{print $1}' "$logfile" | sort | uniq -c | sort -rn | head -10 | \
    awk '{printf "<tr><td><code>%s</code></td><td>%s</td></tr>", $2, $1}')

  local ua_rows=$(grep -iE "sqlmap|nikto|masscan|python-requests|curl|wget|nmap|dirbuster" "$logfile" 2>/dev/null | \
    awk -F'"' '{print $6}' | sort | uniq -c | sort -rn | head -8 | \
    awk '{printf "<tr><td><code>%s</code></td><td>%s</td></tr>", substr($0, index($0,$2)), $1}')

cat > "$outfile" << HTMLEOF
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport Analyse Logs — MaoHackk</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#010409;color:#e6edf3;font-family:'Segoe UI',monospace;padding:40px}
  h1{font-size:28px;color:#00ff88;margin-bottom:4px}
  h2{font-size:16px;color:#4fc3f7;margin:28px 0 14px;border-bottom:1px solid #21262d;padding-bottom:6px}
  .meta{color:#8b949e;font-size:12px;margin-bottom:32px;font-family:monospace}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:36px}
  .stat{background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:14px;text-align:center}
  .stat-v{font-size:26px;font-weight:bold;font-family:monospace}
  .stat-l{color:#8b949e;font-size:10px;margin-top:4px}
  .alert{background:#ff444418;border:1px solid #ff4444;border-radius:8px;padding:12px 18px;margin-bottom:10px;color:#ff8888}
  .ok{background:#00ff8812;border:1px solid #00ff88;border-radius:8px;padding:12px 18px;color:#00ff88}
  table{width:100%;border-collapse:collapse;background:#0d1117;border-radius:8px;overflow:hidden;margin-bottom:24px}
  th{background:#161b22;color:#8b949e;padding:10px 14px;text-align:left;font-size:11px;text-transform:uppercase}
  td{padding:10px 14px;border-bottom:1px solid #161b22;font-size:12px}
  code{color:#4fc3f7}
  footer{color:#3d444d;font-size:11px;margin-top:40px;text-align:center;font-family:monospace}
</style>
</head>
<body>
<h1>🔎 Rapport d'Analyse de Logs</h1>
<div class="meta">Fichier : <code>$logfile</code> · Généré le $now · MAO Log Analyzer v2.0</div>
<div class="stats">
  <div class="stat"><div class="stat-v" style="color:#4fc3f7">$total</div><div class="stat-l">Requêtes</div></div>
  <div class="stat"><div class="stat-v" style="color:#00ff88">$r200</div><div class="stat-l">200 OK</div></div>
  <div class="stat"><div class="stat-v" style="color:#ffb347">$r404</div><div class="stat-l">404</div></div>
  <div class="stat"><div class="stat-v" style="color:#ff6b6b">$r403</div><div class="stat-l">403</div></div>
  <div class="stat"><div class="stat-v" style="color:#ce93d8">$uniq_ips</div><div class="stat-l">IPs uniques</div></div>
</div>
<h2>Alertes de sécurité</h2>
$([ "$bf" -gt 0 ] && echo "<div class='alert'>🚨 <strong>Brute Force</strong> — $bf IP(s) suspecte(s) détectée(s)</div>" || echo "<div class='ok'>✓ Aucun brute force détecté</div>")
$([ "$scan" -gt 0 ] && echo "<div class='alert'>⚠️  <strong>Scan de répertoires</strong> — $scan IP(s) identifiée(s)</div>" || echo "<div class='ok'>✓ Aucun scan détecté</div>")
$([ "$inject" -gt 0 ] && echo "<div class='alert'>💉 <strong>Tentatives d'injection</strong> — $inject ligne(s)</div>" || echo "<div class='ok'>✓ Aucune injection détectée</div>")
<h2>Top 10 IPs</h2>
<table><thead><tr><th>Adresse IP</th><th>Requêtes</th></tr></thead><tbody>$top_ips</tbody></table>
<h2>User-Agents suspects</h2>
<table><thead><tr><th>User-Agent</th><th>Occurrences</th></tr></thead><tbody>${ua_rows:-<tr><td colspan='2' style='color:#3d444d;text-align:center'>Aucun user-agent suspect</td></tr>}</tbody></table>
<footer>MAO Log Analyzer v2.0 — github.com/MaoHackk/analyseur-logs</footer>
</body>
</html>
HTMLEOF
}

# ── Main ─────────────────────────────────────────────────────
main() {
  check_deps
  banner

  # Parse args
  local logfile=""
  OUTPUT_FILE=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --no-html) REPORT_HTML=0 ;;
      -o) OUTPUT_FILE="$2"; shift ;;
      -t) THRESHOLD_BRUTEFORCE="$2"; shift ;;
      -s) THRESHOLD_SCAN="$2"; shift ;;
      -*) echo -e "${RED}Option inconnue : $1${RESET}"; usage; exit 1 ;;
      *) logfile="$1" ;;
    esac
    shift
  done

  if [ -z "$logfile" ]; then
    echo -e "${CYAN}ℹ Aucun fichier spécifié — mode démonstration${RESET}"
    logfile=$(generate_demo_log)
    echo ""
  fi

  analyze "$logfile"
}

main "$@"
