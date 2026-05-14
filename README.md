# 📊 MAO Log Analyzer

Analyseur de logs Apache/Nginx pour détecter les tentatives d'intrusion.

![Bash](https://img.shields.io/badge/Bash-5.0+-00ff88?style=flat-square&logo=gnubash&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Ubuntu%20%7C%20Kali-4fc3f7?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-ffb347?style=flat-square)

---

## Fonctionnalités

- **Statistiques générales** : total requêtes, codes HTTP, IPs uniques
- **Détection brute force** : IPs avec volume anormal de POST/401
- **Détection scans** : IPs générant beaucoup de 404
- **Détection injections** : SQL, XSS, LFI, RCE, outils connus (sqlmap, nikto...)
- **User-agents suspects** : identification des outils d'attaque
- **Top 10 IPs** avec visualisation par barres
- **Rapport HTML** généré automatiquement

---

## Installation

```bash
git clone https://github.com/MaoHackk/analyseur-logs.git
cd analyseur-logs
chmod +x log_analyzer.sh
```

Aucune dépendance externe — uniquement des outils Unix standards (`awk`, `grep`, `sort`, `uniq`).

---

## Utilisation

```bash
# Mode démonstration (génère un log fictif)
bash log_analyzer.sh

# Analyser un fichier de log
bash log_analyzer.sh /var/log/nginx/access.log

# Avec options
bash log_analyzer.sh access.log -o rapport.html -t 30 -s 20

# Sans rapport HTML
bash log_analyzer.sh access.log --no-html
```

---

## Options

| Option | Description | Défaut |
|--------|-------------|--------|
| `-o <fichier>` | Nom du rapport HTML | `rapport_YYYYMMDD.html` |
| `-t <n>` | Seuil brute force (req POST) | `20` |
| `-s <n>` | Seuil scan (erreurs 404) | `15` |
| `--no-html` | Désactiver le rapport HTML | — |
| `-h` | Aide | — |

---

## Exemple de sortie

```
┌─ STATISTIQUES GÉNÉRALES ─────────────────────────────
│  📊  Total requêtes              156
│  ✅  Requêtes 200 OK             80
│  ⚠️   Erreurs 404                 42
│  🚫  Erreurs 403                 12
│  🌐  IPs uniques                 6

┌─ DÉTECTION BRUTE FORCE ──────────────────────────────
│  🚨 ALERTE BRUTE FORCE
│  IP     : 185.220.101.42
│  Volume : 35 requêtes POST
│  Action : iptables -A INPUT -s 185.220.101.42 -j DROP

┌─ DÉTECTION TENTATIVES D'INJECTION ───────────────────
│  [SQL]   4 occurrence(s) détectée(s)
│    ↳ Source : 203.0.113.99
│  [SCAN]  39 occurrence(s) détectée(s)
│    ↳ Source : 45.33.32.156
```

---

## Auteur

**MaoHackk** — Étudiant L2 Informatique | Cybersécurité  
GitHub : [@MaoHackk](https://github.com/MaoHackk)
