#!/usr/bin/env bash
set -euo pipefail

ROOTS=("$HOME")
SCAN_MODE="quick"
REPORT_PATH="./ShaiHulud-Scan-Report.txt"

# Wide ASCII Art Banner (for terminals >= 180 chars)
BANNER_WIDE='
     .:--.------:--:--:--:---:--:--:--:---:--:--:=-:------.--:--:---:--:--:------:--.--:--:---:--:--:------:--:--:------:--:--:------:--:--:---:--:--.=--------:=-:--:---:=-:--..
     .=##:##+*#++##=##=##=*#*+##=##=##+##*=##=##=##++#*+##:##+*#=###=##+##-##*+#*+##-##+*#+*##=##=##-*#**#*=##=##+##++##=##-##=*#+*##-##=##=##*+##+##:##+*#+*##-##+##=*##+##=##:.

                   ...:---:... .:::..   .:::.     ..::::..     :::..                    .:::.     :::....:::..   ..:::. .:::.     ..::..    .:::.  .:::::::....
                  ..*@@@@@@@+. -@@@..   :%@@-     .@@@@@:.     @@@=.                    .@@@-     @@@=..-@@@:.   .=@@%. .%@@*     .#@@+.    .#@@:. .@@@@@@@@@%-.
                  .+@@#. ..=-. -@@@:.   :%@@-    .+@@#@@%.     @@@=.                    .@@@-     @@@=..-@@@:.    =@@%. .%@@*     .#@@+.    .#@@:. .@@%:..:+@@@%:
                  .*@@%:...    -@@@:....:%@@-    .@@#.#@@+.    @@@=.                    .@@@-.....@@@=. -@@@:.    =@@%. .%@@*     .#@@+.    .#@@:. .@@%:   ..#@@*
                  .:%@@@@%+... -@@@@@@@@@@@@-  ..#@@-.-@@@.    @@@=.                    .@@@@@@@@@@@@=. -@@@:.    =@@%. .%@@*     .#@@+.    .#@@:. .@@%:     =@@%
                     .+%@@@@#. -@@@%####%@@@-  .=@@#  .*@@%..  @@@=.      -#####=.      .@@@%#####@@@=. -@@@:.    =@@%. .%@@*     .#@@+.    .#@@:. .@@%:     -@@%
                        .=@@@= -@@@:.   :%@@-  :%@@@@@@@@@@=.  @@@=.      =@@@@@*.      .@@@-     @@@=..-@@@:.   .=@@%. .%@@*     .*@@*.    .%@@:. .@@%:     #@@*
                  .=:....:@@@- -@@@..   :%@@- .*@@#=====*@@%.. @@@=.                    .@@@-     @@@=...@@@#....-@@@+. .%@@*......=@@@-....*@@%.  .@@%:...-%@@@:
                  .%@@@@@@@@=. -@@@..   :%@@- -@@@:     .#@@*. @@@=.                    .@@@-     @@@=.  .#@@@@@@@@@=.  .%@@@@@@@%..+@@@@@@@@@%..  .@@@@@@@@@@*.
                   .:=**+-:.   .-=-..   .-=-. :=-:.      .-=-. -=-..                    .-=-.     -=-..   ..-+**+-:..   .:-------:.  .:-+**=:..    .-------:.

       ....... ...... .. ...... .. ...... .. ...... .... ...... .. ... .. .. ... .. .. ... .. ...... .... ...... .. ...... .. ...... .. ...... ........... ...... .. .. ... .. ..
       +++-++-++:++==+=-++-++-++-=++=++:++-++-++=-++-++:++==+==++.++-++-+++-++-++:++==+=-++:++=++==++-++-++-=+==++-++-++-++=-++-++:++-=+==++:++-++-++=-++-++:++==+==++:++-++-=++.
....................................................................................................................................................................................
--------------------------------::::::-------------::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::...........................................................
---------------------------------:::::------------:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::..:..........................................................
----------------------------------:::::-----------:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::...............................................................
----------------------------------::::------------:-::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::............................................................
----------------------------------:::-------------::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::...:........................................................
-------------------------------:::----------------::::::::::::::::::::::::::::::::-::::::::::::::::::::::::::::::::::::.............................................................
--------------------------------------------------:::::::::::::::::::::::::::::::*#+-:::::::::::::::::::::::::::::::::..............................................................
---------------------------------------------------:::::::::::::::::::::::::::::*#%*+=:::::::::::::::::::::::::::::::::.............................................................
-------------------------------------------------:-:::::::::::::::::::::::::::*#%%#*++*-:::::::::::::::::::::::::::::::..:..........................................................
-------------------------------------------------:::::::::::::::::::::::::::::#+##+++=*+-:::::::::::::::::::::::::::::::::..........................................................
---------------------------------------------------::::::::::::::::::::::::::###%%##*+:=*=:::::::::::::::::::::::::::::::..:........................................................
-------------------------------------------------::::::::::::::::::::-::::=*+=#%%%***+=:**+=::::::::::::::::::::::::::::..:.........................................................
-------------------------------------------------::::::::::::::::::::::-=*#==%%#%%%#+=**:-+-=:::::::::::::::::::::::::::..:.........................................................
-------------------------------------------------:-:::::::::::::::::::::-=-*####%###*#=+#=:*=-=::::::::::::::::::::::::::.:.:.......................................................
-------------------------------------------------:::::::::::::::::::::::=*###*#@%*#**%#+:-::-*---:::::::::::::::::::::::::::::......................................................
-------------------------------------------------::--:::::::::::::::::-*#*****%%#**+--%#=::.:==+====+===--:.::::::::::::..::::......................................................
------------------------------------------------:::::::::::::::::::::-*****++##*-:::.-%*=-++++++++=++==+++++=-:::::::::::::.::......................................................
-------------------------------------------:-:--:::-:::::::::::::::::=*=::::+#+--*###**+++*#******#*++**++=======--::..:::..........................................................
---------------------------------------------:-::::::::::::::::::::::==::::-###%%%#***##**#%#*##########**++**+===----:..::.........................................................
------------------------------------------:--::::::::::::::::::::::::::::=#%*%####*###%%%%%%%%%%%%%%%########*+==++++===:..::.......................................................
---------------------------------------:-:-::::::::::::::::::::::::::::+%%%*#%###%##%%%@@%%%%%%%%%%%%%%%%%####****+====---:.::::..................................::.::::::.::::..::
-----------------------------------------::::::::::::::::::::::::::::+###%%%#%%##%%%%@@%%%#########%#%#%%%%%%%%%#*++++====-:...:.............................:.::::::::::::::::--==-
-------------------------------------:---:-:-::::::::::::::::::::::-#%%%#%%%##%%%%@%%%##########**######%%%%#%%%###*#*++==---:.::.:....:.......:----::::.....:::::::::::::-======++=
--------------------------------------:::::::::::::::::::::::::::*#####%%%%%%%%@@%%#####**####**###**#**#*#####%%%%##*+=====---..............-==+++=-:::::::-------===========++++++
----------------::---------------::::::::::::::::::::::::::::::-*######%%%%@@@%%%####%#**##*###*###**+***++**###%%%##**++====---:::.......:==++*++---:---------=====+==+++++==+++++=
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::-*#%%%##%%%%%%%%%%#*###%**##*#%#*###*+++++==+**##*#%%%%##**++===---:-------==++****++==--============++======+++*****+
----------:::::::::::::::::------------:---:::::::::::-------+*##%%%##%%%@@%%%%#***#%%##%######***+=+++++*###*++**#%%%%%#*++=----::-======++*******+++=-=======++=+++++====+++++++*+
==========------------------------------================--==+*####%%%#%%%%%%#%%#***#%###%######***+****#****+++=+++*#%%%##**+==----:-++++++**********+=-----====+=++++==+=====+++++=
+++++===-----------------=======+++++++++++++++++++++======**######%%%%%%#####%#***#%##%%##%%#*#***+*##*#*+++++====++#%%%%##*====----:+++++++++*++++++===++=--=++++++++++++++++++++=
=++++++++++++++++==--------====+++++++++++++++++++++++++++#**######%@@%%%#*###%%##*#%%%%%##%%####*+*####****++++====+*%%%%###*+=--=--:-=+++++++**************+==++++++++++++++++++++
++++++=======---------------=====+++++++++++++++++++====+*#**#####%%@@%%%%####%%####%%%%%#%%%##%#*#######*****+===--=+#%%%%%##*+++++=--:++++++++*******+++++++===+==+++++++++++++++=
++====------============+===============+++++++++++====++*#**#%###%%@%%%%%%%###%%#%##%%%%%%%%%%%#####%###***+++=====-=*%%%%%%###*++==--:-++===+++++++++++++===========+++++++++===+=
-----------====================================++++++++*##%####%%%%%%%%%###%%##%%%#%%%%%%%%%%%%%%%%%%%###****++=======+#%%%%%%%#**+===-:::=+++++++++++++++==========+++++++++++++++=
=+++++++++++****++==------=================+==++++++++**#%%%%###%@%%%#%%%%###%%#%%%%%%%@%@@%%%%%%%%%%%%#*#***+++=++===+*%%%%%%%###*++=--::-====+++++++++++++++++++++++++++==========
+++++++++===----:-------======++++===+++++++++++++**+*#*#%%%%%%%%@%%%###%%%%##%%%%%%%%%%@@@%%%@%%%%%%%%###***++==+++===*%%%%#%%%%##**+=-::-++++++++++++++++++++++++++++++++++++++++=
=======-------===============+++++++++++++++++++++*++#%###%%%%%@@%%%%%%###%%%%%###%%%#%%@@%%%%@%%%%%%%%%###****++=+++==+#%%%%##%%%%##*++-:-*++++++++++++++++====+++++++=========+++=
----=========================++++++++++++++++++++*++*#%%###%%%%@%%%%#%%%%%###%%%*#%#########%%@%%%%%%%%%###***++==+*+==+#%%%%%%##%@%%#*+=--+********++++++++++++++++++++++++++=====-
*******+=====+++++++++++++++++++++*****+++++++++++***#%%%###%%%%%%%%#####%%%%###*#####*******#%%%%%%%%%%%#******+++*++==*%%%%%%%%%%%%%#*+=-*#****************************+=======+++
*+++++++++++++***++++++++*+****+++++****+++******+***#%%%%%%%%%%@@%%%#############*************#%%%%%%%%%###****+++**===+#%%%%%%%%%%%%%#+=-###*#**************+**********+====*****+
******************++++++++++++++++++++++**********#####%%%@@@@%%%%%%%%###*****++++**************+**#%%%%%%##*********==++**#%%%%%%%%%%%*+==#*############***#########*****##*######*
******################***++====++++++++++++++****#%%%####%%@@@%%%%###%%%####***++********#######*#**%%%%%%%%%######**++++**+***###%%##*+==***********##############################*
#####################*****+=====+=+++++********###%%%%%##%%%%%%%%%%#***#####**+====++********#*******%%%%%%%%#####******++*##***+++++===+*******###################################*
####*****++++++++++==============+++++++*******%%%%%%@%%%%%%%%%%%%%###**++++++=======+++**************#%%%%%%##########%#++***********************#################################*
*+++****+++++++++++++++++++++++++++++++++***#*#%%%%%%%%%%%%%%%%%%%%%%%##**++===========++***************%%%%%%%%%%%%%%%%%*=****#**#***********#####################################*
**********************************************#%%%%%%%%@%%%@%%%%%###***+++=---=++=======++****************%%%#**#%%%#%%%#*=***##########**********############################%%%%%*
####################**********************#####%%%%%%%%%%%%%%%%%%%##**+++==--==+=========+****************+*####***#%###%#=*###########**##*****############################%######*
#######################*****************#####%%%%%%%%%%%%%%%%%%%%%%##***+++=+============+**************++++++#%###***###+=*##############**#******################################*
###################*******************#####%%%%%%%%%%######%%%%%%%#####**+==========+====+***********************####**++=+#####********************###############################*
#****###################*******#****#*####%%%%%%%%%%%#############****++==============-==+****###*#*#*######**#*****##****####*******************##################################*

                                          Supply Chain Malware Detection Scanner for macOS
'

# Narrow ASCII Art Banner (for terminals < 180 chars)
BANNER_NARROW='
   ___  _  _   _   ___      _  _ _   _ _    _   _ ___
  / __|| || | /_\ |_ _| ___| || | | | | |  | | | |   \
  \__ \| __ |/ _ \ | | |___| __ | |_| | |__| |_| | |) |
  |___/|_||_/_/ \_\___|    |_||_|\___/|____|\___/|___/
  .......................................................
  ---------------::-----::::::::::::::::::::::::::::::::..............
  -----------------------:::::::::::::=+:::::::::::::::.................
  -----------------------::::::::::::%#*+-::::::::::::::.................
  ----------------------::::::::::=+*#%#*+:=-::::::::::::::..............
  ----------------------:::::::::-***%*=+*:-===---::::::::...............
  -------------------:::::::::::::+#####%%%%%%%#%##**+==-::...........:.
  ------------------::::::::::::+#%%%%%%%########%#%#**+=-:::....:--::--+
  -------:::::::::::::::::::::=###%%@%##%*####*+*+*##%#*+=--:::-+*+--=+++
  --=----:-------------------+#%%#%%%%*###*###+****++*%%#+=---=++***+=+++
  +++++++==---==++++++++++++*###%%%##%###%#%##+##*++==+%%#*=---+++**+++++
  ==-----==========++++++++*##%%%%%%#%#%%%%%%%#%#**+==-#%%##+=--++++++=+=
  +++++++=---=====++=+++++*#%%%%%#%%%%%%%%@%%%%%##*+=+=+%%%%#+=:=++++====
  -============+++++++++**%#%%@%%%%#%%#####%@%%%%#**=++=%%%%%%*==**+++===
  ++++++++++++*+++**+*****#%%%%%%######******%%%%##*+++=*%%%%%#++*#**+=**
  ###########**==++++***#%##%%%%##%##++***####*%%%%%#**+**+***+=****#####
  ***+++++++++++++++***%%%%%%%%%%#*+=====+******#%%%%%%%#*####*****######
  #########*********###%%%%%%%%%#*+==+====+*******##**%##*######***######
  ########*********##%%%%%##%####*+=======+**********##*+*#*********#####

            Supply Chain Malware Detection Scanner
'

# Function to print banner based on terminal width
print_banner() {
  local term_width=80
  if command -v tput >/dev/null 2>&1; then
    term_width=$(tput cols 2>/dev/null || echo 80)
  elif [[ -n "${COLUMNS:-}" ]]; then
    term_width="$COLUMNS"
  fi

  echo ""
  if [[ "$term_width" -ge 180 ]]; then
    echo -e "\033[33m${BANNER_WIDE}\033[0m"
  else
    echo -e "\033[33m${BANNER_NARROW}\033[0m"
  fi
}

usage() {
  cat <<'EOF'
Usage: Check-ShaiHulud-Dynamic-macOS.sh [options]
  -r, --roots "path1,path2"   Comma-separated root paths to scan (default: $HOME)
  -m, --mode  quick|full      Scan mode (default: quick)
  -o, --report FILE           Report output path (default: ./ShaiHulud-Scan-Report.txt)
  -h, --help                  Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--roots) IFS=',' read -r -a ROOTS <<<"$2"; shift 2;;
    -m|--mode) SCAN_MODE="$(echo "$2" | tr '[:upper:]' '[:lower:]')"; shift 2;;
    -o|--report) REPORT_PATH="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) ROOTS+=("$1"); shift;;
  esac
done

if [[ "$SCAN_MODE" != "quick" && "$SCAN_MODE" != "full" ]]; then
  echo "Invalid mode: $SCAN_MODE (use quick or full)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_FILE="$SCRIPT_DIR/compromised-packages-cache.txt"

PACKAGE_FEED_URLS=(
  "https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/refs/heads/main/compromised-packages.txt"
)

MALICIOUS_FILES=(
  "shai-hulud.js" "shai_hulud.js"
  "shai-hulud-workflow.yml" "shai_hulud_workflow.yml"
  "shai-hulud.yml" "shai_hulud.yml"
  "setup_bun.js" "bun_environment.js" "discussion.yaml"
  "truffleSecrets.json" "actionsSecrets.json"
)

SUSPICIOUS_BRANCH_PATTERNS=("shai-hulud" "shai_hulud" "SHA1HULUD")
SUSPICIOUS_WORKFLOW_PATTERNS=("self-hosted" "SHA1HULUD" "shai-hulud" "shai_hulud" "webhook.site" "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7")
CLOUD_CREDENTIAL_PATHS=(".aws/credentials" ".aws/config" ".azure/" ".npmrc" ".env")
SUSPICIOUS_HOOK_PATTERNS=("curl " "wget " "node -e" "eval(" "base64" "webhook" "exfil" "/tmp/" "\\temp\\" "powershell" "cmd /c")
SUSPICIOUS_NAMES=("bundle.js" "setup_bun.js" "bun_environment.js" "shai-hulud.js" "shai_hulud.js")

# Hash checking functions (compatible with bash 3.2)
check_mal_sha256() {
  local hash="$1"
  case "$hash" in
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09")
      echo "Shai-Hulud bundle.js payload"
      return 0
      ;;
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777")
      echo "Shai-Hulud malicious file"
      return 0
      ;;
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c")
      echo "Shai-Hulud malicious file"
      return 0
      ;;
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db")
      echo "Shai-Hulud malicious file"
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

check_mal_sha1() {
  local hash="$1"
  case "$hash" in
    "d1829b4708126dcc7bea7437c04d1f10eacd4a16")
      echo "setup_bun.js (Shai-Hulud 2.0)"
      return 0
      ;;
    "d60ec97eea19fffb4809bc35b91033b52490ca11")
      echo "bun_environment.js (Shai-Hulud 2.0)"
      return 0
      ;;
    "3d7570d14d34b0ba137d502f042b27b0f37a59fa")
      echo "bun_environment.js variant (Shai-Hulud 2.0)"
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

FINDING_LIST=()

log_section() { echo; echo "---- $1 ----"; }
add_finding() {
  local type="$1" indicator="$2" location="$3"
  FINDING_LIST+=("$type|$indicator|$location")
}

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

escape_regex() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\./\\.}"; s="${s//\*/\\*}"; s="${s//\+/\\+}"
  s="${s//\?/\\?}"; s="${s//\^/\\^}"; s="${s//\$/\\$}"; s="${s//\[/\\[}"
  s="${s//\]/\\]}"; s="${s//\(/\\(}"; s="${s//\)/\\)}"; s="${s//\{/\\{}"
  s="${s//\}/\\}}"; s="${s//\|/\\|}"; s="${s//\//\\/}"
  s="${s//:/[:_-]}"
  printf '%s' "$s"
}

COMP_UNSCOPED=()
COMP_SCOPED=()
COMP_SCOPES=()
COMPROMISED_REGEX=""

# Helper functions for checking compromised packages (bash 3.2 compatible)
is_compromised_unscoped() {
  local pkg="$1"
  local item
  if [ ${#COMP_UNSCOPED[@]} -eq 0 ]; then
    return 1
  fi
  for item in "${COMP_UNSCOPED[@]}"; do
    if [ "$item" = "$pkg" ]; then
      return 0
    fi
  done
  return 1
}

is_compromised_scoped() {
  local scope="$1"
  local name="$2"
  local key="$scope|$name"
  local item
  if [ ${#COMP_SCOPED[@]} -eq 0 ]; then
    return 1
  fi
  for item in "${COMP_SCOPED[@]}"; do
    if [ "$item" = "$key" ]; then
      return 0
    fi
  done
  return 1
}

has_compromised_scope() {
  local scope="$1"
  local item
  if [ ${#COMP_SCOPES[@]} -eq 0 ]; then
    return 1
  fi
  for item in "${COMP_SCOPES[@]}"; do
    if [ "$item" = "$scope" ]; then
      return 0
    fi
  done
  return 1
}

load_compromised_packages() {
  local loaded=0
  local tmpfile
  tmpfile="$(mktemp)"
  for url in "${PACKAGE_FEED_URLS[@]}"; do
    echo "[*] Fetching compromised package list from: $url"
    if curl -fsSL --max-time 30 "$url" >>"$tmpfile"; then
      loaded=1
    else
      echo "[!] Failed to fetch $url" >&2
    fi
  done

  if [[ $loaded -eq 0 && -f "$CACHE_FILE" ]]; then
    echo "[*] Using cached compromised package snapshot: $CACHE_FILE"
    cat "$CACHE_FILE" >"$tmpfile"
  fi

  if [[ ! -s "$tmpfile" ]]; then
    rm -f "$tmpfile"
    return
  fi

  >"$CACHE_FILE"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(trim "$line")"
    [[ -z "$line" ]] && continue
    local token="${line%%[ ,;|]*}"
    token="$(trim "$token")"
    [[ -z "$token" ]] && continue
    echo "$token" >>"$CACHE_FILE"
    if [[ "$token" == @*/* ]]; then
      local scope="${token%%/*}"
      local name="${token#*/}"
      local key="$scope|$name"
      # Add to scoped list if not already present
      local found=0
      local item
      if [ ${#COMP_SCOPED[@]} -gt 0 ]; then
        for item in "${COMP_SCOPED[@]}"; do
          if [ "$item" = "$key" ]; then
            found=1
            break
          fi
        done
      fi
      if [ $found -eq 0 ]; then
        COMP_SCOPED+=("$key")
      fi
      # Add to scopes list if not already present
      found=0
      if [ ${#COMP_SCOPES[@]} -gt 0 ]; then
        for item in "${COMP_SCOPES[@]}"; do
          if [ "$item" = "$scope" ]; then
            found=1
            break
          fi
        done
      fi
      if [ $found -eq 0 ]; then
        COMP_SCOPES+=("$scope")
      fi
    else
      # Add to unscoped list if not already present
      local found=0
      local item
      if [ ${#COMP_UNSCOPED[@]} -gt 0 ]; then
        for item in "${COMP_UNSCOPED[@]}"; do
          if [ "$item" = "$token" ]; then
            found=1
            break
          fi
        done
      fi
      if [ $found -eq 0 ]; then
        COMP_UNSCOPED+=("$token")
      fi
    fi
  done <"$tmpfile"
  rm -f "$tmpfile"

  local patterns=()
  local pkg
  if [ ${#COMP_UNSCOPED[@]} -gt 0 ]; then
    for pkg in "${COMP_UNSCOPED[@]}"; do
      patterns+=("$(escape_regex "$pkg")")
    done
  fi
  local key
  if [ ${#COMP_SCOPED[@]} -gt 0 ]; then
    for key in "${COMP_SCOPED[@]}"; do
      local scope="${key%%|*}"; local name="${key#*|}"
      patterns+=("$(escape_regex "$scope/$name")")
    done
  fi
  if [[ ${#patterns[@]} -gt 0 ]]; then
    COMPROMISED_REGEX="(${patterns[*]// /|})"
  fi
  echo "[*] Total unique compromised package identifiers loaded: $(( ${#COMP_UNSCOPED[@]} + ${#COMP_SCOPED[@]} ))"
}

find_node_modules() {
  local mode="$1"; shift
  local -a dirs=()
  for root in "$@"; do
    [[ -d "$root" ]] || { echo "[!] Root path not found: $root" >&2; continue; }
    if [[ "$mode" == "quick" ]]; then
      [[ -d "$root/node_modules" ]] && dirs+=("$root/node_modules")
      for sub in "$root"/*; do
        [[ -d "$sub" && -d "$sub/node_modules" ]] && dirs+=("$sub/node_modules")
      done
    else
      while IFS= read -r -d '' d; do dirs+=("$d"); done < <(find "$root" -type d -name node_modules -print0 2>/dev/null)
    fi
  done
  printf '%s\n' "${dirs[@]}" | sort -u
}

scan_node_modules() {
  local nm_dirs=("$@")
  for nm in "${nm_dirs[@]}"; do
    [[ -d "$nm" ]] || continue
    while IFS= read -r -d '' child; do
      local name
      name="$(basename "$child")"
      if [[ "$name" == @* ]]; then
        has_compromised_scope "$name" || continue
        while IFS= read -r -d '' pkgdir; do
          local pkgname
          pkgname="$(basename "$pkgdir")"
          if is_compromised_scoped "$name" "$pkgname"; then
            add_finding "node_modules" "$name/$pkgname" "$pkgdir"
            echo "    [!] FOUND: $name/$pkgname at $nm"
          fi
        done < <(find "$child" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
      else
        if is_compromised_unscoped "$name"; then
          add_finding "node_modules" "$name" "$child"
          echo "    [!] FOUND: $name at $nm"
        fi
      fi
    done < <(find "$nm" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
  done
}

scan_npm_cache() {
  local cache_path="$1"
  [[ -n "$cache_path" && -d "$cache_path" ]] || { echo "[*] npm cache path not detected."; return; }
  [[ -z "$COMPROMISED_REGEX" ]] && return
  echo "[*] Scanning npm cache at: $cache_path"
  while IFS= read -r -d '' dir; do
    if [[ "$dir" =~ $COMPROMISED_REGEX ]]; then
      add_finding "npm-cache" "${BASH_REMATCH[0]}" "$dir"
      echo "    [!] FOUND in cache: ${BASH_REMATCH[0]}"
    fi
  done < <(find "$cache_path" -type d -print0 2>/dev/null)
}

scan_malicious_files() {
  local mode="$1"; shift
  local roots=("$@")
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    if [[ "$mode" == "quick" ]]; then
      for f in "${MALICIOUS_FILES[@]}"; do
        [[ -f "$root/$f" ]] && { add_finding "file-artefact" "$f" "$root/$f"; echo "    [!] FOUND: $f at $root"; }
        if [[ -d "$root/.github/workflows" && -f "$root/.github/workflows/$f" ]]; then
          add_finding "file-artefact" "$f" "$root/.github/workflows/$f"
          echo "    [!] FOUND: $f at $root/.github/workflows"
        fi
      done
    else
      while IFS= read -r -d '' fpath; do
        add_finding "file-artefact" "$(basename "$fpath")" "$fpath"
        echo "    [!] FOUND: $(basename "$fpath") at $(dirname "$fpath")"
      done < <(find "$root" -type f \( $(printf -- '-name %q -o ' "${MALICIOUS_FILES[@]}") -false \) -print0 2>/dev/null)
    fi
  done
}

scan_git() {
  local mode="$1"; shift
  local roots=("$@")
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    if [[ "$mode" == "quick" ]]; then
      local candidates=()
      [[ -d "$root/.git" ]] && candidates+=("$root/.git")
      local count=0
      for sub in "$root"/*; do
        [[ -d "$sub/.git" ]] && candidates+=("$sub/.git")
        ((count++)); [[ $count -ge 20 ]] && break
      done
      if [ ${#candidates[@]} -gt 0 ]; then
        for gitdir in "${candidates[@]}"; do
        local repo
        repo="$(dirname "$gitdir")"
        branches=$(git -C "$repo" branch -a 2>/dev/null || true)
        remotes=$(git -C "$repo" remote -v 2>/dev/null || true)
        for b in $branches; do
          for pat in "${SUSPICIOUS_BRANCH_PATTERNS[@]}"; do
            if [[ "$b" == *"$pat"* ]]; then
              add_finding "git-branch" "Branch: $b" "$repo"
            fi
          done
        done
        if [[ "$remotes" == *"Shai-Hulud"* ]]; then
          add_finding "git-remote" "Remote contains 'Shai-Hulud'" "$repo"
        fi
        done
      fi
    else
      while IFS= read -r -d '' gitdir; do
        local repo
        repo="$(dirname "$gitdir")"
        branches=$(git -C "$repo" branch -a 2>/dev/null || true)
        remotes=$(git -C "$repo" remote -v 2>/dev/null || true)
        for b in $branches; do
          for pat in "${SUSPICIOUS_BRANCH_PATTERNS[@]}"; do
            if [[ "$b" == *"$pat"* ]]; then
              add_finding "git-branch" "Branch: $b" "$repo"
            fi
          done
        done
        if [[ "$remotes" == *"Shai-Hulud"* ]]; then
          add_finding "git-remote" "Remote contains 'Shai-Hulud'" "$repo"
        fi
      done < <(find "$root" -type d -name .git -print0 2>/dev/null)
    fi
  done
}

scan_workflows() {
  local roots=("$@")
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    while IFS= read -r -d '' wfdir; do
      while IFS= read -r -d '' wf; do
        local base
        base="$(basename "$wf")"
        if [[ "$base" =~ ^formatter_[0-9]+\.yml$ ]]; then
          add_finding "workflow-pattern" "Suspicious workflow name: $base" "$wf"
          echo "    [!] SUSPICIOUS workflow: $wf"
        fi
        local content
        content="$(cat "$wf" 2>/dev/null || true)"
        for pat in "${SUSPICIOUS_WORKFLOW_PATTERNS[@]}"; do
          if [[ "$content" == *"$pat"* ]]; then
            add_finding "workflow-content" "Workflow contains: $pat" "$wf"
            break
          fi
        done
      done < <(find "$wfdir" -maxdepth 1 -type f \( -name "*.yml" -o -name "*.yaml" \) -print0 2>/dev/null)
    done < <(find "$root" -type d -path "*/.github/workflows" -print0 2>/dev/null)
  done
}

scan_credentials() {
  local mode="$1"; shift
  local roots=("$@")
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    for cred in "${CLOUD_CREDENTIAL_PATHS[@]}"; do
      local path="$root/$cred"
      if [[ -e "$path" ]]; then
        add_finding "credential-file" "$cred" "$path"
      fi
    done
    if [[ "$mode" == "full" ]]; then
      while IFS= read -r -d '' envfile; do
        add_finding "credential-file" ".env file" "$envfile"
      done < <(find "$root" -type f -name ".env*" ! -path "*/node_modules/*" -print0 2>/dev/null)
    else
      [[ -f "$root/.env" ]] && add_finding "credential-file" ".env file" "$root/.env"
    fi
  done
}

scan_runners() {
  local roots=("$@")
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    while IFS= read -r -d '' dir; do
      local runner="$dir/.runner"
      if [[ -f "$runner" ]]; then
        if grep -q "SHA1HULUD" "$runner" 2>/dev/null; then
          add_finding "malicious-runner" "Malicious self-hosted runner 'SHA1HULUD'" "$dir"
          echo "    [!] CRITICAL: Malicious runner at $dir"
        else
          add_finding "runner-installation" "Self-hosted runner installation (verify legitimacy)" "$dir"
        fi
      fi
    done < <(find "$root" -type d \( -name "actions-runner" -o -name "_work" -o -name "*runner*" \) -print0 2>/dev/null)
  done
}

scan_hooks() {
  local mode="$1"; shift
  local roots=("$@")
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    if [[ "$mode" == "quick" ]]; then
      local pkg="$root/package.json"
      [[ -f "$pkg" ]] || continue
      while IFS='|' read -r hook pat; do
        [[ -z "$hook" ]] && continue
        add_finding "postinstall-hook" "Suspicious $hook: $pat" "$pkg"
      done <<<"$(python3 - "$pkg" "${SUSPICIOUS_HOOK_PATTERNS[@]}" 2>/dev/null <<'PY'
import json, sys
pkg = sys.argv[1]
pats = sys.argv[2:]
try:
    data = json.load(open(pkg, "r", encoding="utf-8"))
except Exception:
    sys.exit(0)
scripts = data.get("scripts") or {}
for hook in ("postinstall","preinstall","install","prepare"):
    val = scripts.get(hook)
    if not isinstance(val, str):
        continue
    for pat in pats:
        if pat in val:
            print(f"{hook}|{pat}")
            sys.exit(0)
PY
)"
    else
      while IFS= read -r -d '' pkg; do
        while IFS='|' read -r hook pat; do
          [[ -z "$hook" ]] && continue
          add_finding "postinstall-hook" "Suspicious $hook: $pat" "$pkg"
        done <<<"$(python3 - "$pkg" "${SUSPICIOUS_HOOK_PATTERNS[@]}" 2>/dev/null <<'PY'
import json, sys, pathlib
pkg = pathlib.Path(sys.argv[1])
pats = sys.argv[2:]
try:
    data = json.load(open(pkg, "r", encoding="utf-8"))
except Exception:
    sys.exit(0)
scripts = data.get("scripts") or {}
for hook in ("postinstall","preinstall","install","prepare"):
    val = scripts.get(hook)
    if not isinstance(val, str):
        continue
    for pat in pats:
        if pat in val:
            print(f"{hook}|{pat}")
            sys.exit(0)
PY
)"
      done < <(find "$root" -type f -name "package.json" ! -path "*/node_modules/*/node_modules/*" -print0 2>/dev/null)
    fi
  done
}

scan_hashes() {
  local mode="$1"; shift
  local roots=("$@")
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    if [[ "$mode" == "quick" ]]; then
      while IFS= read -r -d '' file; do
        local sha256
        sha256=$(shasum -a 256 "$file" 2>/dev/null | awk '{print $1}')
        local desc
        if desc=$(check_mal_sha256 "$sha256"); then
          add_finding "malware-hash" "SHA256 match: $desc" "$file"
          echo "    [!!!] MALWARE DETECTED: $file"
          continue
        fi
        local sha1
        sha1=$(shasum -a 1 "$file" 2>/dev/null | awk '{print $1}')
        if desc=$(check_mal_sha1 "$sha1"); then
          add_finding "malware-hash" "SHA1 match: $desc" "$file"
          echo "    [!!!] MALWARE DETECTED: $file"
        fi
      done < <(find "$root" \( -path "*/node_modules/*/node_modules/*" -prune \) -o -type f \( $(printf -- '-name %q -o ' "${SUSPICIOUS_NAMES[@]}") -false \) -print0 2>/dev/null)
    else
      while IFS= read -r -d '' file; do
        local sha256
        sha256=$(shasum -a 256 "$file" 2>/dev/null | awk '{print $1}')
        local desc
        if desc=$(check_mal_sha256 "$sha256"); then
          add_finding "malware-hash" "SHA256 match: $desc" "$file"
          echo "    [!!!] MALWARE DETECTED: $file"
          continue
        fi
        local sha1
        sha1=$(shasum -a 1 "$file" 2>/dev/null | awk '{print $1}')
        if desc=$(check_mal_sha1 "$sha1"); then
          add_finding "malware-hash" "SHA1 match: $desc" "$file"
          echo "    [!!!] MALWARE DETECTED: $file"
        fi
      done < <(find "$root" \( -path "*/node_modules/*" -o -name "*.d.ts" \) -prune -false -o -type f \( -name "*.js" -o -name "*.ts" \) -print0 2>/dev/null)
    fi
  done
}

scan_migration_suffix() {
  local roots=("$@")
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    while IFS= read -r -d '' gitdir; do
      local repo
      repo="$(dirname "$gitdir")"
      remotes=$(git -C "$repo" remote -v 2>/dev/null || true)
      if echo "$remotes" | grep -qi "\-migration"; then
        add_finding "migration-attack" "Remote URL contains '-migration'" "$repo"
      fi
    done < <(find "$root" -type d -name .git -print0 2>/dev/null)
    while IFS= read -r -d '' dir; do
      add_finding "migration-attack" "Directory ends with -migration" "$dir"
    done < <(find "$root" -type d -name "*-migration" -print0 2>/dev/null)
  done
}

scan_trufflehog() {
  local mode="$1"; shift
  local roots=("$@")
  if command -v trufflehog >/dev/null 2>&1; then
    add_finding "trufflehog-installation" "TruffleHog in PATH" "$(command -v trufflehog)"
  fi
  if [[ "$mode" == "full" ]]; then
    for root in "${roots[@]}"; do
      [[ -d "$root" ]] || continue
      while IFS= read -r -d '' tf; do
        add_finding "trufflehog-installation" "TruffleHog binary" "$tf"
      done < <(find "$root" -type f -regex ".*trufflehog(\.exe)?$" -print0 2>/dev/null)
      while IFS= read -r -d '' pkg; do
        if grep -qi "trufflehog" "$pkg" 2>/dev/null; then
          add_finding "trufflehog-reference" "package.json references trufflehog" "$pkg"
        fi
      done < <(find "$root" -type f -name "package.json" ! -path "*/node_modules/*/node_modules/*" -print0 2>/dev/null)
    done
  fi
}

scan_env_patterns() {
  local roots=("$@")
  local env_regex='process\.env|os\.environ|\$env:|AWS_ACCESS_KEY|AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN|GH_TOKEN|AZURE_'
  local exfil_regex='webhook\.site|bb8ca5f6-4175-45d2-b042-fc9ebb8170b7|exfiltrat|fetch\s*\(|axios\.|http\.request|https\.request'
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue
    while IFS= read -r -d '' file; do
      content="$(cat "$file" 2>/dev/null || true)"
      [[ -z "$content" ]] && continue
      if echo "$content" | grep -Eiq "$env_regex" && echo "$content" | grep -Eiq "$exfil_regex"; then
        add_finding "env-exfil-pattern" "Env access + exfil pattern" "$file"
        echo "    [!] SUSPICIOUS env+exfil: $file"
      fi
    done < <(find "$root" \( -path "*/node_modules/*" -o -name "*.d.ts" \) -prune -false -o -type f \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.sh" -o -name "*.ps1" \) -print0 2>/dev/null)
  done
}

main() {
  local start_ts
  start_ts=$(date +%s)

  print_banner
  echo ""
  echo "============================================"
  echo " Shai-Hulud Dynamic Detection (macOS)"
  echo "============================================"
  echo "[*] Scan Mode: $(echo "$SCAN_MODE" | tr '[:lower:]' '[:upper:]')"
  echo ""

  log_section "Loading compromised package lists"
  load_compromised_packages
  if [[ ${#COMP_UNSCOPED[@]} -eq 0 && ${#COMP_SCOPED[@]} -eq 0 ]]; then
    echo "[!] No compromised packages loaded. Package-based checks will be limited."
  fi

  log_section "Finding node_modules directories"
  NM_DIRS=()
  while IFS= read -r line; do
    NM_DIRS+=("$line")
  done < <(find_node_modules "$SCAN_MODE" "${ROOTS[@]}")
  echo "[*] Found ${#NM_DIRS[@]} node_modules directories."

  local npm_cache=""
  if [[ "$SCAN_MODE" == "full" ]]; then
    if npm_cmd=$(command -v npm 2>/dev/null); then
      npm_cache="$(npm config get cache 2>/dev/null || true)"
    fi
    [[ -z "$npm_cache" ]] && npm_cache="$HOME/.npm"
  fi

  log_section "Scanning for malicious packages in node_modules"
  if [[ ${#NM_DIRS[@]} -gt 0 && ( ${#COMP_UNSCOPED[@]} -gt 0 || ${#COMP_SCOPED[@]} -gt 0 ) ]]; then
    scan_node_modules "${NM_DIRS[@]}"
  else
    echo "[-] Skipping node_modules package scan (no packages or dirs)."
  fi

  if [[ "$SCAN_MODE" == "full" ]]; then
    log_section "Scanning npm cache for compromised packages"
    if [[ -n "$npm_cache" ]]; then
      scan_npm_cache "$npm_cache"
    else
      echo "[-] Skipping npm cache scan (no cache path)."
    fi
  else
    echo "[Quick] Skipping npm cache scan (use --mode full)"
  fi

  log_section "Scanning for known Shai-Hulud artefact files"
  scan_malicious_files "$SCAN_MODE" "${ROOTS[@]}"

  log_section "Scanning for suspicious git branches and remotes"
  scan_git "$SCAN_MODE" "${ROOTS[@]}"

  log_section "Scanning GitHub Actions workflows"
  scan_workflows "${ROOTS[@]}"

  log_section "Checking cloud credential files"
  scan_credentials "$SCAN_MODE" "${ROOTS[@]}"

  if [[ "$SCAN_MODE" == "full" ]]; then
    log_section "Checking for self-hosted runners"
    scan_runners "${ROOTS[@]}"
  else
    echo "[Quick] Skipping self-hosted runner scan (use --mode full)"
  fi

  log_section "Scanning postinstall hooks"
  scan_hooks "$SCAN_MODE" "${ROOTS[@]}"

  log_section "Hash-based malware detection"
  scan_hashes "$SCAN_MODE" "${ROOTS[@]}"

  if [[ "$SCAN_MODE" == "full" ]]; then
    log_section "Checking for migration suffix attack"
    scan_migration_suffix "${ROOTS[@]}"
  else
    echo "[Quick] Skipping migration suffix scan (use --mode full)"
  fi

  log_section "Checking for TruffleHog installation"
  scan_trufflehog "$SCAN_MODE" "${ROOTS[@]}"

  if [[ "$SCAN_MODE" == "full" ]]; then
    log_section "Scanning for suspicious env+exfil patterns"
    scan_env_patterns "${ROOTS[@]}"
  else
    echo "[Quick] Skipping env+exfil pattern scan (use --mode full)"
  fi

  local end_ts
  end_ts=$(date +%s)
  local duration=$(( end_ts - start_ts ))

  log_section "Summary"
  echo "[*] Scan completed in ${duration}s (${SCAN_MODE^^} mode)"
  if [[ ${#FINDING_LIST[@]} -eq 0 ]]; then
    echo "[OK] No indicators of Shai-Hulud compromise were found in the scanned locations."
  else
    echo "[!!!] POTENTIAL INDICATORS OF COMPROMISE FOUND: ${#FINDING_LIST[@]} item(s)"
    for f in "${FINDING_LIST[@]}"; do
      IFS='|' read -r t ind loc <<<"$f"
      printf "%-18s %-40s %s\n" "$t" "$ind" "$loc"
    done
  fi

  echo ""
  echo "[*] Writing detailed report to: $REPORT_PATH"
  {
    echo "Shai-Hulud Dynamic Detection Report"
    echo "Timestamp: $(date -u +"%Y-%m-%d %H:%M:%SZ")"
    echo "Scan Mode: ${SCAN_MODE^^}"
    echo "Scan Duration: ${duration}s"
    echo "Paths Scanned: ${ROOTS[*]}"
    echo ""
    echo "Compromised packages loaded: $(( ${#COMP_UNSCOPED[@]} + ${#COMP_SCOPED[@]} ))"
    echo ""
    if [[ ${#FINDING_LIST[@]} -eq 0 ]]; then
      echo "No indicators of compromise found in scanned locations."
    else
      echo "Indicators of compromise detected: ${#FINDING_LIST[@]}"
      echo ""
      for f in "${FINDING_LIST[@]}"; do
        IFS='|' read -r t ind loc <<<"$f"
        echo "Type: $t | Indicator: $ind | Location: $loc"
      done
    fi
  } >"$REPORT_PATH"
  echo "[*] Report written successfully."
  echo ""
  echo "============================================"
  echo " Scan complete - review the report carefully"
  echo "============================================"
  echo ""
}

main "$@"
