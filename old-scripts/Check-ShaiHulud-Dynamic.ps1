<#
    Check-ShaiHulud-Dynamic.ps1
    ---------------------------
    Comprehensive Shai-Hulud detection script for Windows.
    Detects both original Shai-Hulud (Sept 2025) and Shai-Hulud 2.0 (Nov 2025) IOCs.

    Scan Modes:
    - Quick : Fast scan (10-30 seconds) - checks most common IOCs, skips deep scans
    - Full  : Comprehensive scan (5-30+ minutes) - thorough recursive analysis

    Features (Quick mode = subset, Full mode = all):
    1. [Quick+Full] Fetches latest lists of compromised npm packages from remote sources
    2. [Quick+Full] Scans node_modules directories for compromised packages
    3. [Full only]  Scans npm cache for compromised packages
    4. [Quick+Full] Checks for known Shai-Hulud artefact files
    5. [Quick+Full] Scans git repositories for suspicious branches and remotes
    6. [Quick+Full] Scans GitHub Actions workflows for malicious patterns
    7. [Quick+Full] Detects cloud credential files (Quick: direct paths only)
    8. [Full only]  Checks for self-hosted GitHub Actions runner installations
    9. [Quick+Full] Scans package.json for suspicious postinstall hooks (Quick: root only)
    10. [Quick+Full] Hash-based malware detection (Quick: suspicious names only)
    11. [Full only]  Detects '-migration' suffix repos
    12. [Quick+Full] Checks for TruffleHog (Quick: PATH only)
    13. [Full only]  Scans for env+exfil patterns in code
    14. Read-only: does NOT delete or modify anything

    Detected IOCs include:
    - Malicious files: shai-hulud.js, setup_bun.js, bun_environment.js, discussion.yaml
    - Workflow patterns: formatter_*.yml, self-hosted runners, SHA1HULUD
    - Git indicators: shai-hulud branches, -migration suffix repos
    - Hash signatures: Known malicious SHA256/SHA1 hashes
    - Behavioral: env+exfil patterns, suspicious postinstall hooks

    Usage (PowerShell, as user):
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

        # Quick scan (default - fast):
        .\Check-ShaiHulud-Dynamic.ps1 -RootPaths "C:\Development"

        # Full scan (comprehensive):
        .\Check-ShaiHulud-Dynamic.ps1 -RootPaths "C:\Development" -ScanMode Full

    Parameters:
        -RootPaths  : One or more root directories to scan (default: $env:USERPROFILE)
        -ReportPath : Custom report file path (default: .\ShaiHulud-Scan-Report.txt)
        -ScanMode   : Quick (default) or Full

    References:
        - https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack
        - https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
        - https://unit42.paloaltonetworks.com/npm-supply-chain-attack/
        - https://github.com/sngular/shai-hulud-integrity-scanner
#>

param(
    [string[]]$RootPaths = @("$($env:USERPROFILE)"),
    [string]$ReportPath = ".\ShaiHulud-Scan-Report.txt",
    [ValidateSet("Quick", "Full")]
    [string]$ScanMode = "Quick"
)

# Detect terminal width
$terminalWidth = 120  # Default fallback
try {
    $terminalWidth = $Host.UI.RawUI.WindowSize.Width
} catch {
    # If we can't detect, use default
}

# Wide ASCII Art Banner (for terminals >= 180 chars)
$bannerWide = @"

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

                                          Supply Chain Malware Detection Scanner for Windows
"@

# Narrow ASCII Art Banner (for terminals < 180 chars)
$bannerNarrow = @"

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
  -------------------:::::::::::::+#####%%%%%%%#%##**+==-::...........:.:
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

            Supply Chain Malware Detection Scanner for Windows
"@

Write-Host ""
if ($terminalWidth -ge 180) {
    Write-Host $bannerWide -ForegroundColor DarkYellow
} else {
    Write-Host $bannerNarrow -ForegroundColor DarkYellow
}
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Shai-Hulud Dynamic Detection (Windows)" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Display scan mode
if ($ScanMode -eq "Quick") {
    Write-Host "[*] Scan Mode: QUICK (fast scan, common IOCs)" -ForegroundColor Cyan
    Write-Host "[*] For comprehensive analysis, use: -ScanMode Full" -ForegroundColor Gray
} else {
    Write-Host "[*] Scan Mode: FULL (comprehensive deep scan)" -ForegroundColor Cyan
    Write-Host "[*] This may take several minutes..." -ForegroundColor Gray
}
Write-Host ""

# -----------------------------
# 1. Configuration – Feeds & IOCs
# -----------------------------

# URLs that provide compromised package lists.
# These should be TEXT or CSV-like with one package identifier per line/column.
# You can add/remove feeds as needed.
$PackageFeedUrls = @(
    "https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/refs/heads/main/compromised-packages.txt"
    # Add other feeds here as they become available.
)

# Local cache snapshot for compromised package list (used if feeds are unreachable)
$CompromisedPackageCacheFile = if ($PSScriptRoot) {
    Join-Path $PSScriptRoot "compromised-packages-cache.txt"
} else {
    ".\compromised-packages-cache.txt"
}

# Known Shai-Hulud artefact filenames (workflows / payloads).
# Updated to include Shai-Hulud 2.0 IOCs (November 2025)
$MaliciousFileNames = @(
    # Original Shai-Hulud (September 2025)
    "shai-hulud.js",
    "shai_hulud.js",
    "shai-hulud-workflow.yml",
    "shai_hulud_workflow.yml",
    "shai-hulud.yml",
    "shai_hulud.yml",
    # Note: bundle.js excluded - too common, causes false positives
    # Real Shai-Hulud bundle.js has SHA256: 46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09
    # Shai-Hulud 2.0 (November 2025)
    "setup_bun.js",
    "bun_environment.js",
    "discussion.yaml",
    # Exfiltration artifacts (only flag if found alongside other IOCs)
    "truffleSecrets.json",
    "actionsSecrets.json"
    # Note: cloud.json, contents.json, environment.json, format.json excluded - too generic
)

# Suspicious git branch patterns
$SuspiciousBranchPatterns = @(
    "shai-hulud",
    "shai_hulud",
    "SHA1HULUD"
)

# Known malicious file hashes (SHA256)
$MaliciousHashes = @{
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09" = "Shai-Hulud bundle.js payload"
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777" = "Shai-Hulud malicious file"
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c" = "Shai-Hulud malicious file"
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db" = "Shai-Hulud malicious file"
}

# Known malicious file hashes (SHA1) - for Shai-Hulud 2.0
$MaliciousHashesSHA1 = @{
    "d1829b4708126dcc7bea7437c04d1f10eacd4a16" = "setup_bun.js (Shai-Hulud 2.0)"
    "d60ec97eea19fffb4809bc35b91033b52490ca11" = "bun_environment.js (Shai-Hulud 2.0)"
    "3d7570d14d34b0ba137d502f042b27b0f37a59fa" = "bun_environment.js variant (Shai-Hulud 2.0)"
}

# Suspicious workflow patterns
$SuspiciousWorkflowPatterns = @(
    "self-hosted",
    "SHA1HULUD",
    "shai-hulud",
    "shai_hulud",
    "webhook.site",
    "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7"
)

# Cloud credential file paths (relative to user home)
$CloudCredentialPaths = @(
    ".aws\credentials",
    ".aws\config",
    ".azure\",
    ".npmrc",
    ".env"
)

# Suspicious postinstall patterns (indicate potential malicious behavior)
$SuspiciousPostinstallPatterns = @(
    "curl ",
    "wget ",
    "node -e",
    "eval(",
    "base64",
    "webhook",
    "exfil",
    "/tmp/",
    "\\temp\\",
    "powershell",
    "cmd /c"
)

# -----------------------------
# 2. Helper Functions
# -----------------------------

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "---- $Text ----"
}

function Get-CompromisedPackageList {
    param(
        [string[]]$Urls,
        [string]$CacheFile
    )

    $allPkgs = New-Object System.Collections.Generic.HashSet[string]
    $totalUrls = $Urls.Count
    $currentUrl = 0

    foreach ($url in $Urls) {
        $currentUrl++
        Write-Host "[*] Fetching compromised package list from: $url"
        Write-Progress -Activity "Fetching compromised package lists" -Status "Feed $currentUrl of $totalUrls" -PercentComplete (($currentUrl / $totalUrls) * 100)

        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
            $content = $response.Content -split "`n"

            foreach ($line in $content) {
                $clean = ($line.Trim() -split '[,;|\s]')[0]  # take first token on the line
                if (![string]::IsNullOrWhiteSpace($clean)) {
                    [void]$allPkgs.Add($clean)
                }
            }
        }
        catch {
            Write-Host "[!] Failed to fetch or parse list from $url : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Progress -Activity "Fetching compromised package lists" -Completed

    # Cache the successful fetch for offline use
    if ($allPkgs.Count -gt 0 -and $CacheFile) {
        try {
            $allPkgs | Sort-Object | Out-File -FilePath $CacheFile -Encoding UTF8 -Force
        }
        catch {
            Write-Host "[!] Failed to write cache file $CacheFile : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    # Fallback to cached snapshot if feeds failed
    if ($allPkgs.Count -eq 0 -and $CacheFile -and (Test-Path $CacheFile)) {
        try {
            Write-Host "[*] Loading compromised package snapshot from cache: $CacheFile" -ForegroundColor Yellow
            $cached = Get-Content $CacheFile -ErrorAction Stop
            foreach ($line in $cached) {
                $clean = ($line.Trim() -split '[,;|\s]')[0]
                if (![string]::IsNullOrWhiteSpace($clean) -and -not $clean.StartsWith("#")) {
                    [void]$allPkgs.Add($clean)
                }
            }
        }
        catch {
            Write-Host "[!] Failed to load cache file $CacheFile : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Host "[*] Total unique compromised package identifiers loaded: $($allPkgs.Count)"
    return $allPkgs
}

function Find-NodeModulesDirs {
    param(
        [string[]]$Roots,
        [switch]$QuickMode
    )

    $dirs = @()
    $totalRoots = $Roots.Count
    $currentRoot = 0

    foreach ($root in $Roots) {
        $currentRoot++
        if (-not (Test-Path $root)) {
            Write-Host "[!] Root path not found: $root" -ForegroundColor Yellow
            continue
        }

        if ($QuickMode) {
            Write-Host "[*] Quick scan for node_modules in: $root (depth limited)"
            Write-Progress -Activity "Finding node_modules directories" -Status "Quick scan $root" -PercentComplete (($currentRoot / $totalRoots) * 100)

            try {
                # Quick mode: only check root and immediate subdirectories
                # Check if root itself has node_modules
                $rootNm = Join-Path $root "node_modules"
                if (Test-Path $rootNm) {
                    $dirs += Get-Item $rootNm
                }

                # Check immediate subdirectories for node_modules
                $subDirs = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue
                foreach ($subDir in $subDirs) {
                    $subNm = Join-Path $subDir.FullName "node_modules"
                    if (Test-Path $subNm) {
                        $dirs += Get-Item $subNm
                    }
                }
            }
            catch {
                Write-Host "[!] Error while scanning $root : $($_.Exception.Message)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "[*] Scanning for node_modules under: $root"
            Write-Progress -Activity "Finding node_modules directories" -Status "Scanning $root" -PercentComplete (($currentRoot / $totalRoots) * 100)

            try {
                $found = Get-ChildItem -Path $root -Recurse -Directory -Filter "node_modules" -ErrorAction SilentlyContinue
                $dirs += $found
            }
            catch {
                Write-Host "[!] Error while scanning $root : $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }

    Write-Progress -Activity "Finding node_modules directories" -Completed
    $unique = $dirs | Select-Object -ExpandProperty FullName -Unique
    Write-Host "[*] Found $($unique.Count) node_modules directories."
    return $unique
}

function Get-NpmCachePath {
    try {
        $npmPath = (Get-Command npm -ErrorAction Stop).Source
        $cache = (& npm config get cache) 2>$null
        if ($cache -and (Test-Path $cache)) {
            return $cache
        }
    }
    catch {
        # npm might not be installed or not in PATH
    }

    # fallback (default location on Windows is usually under %APPDATA%)
    $fallback = Join-Path $env:APPDATA "npm-cache"
    if (Test-Path $fallback) {
        return $fallback
    }

    return $null
}

function Scan-For-MaliciousPackages {
    param(
        [System.Collections.Generic.HashSet[string]]$CompromisedPackages,
        [string[]]$NodeModulesDirs
    )

    $hits = @()
    $totalDirs = $NodeModulesDirs.Count
    $currentDir = 0
    $lastProgressUpdate = 0

    # Pre-separate scoped vs unscoped packages for faster lookup
    $unscopedPackages = New-Object System.Collections.Generic.HashSet[string]
    $scopedPackages = @{}  # scope -> HashSet of package names

    foreach ($pkg in $CompromisedPackages) {
        if ($pkg.StartsWith("@")) {
            $parts = $pkg.Split("/")
            if ($parts.Count -eq 2) {
                $scope = $parts[0]
                $name = $parts[1]
                if (-not $scopedPackages.ContainsKey($scope)) {
                    $scopedPackages[$scope] = New-Object System.Collections.Generic.HashSet[string]
                }
                [void]$scopedPackages[$scope].Add($name)
            }
        } else {
            [void]$unscopedPackages.Add($pkg)
        }
    }

    Write-Host "[*] Optimized lookup: $($unscopedPackages.Count) unscoped, $($scopedPackages.Count) scoped namespaces"

    foreach ($nmDir in $NodeModulesDirs) {
        $currentDir++

        # Update progress every 50 directories or if only a few total
        if (($currentDir - $lastProgressUpdate) -ge 50 -or $totalDirs -lt 100) {
            $lastProgressUpdate = $currentDir
            Write-Progress -Activity "Scanning node_modules for malicious packages" -Status "$currentDir of $totalDirs directories" -PercentComplete (($currentDir / [Math]::Max($totalDirs, 1)) * 100)
        }

        try {
            # Get all immediate subdirectories in this node_modules (single filesystem call)
            $installedPackages = Get-ChildItem -Path $nmDir -Directory -ErrorAction SilentlyContinue

            foreach ($installed in $installedPackages) {
                $pkgName = $installed.Name

                if ($pkgName.StartsWith("@")) {
                    # This is a scope directory - check packages inside it
                    if ($scopedPackages.ContainsKey($pkgName)) {
                        $scopeDir = $installed.FullName
                        $scopedInstalled = Get-ChildItem -Path $scopeDir -Directory -ErrorAction SilentlyContinue

                        foreach ($scopedPkg in $scopedInstalled) {
                            if ($scopedPackages[$pkgName].Contains($scopedPkg.Name)) {
                                $fullPkgName = "$pkgName/$($scopedPkg.Name)"
                                Write-Host "    [!] FOUND: $fullPkgName at $nmDir" -ForegroundColor Red
                                $hits += [PSCustomObject]@{
                                    Location = $scopedPkg.FullName
                                    Package  = $fullPkgName
                                    Type     = "node_modules"
                                }
                            }
                        }
                    }
                } else {
                    # Unscoped package - direct HashSet lookup (O(1))
                    if ($unscopedPackages.Contains($pkgName)) {
                        Write-Host "    [!] FOUND: $pkgName at $nmDir" -ForegroundColor Red
                        $hits += [PSCustomObject]@{
                            Location = $installed.FullName
                            Package  = $pkgName
                            Type     = "node_modules"
                        }
                    }
                }
            }
        }
        catch {
            # Skip directories we can't access
        }
    }

    Write-Progress -Activity "Scanning node_modules for malicious packages" -Completed
    return $hits
}

function Scan-NpmCache {
    param(
        [System.Collections.Generic.HashSet[string]]$CompromisedPackages,
        [string]$CachePath
    )

    $hits = @()
    if (-not $CachePath) {
        Write-Host "[*] npm cache path not found or npm not installed."
        return $hits
    }

    Write-Host "[*] Scanning npm cache at: $CachePath"

    # Build a single regex to match any compromised package identifier (version delimiters can be :, -, or _)
    $groupNames = @{}
    $patterns = @()
    $idx = 0
    foreach ($pkg in $CompromisedPackages) {
        $groupName = "pkg$idx"
        $escaped = [regex]::Escape($pkg) -replace "\\:", "[:_\-]"
        $patterns += "(?<$groupName>$escaped)"
        $groupNames[$groupName] = $pkg
        $idx++
    }

    if ($patterns.Count -eq 0) {
        return $hits
    }

    $cacheRegex = [regex]::new("(?i)(" + ($patterns -join "|") + ")")

    try {
        $checked = 0
        $lastProgressUpdate = 0

        Get-ChildItem -Path $CachePath -Recurse -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $checked++

            if (($checked - $lastProgressUpdate) -ge 200) {
                $lastProgressUpdate = $checked
                Write-Progress -Activity "Scanning npm cache" -Status "$checked directories checked"
            }

            $match = $cacheRegex.Match($_.FullName)
            if ($match.Success) {
                $matchedPkg = $null
                foreach ($g in $cacheRegex.GetGroupNames()) {
                    if ($g -notlike "pkg*") { continue }
                    if ($match.Groups[$g].Success) {
                        $matchedPkg = $groupNames[$g]
                        break
                    }
                }

                if (-not $matchedPkg) { $matchedPkg = $match.Value }

                Write-Host "    [!] FOUND in cache: $matchedPkg" -ForegroundColor Red
                $hits += [PSCustomObject]@{
                    Location = $_.FullName
                    Package  = $matchedPkg
                    Type     = "npm-cache"
                }
            }
        }
    }
    catch {
        Write-Host "[!] Error while scanning npm cache: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Progress -Activity "Scanning npm cache" -Completed
    return $hits
}

function Scan-For-MaliciousFiles {
    param(
        [string[]]$Roots,
        [string[]]$FileNames,
        [switch]$QuickMode
    )

    $hits = @()
    $totalRoots = $Roots.Count
    $currentRoot = 0

    foreach ($root in $Roots) {
        $currentRoot++
        if (-not (Test-Path $root)) { continue }

        if ($QuickMode) {
            Write-Host "[*] Quick scan for Shai-Hulud artefacts in: $root (depth limited)"
        } else {
            Write-Host "[*] Scanning for known Shai-Hulud artefacts under: $root"
        }
        Write-Progress -Activity "Scanning for malicious files" -Status "Scanning $root" -PercentComplete (($currentRoot / $totalRoots) * 100)

        try {
            if ($QuickMode) {
                # Quick mode: only scan immediate directory and .github/workflows
                $files = @()
                # Check root directory
                $files += Get-ChildItem -Path $root -File -ErrorAction SilentlyContinue |
                    Where-Object { $FileNames -contains $_.Name }
                # Check .github/workflows specifically
                $workflowPath = Join-Path $root ".github\workflows"
                if (Test-Path $workflowPath) {
                    $files += Get-ChildItem -Path $workflowPath -File -ErrorAction SilentlyContinue |
                        Where-Object { $FileNames -contains $_.Name }
                }
            } else {
                # Full mode: recursive scan
                $files = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $FileNames -contains $_.Name }
            }

            foreach ($f in $files) {
                Write-Host "    [!] FOUND: $($f.Name) at $($f.DirectoryName)" -ForegroundColor Red
                $hits += [PSCustomObject]@{
                    Location = $f.FullName
                    Indicator = $f.Name
                    Type = "file-artefact"
                }
            }
        }
        catch {
            Write-Host "[!] Error scanning for artefacts under $root : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Progress -Activity "Scanning for malicious files" -Completed
    return $hits
}

function Scan-For-SuspiciousGitBranches {
    param(
        [string[]]$Roots,
        [string[]]$BranchPatterns,
        [switch]$QuickMode
    )

    $hits = @()

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }

        if ($QuickMode) {
            Write-Host "[*] Quick scan for git branches in: $root (top-level only)"
        } else {
            Write-Host "[*] Scanning for suspicious git branches under: $root"
        }
        Write-Progress -Activity "Scanning for git repositories" -Status "Searching in $root"

        try {
            if ($QuickMode) {
                # Quick mode: only check if root itself is a git repo
                $gitDirs = @()
                $rootGit = Join-Path $root ".git"
                if (Test-Path $rootGit) {
                    $gitDirs = @(Get-Item $rootGit -Force)
                }
                # Also check immediate subdirectories
                $subDirs = Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | Select-Object -First 20
                foreach ($subDir in $subDirs) {
                    $subGit = Join-Path $subDir.FullName ".git"
                    if (Test-Path $subGit) {
                        $gitDirs += Get-Item $subGit -Force
                    }
                }
            } else {
                # Full mode: recursive search
                $gitDirs = Get-ChildItem -Path $root -Recurse -Directory -Filter ".git" -ErrorAction SilentlyContinue -Force
            }

            $totalGit = @($gitDirs).Count
            $currentGit = 0

            foreach ($gitDir in $gitDirs) {
                $currentGit++
                $repoPath = Split-Path $gitDir.FullName -Parent
                Write-Progress -Activity "Checking git branches" -Status "$repoPath" -PercentComplete (($currentGit / [Math]::Max($totalGit, 1)) * 100)

                try {
                    # Get all branches (local and remote)
                    $branches = & git -C $repoPath branch -a 2>$null
                    if ($branches) {
                        foreach ($branch in $branches) {
                            foreach ($pattern in $BranchPatterns) {
                                if ($branch -match $pattern) {
                                    $hits += [PSCustomObject]@{
                                        Location  = $repoPath
                                        Indicator = "Branch: $($branch.Trim())"
                                        Type      = "git-branch"
                                    }
                                }
                            }
                        }
                    }

                    # Also check for Shai-Hulud repository name pattern
                    $remotes = & git -C $repoPath remote -v 2>$null
                    if ($remotes -match "Shai-Hulud") {
                        $hits += [PSCustomObject]@{
                            Location  = $repoPath
                            Indicator = "Remote contains 'Shai-Hulud'"
                            Type      = "git-remote"
                        }
                    }
                }
                catch {
                    # Git command failed, skip this repo
                }
            }
        }
        catch {
            Write-Host "[!] Error scanning for git branches under $root : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Progress -Activity "Checking git branches" -Completed
    return $hits
}

# Function 1: Scan GitHub Actions workflows for suspicious patterns
function Scan-GitHubWorkflows {
    param(
        [string[]]$Roots,
        [string[]]$Patterns
    )

    $hits = @()

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }

        Write-Host "[*] Scanning GitHub Actions workflows under: $root"
        Write-Progress -Activity "Scanning GitHub workflows" -Status "Searching in $root"

        try {
            # Find all .github/workflows directories
            $workflowDirs = Get-ChildItem -Path $root -Recurse -Directory -Filter "workflows" -ErrorAction SilentlyContinue |
                Where-Object { $_.Parent.Name -eq ".github" }

            foreach ($wfDir in $workflowDirs) {
                $ymlFiles = Get-ChildItem -Path $wfDir.FullName -Filter "*.yml" -ErrorAction SilentlyContinue
                $yamlFiles = Get-ChildItem -Path $wfDir.FullName -Filter "*.yaml" -ErrorAction SilentlyContinue
                $allWorkflows = @($ymlFiles) + @($yamlFiles)

                foreach ($wf in $allWorkflows) {
                    # Check for formatter_*.yml pattern (Shai-Hulud 2.0)
                    if ($wf.Name -match "^formatter_\d+\.yml$") {
                        Write-Host "    [!] SUSPICIOUS: formatter workflow found: $($wf.FullName)" -ForegroundColor Red
                        $hits += [PSCustomObject]@{
                            Location  = $wf.FullName
                            Indicator = "Suspicious workflow name: $($wf.Name)"
                            Type      = "workflow-pattern"
                        }
                    }

                    # Check workflow content for suspicious patterns
                    try {
                        $content = Get-Content $wf.FullName -Raw -ErrorAction SilentlyContinue
                        foreach ($pattern in $Patterns) {
                            if ($content -match $pattern) {
                                Write-Host "    [!] SUSPICIOUS: Pattern '$pattern' found in: $($wf.FullName)" -ForegroundColor Red
                                $hits += [PSCustomObject]@{
                                    Location  = $wf.FullName
                                    Indicator = "Workflow contains: $pattern"
                                    Type      = "workflow-content"
                                }
                                break  # One hit per file is enough
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch {
            Write-Host "[!] Error scanning workflows under $root : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Progress -Activity "Scanning GitHub workflows" -Completed
    return $hits
}

# Function 2: Check for cloud credential file exposure
function Scan-CloudCredentials {
    param(
        [string[]]$Roots,
        [string[]]$CredentialPaths,
        [switch]$QuickMode
    )

    $hits = @()

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }

        if ($QuickMode) {
            Write-Host "[*] Quick check for cloud credential files in: $root"
        } else {
            Write-Host "[*] Checking for cloud credential files under: $root"
        }

        foreach ($credPath in $CredentialPaths) {
            $fullPath = Join-Path $root $credPath

            if (Test-Path $fullPath) {
                # Check if it's a file or directory
                $item = Get-Item $fullPath -ErrorAction SilentlyContinue

                if ($item.PSIsContainer) {
                    # It's a directory (like .azure\)
                    $files = Get-ChildItem -Path $fullPath -File -ErrorAction SilentlyContinue
                    if ($files.Count -gt 0) {
                        Write-Host "    [!] Cloud credential directory found: $fullPath" -ForegroundColor Yellow
                        $hits += [PSCustomObject]@{
                            Location  = $fullPath
                            Indicator = "Cloud credential directory exists (potential exfil target)"
                            Type      = "credential-file"
                        }
                    }
                }
                else {
                    # It's a file
                    Write-Host "    [!] Cloud credential file found: $fullPath" -ForegroundColor Yellow
                    $hits += [PSCustomObject]@{
                        Location  = $fullPath
                        Indicator = "Cloud credential file exists (potential exfil target)"
                        Type      = "credential-file"
                    }
                }
            }
        }

        # Scan for .env files - Quick mode: only root, Full mode: recursive
        if (-not $QuickMode) {
            try {
                $envFiles = Get-ChildItem -Path $root -Recurse -File -Filter ".env*" -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -notmatch "node_modules" }

                foreach ($envFile in $envFiles) {
                    $hits += [PSCustomObject]@{
                        Location  = $envFile.FullName
                        Indicator = ".env file (potential secrets exposure)"
                        Type      = "credential-file"
                    }
                }
            }
            catch { }
        } else {
            # Quick mode: only check root .env
            $rootEnv = Join-Path $root ".env"
            if (Test-Path $rootEnv) {
                $hits += [PSCustomObject]@{
                    Location  = $rootEnv
                    Indicator = ".env file (potential secrets exposure)"
                    Type      = "credential-file"
                }
            }
        }
    }

    return $hits
}

# Function 3: Check for self-hosted GitHub Actions runners
function Scan-SelfHostedRunners {
    param(
        [string[]]$Roots
    )

    $hits = @()

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }

        Write-Host "[*] Checking for self-hosted GitHub runners under: $root"

        try {
            # Look for actions-runner directories
            $runnerDirs = Get-ChildItem -Path $root -Recurse -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "actions-runner|_work|runner" }

            foreach ($runnerDir in $runnerDirs) {
                # Check for .runner file (indicates configured runner)
                $runnerConfig = Join-Path $runnerDir.FullName ".runner"
                if (Test-Path $runnerConfig) {
                    $configContent = Get-Content $runnerConfig -Raw -ErrorAction SilentlyContinue

                    # Check if runner name contains SHA1HULUD
                    if ($configContent -match "SHA1HULUD") {
                        Write-Host "    [!] CRITICAL: Malicious runner 'SHA1HULUD' found: $runnerDir" -ForegroundColor Red
                        $hits += [PSCustomObject]@{
                            Location  = $runnerDir.FullName
                            Indicator = "Malicious self-hosted runner 'SHA1HULUD'"
                            Type      = "malicious-runner"
                        }
                    }
                    else {
                        Write-Host "    [*] Self-hosted runner found (verify legitimacy): $runnerDir" -ForegroundColor Yellow
                        $hits += [PSCustomObject]@{
                            Location  = $runnerDir.FullName
                            Indicator = "Self-hosted runner installation (verify legitimacy)"
                            Type      = "runner-installation"
                        }
                    }
                }
            }
        }
        catch {
            Write-Host "[!] Error scanning for runners: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    return $hits
}

# Function 4: Scan package.json files for suspicious postinstall hooks
function Scan-PostinstallHooks {
    param(
        [string[]]$Roots,
        [string[]]$SuspiciousPatterns,
        [switch]$QuickMode
    )

    $hits = @()

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }

        if ($QuickMode) {
            Write-Host "[*] Quick scan for postinstall hooks in: $root (root package.json only)"
        } else {
            Write-Host "[*] Scanning package.json files for suspicious postinstall hooks under: $root"
        }
        Write-Progress -Activity "Scanning postinstall hooks" -Status "Searching in $root"

        try {
            if ($QuickMode) {
                # Quick mode: only check root package.json
                $packageFiles = @()
                $rootPkg = Join-Path $root "package.json"
                if (Test-Path $rootPkg) {
                    $packageFiles = @(Get-Item $rootPkg)
                }
            } else {
                # Full mode: find all package.json files (excluding deep node_modules)
                $packageFiles = Get-ChildItem -Path $root -Recurse -File -Filter "package.json" -ErrorAction SilentlyContinue |
                    Where-Object {
                        # Exclude nested node_modules but include top-level project package.json
                        $depth = ($_.FullName -split "node_modules").Count - 1
                        $depth -le 1
                    }
            }

            foreach ($pkgFile in $packageFiles) {
                try {
                    $content = Get-Content $pkgFile.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue

                    if ($content.scripts) {
                        $hookTypes = @("postinstall", "preinstall", "install", "prepare")

                        foreach ($hookType in $hookTypes) {
                            $hookValue = $content.scripts.$hookType
                            if ($hookValue) {
                                $isSuspicious = $false
                                $matchedPattern = ""

                                foreach ($pattern in $SuspiciousPatterns) {
                                    if ($hookValue -match [regex]::Escape($pattern)) {
                                        $isSuspicious = $true
                                        $matchedPattern = $pattern
                                        break
                                    }
                                }

                                if ($isSuspicious) {
                                    Write-Host "    [!] SUSPICIOUS $hookType hook in: $($pkgFile.FullName)" -ForegroundColor Red
                                    $hits += [PSCustomObject]@{
                                        Location  = $pkgFile.FullName
                                        Indicator = "Suspicious $hookType`: $hookValue (matched: $matchedPattern)"
                                        Type      = "postinstall-hook"
                                    }
                                }
                            }
                        }
                    }
                }
                catch { }
            }
        }
        catch {
            Write-Host "[!] Error scanning package.json files: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Progress -Activity "Scanning postinstall hooks" -Completed
    return $hits
}

# Function 5: Hash-based malware detection
function Scan-FileHashes {
    param(
        [string[]]$Roots,
        [hashtable]$KnownBadSHA256,
        [hashtable]$KnownBadSHA1,
        [switch]$QuickMode
    )

    $hits = @()

    # Known malicious filenames for Quick mode targeted scanning
    $suspiciousNames = @("bundle.js", "setup_bun.js", "bun_environment.js", "shai-hulud.js", "shai_hulud.js")

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }

        if ($QuickMode) {
            Write-Host "[*] Quick hash scan in: $root (suspicious filenames only)"
            Write-Progress -Activity "Hash-based malware scan" -Status "Targeted scan for suspicious files..."

            try {
                # Quick mode: single pass for suspicious filenames, skip nested node_modules to keep the fast path fast
                $suspiciousSet = New-Object System.Collections.Generic.HashSet[string]
                $suspiciousNames | ForEach-Object { [void]$suspiciousSet.Add($_) }

                # Track how deep we are inside node_modules (0 = outside, 1 = node_modules, 2 = package root)
                $queue = New-Object 'System.Collections.Generic.Queue[psobject]'
                $queue.Enqueue([PSCustomObject]@{ Path = $root; NodeDepth = 0 })
                $files = @()

                while ($queue.Count -gt 0) {
                    $entry = $queue.Dequeue()
                    $currentDir = $entry.Path
                    $nodeDepth = [int]$entry.NodeDepth

                    try {
                        $files += Get-ChildItem -Path $currentDir -File -ErrorAction SilentlyContinue |
                            Where-Object { $suspiciousSet.Contains($_.Name) }

                        # Do not descend deeper than package root when inside node_modules
                        if ($nodeDepth -ge 2) { continue }

                        $subDirs = Get-ChildItem -Path $currentDir -Directory -ErrorAction SilentlyContinue
                        foreach ($subDir in $subDirs) {
                            $childDepth = $nodeDepth
                            if ($subDir.Name -eq "node_modules") {
                                $childDepth = 1
                            } elseif ($nodeDepth -gt 0) {
                                $childDepth = $nodeDepth + 1
                            }

                            # Skip nested node_modules trees beyond first level
                            if ($childDepth -gt 2) { continue }

                            $queue.Enqueue([PSCustomObject]@{ Path = $subDir.FullName; NodeDepth = $childDepth })
                        }
                    }
                    catch { }
                }
            }
            catch {
                Write-Host "[!] Error finding files: $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            }
        } else {
            Write-Host "[*] Scanning files for known malicious hashes under: $root"
            Write-Progress -Activity "Hash-based malware scan" -Status "Enumerating files..."

            try {
                # Full mode: get all JS/TS files (excluding node_modules)
                $files = Get-ChildItem -Path $root -Recurse -File -Include "*.js","*.ts" -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -notmatch "node_modules" -and $_.Name -notmatch "\.d\.ts$" }
            }
            catch {
                Write-Host "[!] Error enumerating files: $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            }
        }

        $totalFiles = @($files).Count
        $currentFile = 0
        $lastUpdate = 0

        if ($QuickMode) {
            Write-Host "    [*] Found $totalFiles files with suspicious names to hash"
        }

        foreach ($file in $files) {
            $currentFile++
            if (($currentFile - $lastUpdate) -ge 50 -or $QuickMode) {
                $lastUpdate = $currentFile
                Write-Progress -Activity "Hash-based malware scan" -Status "$currentFile of $totalFiles files" -PercentComplete (($currentFile / [Math]::Max($totalFiles, 1)) * 100)
            }

            try {
                # SHA256 check
                $sha256 = (Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash.ToLower()
                if ($KnownBadSHA256.ContainsKey($sha256)) {
                    Write-Host "    [!!!] MALWARE DETECTED: $($file.FullName)" -ForegroundColor Red
                    $hits += [PSCustomObject]@{
                        Location  = $file.FullName
                        Indicator = "SHA256 match: $($KnownBadSHA256[$sha256])"
                        Type      = "malware-hash"
                    }
                    continue  # Already found, skip SHA1 check
                }

                # SHA1 check (for Shai-Hulud 2.0 IOCs) - only if SHA256 didn't match
                $sha1 = (Get-FileHash -Path $file.FullName -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash.ToLower()
                if ($KnownBadSHA1.ContainsKey($sha1)) {
                    Write-Host "    [!!!] MALWARE DETECTED: $($file.FullName)" -ForegroundColor Red
                    $hits += [PSCustomObject]@{
                        Location  = $file.FullName
                        Indicator = "SHA1 match: $($KnownBadSHA1[$sha1])"
                        Type      = "malware-hash"
                    }
                }
            }
            catch { }
        }
    }

    Write-Progress -Activity "Hash-based malware scan" -Completed
    return $hits
}

# Function 6: Check for -migration suffix (private→public repo migration attack)
function Scan-MigrationSuffix {
    param(
        [string[]]$Roots
    )

    $hits = @()

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }

        Write-Host "[*] Checking for '-migration' suffix indicators under: $root"

        try {
            # Check git remotes for -migration suffix
            $gitDirs = Get-ChildItem -Path $root -Recurse -Directory -Filter ".git" -ErrorAction SilentlyContinue -Force

            foreach ($gitDir in $gitDirs) {
                $repoPath = Split-Path $gitDir.FullName -Parent

                try {
                    $remotes = & git -C $repoPath remote -v 2>$null
                    if ($remotes -match "-migration") {
                        Write-Host "    [!] SUSPICIOUS: Repository with '-migration' suffix: $repoPath" -ForegroundColor Red
                        $hits += [PSCustomObject]@{
                            Location  = $repoPath
                            Indicator = "Remote URL contains '-migration' (potential Shai-Hulud migration attack)"
                            Type      = "migration-attack"
                        }
                    }
                }
                catch { }
            }

            # Also check directory names
            $migrationDirs = Get-ChildItem -Path $root -Recurse -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "-migration$" }

            foreach ($dir in $migrationDirs) {
                $hits += [PSCustomObject]@{
                    Location  = $dir.FullName
                    Indicator = "Directory name ends with '-migration'"
                    Type      = "migration-attack"
                }
            }
        }
        catch {
            Write-Host "[!] Error checking migration patterns: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    return $hits
}

# Function 7: Check for TruffleHog installation (used by malware for credential harvesting)
function Scan-TruffleHogInstallation {
    param(
        [string[]]$Roots,
        [switch]$QuickMode
    )

    $hits = @()

    if ($QuickMode) {
        Write-Host "[*] Quick check for TruffleHog (PATH only)..."
    } else {
        Write-Host "[*] Checking for unexpected TruffleHog installations..."
    }

    # Check if trufflehog is in PATH (both modes)
    try {
        $truffleInPath = Get-Command trufflehog -ErrorAction SilentlyContinue
        if ($truffleInPath) {
            Write-Host "    [!] TruffleHog found in PATH: $($truffleInPath.Source)" -ForegroundColor Yellow
            $hits += [PSCustomObject]@{
                Location  = $truffleInPath.Source
                Indicator = "TruffleHog in PATH (verify if intentionally installed)"
                Type      = "trufflehog-installation"
            }
        }
    }
    catch { }

    # Full mode only: recursive file search
    if (-not $QuickMode) {
        foreach ($root in $Roots) {
            if (-not (Test-Path $root)) { continue }

            try {
                # Search for trufflehog binary
                $truffleFiles = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match "^trufflehog(\.exe)?$" }

                foreach ($tf in $truffleFiles) {
                    Write-Host "    [!] TruffleHog binary found: $($tf.FullName)" -ForegroundColor Yellow
                    $hits += [PSCustomObject]@{
                        Location  = $tf.FullName
                        Indicator = "TruffleHog binary (used by Shai-Hulud for credential harvesting)"
                        Type      = "trufflehog-installation"
                    }
                }

                # Also check for trufflehog in npm packages or pip
                $truffleRefs = Get-ChildItem -Path $root -Recurse -File -Filter "package.json" -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -notmatch "node_modules\\.*node_modules" } |
                    ForEach-Object {
                        $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
                        if ($content -match "trufflehog") {
                            $_
                        }
                    }

                foreach ($ref in $truffleRefs) {
                    $hits += [PSCustomObject]@{
                        Location  = $ref.FullName
                        Indicator = "package.json references trufflehog"
                        Type      = "trufflehog-reference"
                    }
                }
            }
            catch { }
        }
    }

    return $hits
}

# Function 8: Scan for suspicious environment variable patterns in code
function Scan-SuspiciousEnvPatterns {
    param(
        [string[]]$Roots
    )

    $hits = @()

    # Patterns that indicate credential harvesting combined with exfiltration
    $envPatterns = @(
        "process\.env",
        "os\.environ",
        '\$env:',
        "AWS_ACCESS_KEY",
        "AWS_SECRET",
        "GITHUB_TOKEN",
        "NPM_TOKEN",
        "GH_TOKEN",
        "AZURE_"
    )

    $exfilPatterns = @(
        "webhook\.site",
        "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7",
        "exfiltrat",
        "fetch\s*\(",
        "axios\.",
        "http\.request",
        "https\.request"
    )

    foreach ($root in $Roots) {
        if (-not (Test-Path $root)) { continue }

        Write-Host "[*] Scanning for suspicious env+exfiltration patterns under: $root"
        Write-Progress -Activity "Environment pattern scan" -Status "Scanning $root"

        try {
            $files = Get-ChildItem -Path $root -Recurse -File -Include "*.js","*.ts","*.py","*.sh","*.ps1" -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch "node_modules" -and $_.Name -notmatch "\.d\.ts$" }

            foreach ($file in $files) {
                try {
                    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                    if (-not $content) { continue }

                    $hasEnvAccess = $false
                    $hasExfil = $false

                    foreach ($pattern in $envPatterns) {
                        if ($content -match $pattern) {
                            $hasEnvAccess = $true
                            break
                        }
                    }

                    if ($hasEnvAccess) {
                        foreach ($pattern in $exfilPatterns) {
                            if ($content -match $pattern) {
                                $hasExfil = $true
                                break
                            }
                        }
                    }

                    # Flag files that have BOTH env access AND exfiltration indicators
                    if ($hasEnvAccess -and $hasExfil) {
                        Write-Host "    [!] SUSPICIOUS: Env access + exfil pattern in: $($file.FullName)" -ForegroundColor Red
                        $hits += [PSCustomObject]@{
                            Location  = $file.FullName
                            Indicator = "File contains both environment variable access and potential exfiltration"
                            Type      = "env-exfil-pattern"
                        }
                    }
                }
                catch { }
            }
        }
        catch {
            Write-Host "[!] Error scanning env patterns: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    Write-Progress -Activity "Environment pattern scan" -Completed
    return $hits
}

# -----------------------------
# 3. Main Logic
# -----------------------------

$ScanStartTime = Get-Date

Write-Section "Loading compromised package lists"
$Compromised = Get-CompromisedPackageList -Urls $PackageFeedUrls -CacheFile $CompromisedPackageCacheFile

if ($Compromised.Count -eq 0) {
    Write-Host "[!] No compromised packages loaded from feeds. The scan will continue with only file-based IOCs." -ForegroundColor Yellow
}

Write-Section "Finding node_modules directories"
$NodeModulesDirs = Find-NodeModulesDirs -Roots $RootPaths -QuickMode:($ScanMode -eq "Quick")

# npm cache - Full mode only
$NpmCachePath = $null
$CacheHits = @()
if ($ScanMode -eq "Full") {
    Write-Section "Determining npm cache path"
    $NpmCachePath = Get-NpmCachePath
    if ($NpmCachePath) {
        Write-Host "[*] npm cache path: $NpmCachePath"
    } else {
        Write-Host "[*] npm cache path not detected."
    }
}

Write-Section "Scanning for malicious packages in node_modules"
$NodeHits = @()
if ($Compromised.Count -gt 0 -and $NodeModulesDirs.Count -gt 0) {
    $NodeHits = Scan-For-MaliciousPackages -CompromisedPackages $Compromised -NodeModulesDirs $NodeModulesDirs
} else {
    Write-Host "[-] Skipping node_modules package scan (no packages or dirs)."
}

# npm cache scan - Full mode only
if ($ScanMode -eq "Full") {
    Write-Section "Scanning npm cache for compromised packages"
    if ($Compromised.Count -gt 0 -and $NpmCachePath) {
        $CacheHits = Scan-NpmCache -CompromisedPackages $Compromised -CachePath $NpmCachePath
    } else {
        Write-Host "[-] Skipping npm cache scan (no packages or cache path)."
    }
} else {
    Write-Host ""
    Write-Host "[Quick] Skipping npm cache scan (use -ScanMode Full)" -ForegroundColor Gray
}

Write-Section "Scanning for known Shai-Hulud artefact files"
$ArtefactHits = Scan-For-MaliciousFiles -Roots $RootPaths -FileNames $MaliciousFileNames -QuickMode:($ScanMode -eq "Quick")

Write-Section "Scanning for suspicious git branches and remotes"
$GitHits = Scan-For-SuspiciousGitBranches -Roots $RootPaths -BranchPatterns $SuspiciousBranchPatterns -QuickMode:($ScanMode -eq "Quick")

Write-Section "Scanning GitHub Actions workflows"
$WorkflowHits = Scan-GitHubWorkflows -Roots $RootPaths -Patterns $SuspiciousWorkflowPatterns

Write-Section "Checking cloud credential files"
$CredentialHits = Scan-CloudCredentials -Roots $RootPaths -CredentialPaths $CloudCredentialPaths -QuickMode:($ScanMode -eq "Quick")

# Self-hosted runners - Full mode only
$RunnerHits = @()
if ($ScanMode -eq "Full") {
    Write-Section "Checking for self-hosted runners"
    $RunnerHits = Scan-SelfHostedRunners -Roots $RootPaths
} else {
    Write-Host ""
    Write-Host "[Quick] Skipping self-hosted runner scan (use -ScanMode Full)" -ForegroundColor Gray
}

Write-Section "Scanning postinstall hooks"
$HookHits = Scan-PostinstallHooks -Roots $RootPaths -SuspiciousPatterns $SuspiciousPostinstallPatterns -QuickMode:($ScanMode -eq "Quick")

Write-Section "Hash-based malware detection"
$HashHits = Scan-FileHashes -Roots $RootPaths -KnownBadSHA256 $MaliciousHashes -KnownBadSHA1 $MaliciousHashesSHA1 -QuickMode:($ScanMode -eq "Quick")

# Migration suffix - Full mode only
$MigrationHits = @()
if ($ScanMode -eq "Full") {
    Write-Section "Checking for migration suffix attack"
    $MigrationHits = Scan-MigrationSuffix -Roots $RootPaths
} else {
    Write-Host ""
    Write-Host "[Quick] Skipping migration suffix scan (use -ScanMode Full)" -ForegroundColor Gray
}

Write-Section "Checking for TruffleHog installation"
$TruffleHits = Scan-TruffleHogInstallation -Roots $RootPaths -QuickMode:($ScanMode -eq "Quick")

# Env+exfil patterns - Full mode only
$EnvHits = @()
if ($ScanMode -eq "Full") {
    Write-Section "Scanning for suspicious env+exfil patterns"
    $EnvHits = Scan-SuspiciousEnvPatterns -Roots $RootPaths
} else {
    Write-Host ""
    Write-Host "[Quick] Skipping env+exfil pattern scan (use -ScanMode Full)" -ForegroundColor Gray
}

$ScanEndTime = Get-Date
$ScanDuration = $ScanEndTime - $ScanStartTime

# -----------------------------
# 4. Reporting
# -----------------------------

$allFindings = @()
$allFindings += $NodeHits
$allFindings += $CacheHits
$allFindings += $ArtefactHits
$allFindings += $GitHits
$allFindings += $WorkflowHits
$allFindings += $CredentialHits
$allFindings += $RunnerHits
$allFindings += $HookHits
$allFindings += $HashHits
$allFindings += $MigrationHits
$allFindings += $TruffleHits
$allFindings += $EnvHits

Write-Section "Summary"

Write-Host "[*] Scan completed in $([math]::Round($ScanDuration.TotalSeconds, 1)) seconds ($ScanMode mode)"
Write-Host ""

if ($allFindings.Count -eq 0) {
    Write-Host "[OK] No indicators of Shai-Hulud compromise were found in the scanned locations." -ForegroundColor Green
} else {
    Write-Host "[!!!] POTENTIAL INDICATORS OF COMPROMISE FOUND: $($allFindings.Count) item(s)" -ForegroundColor Red
    $allFindings | Format-Table -AutoSize
}

if ($ScanMode -eq "Quick") {
    Write-Host ""
    Write-Host "[*] Quick scan complete. For comprehensive analysis, run with -ScanMode Full" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "[*] Writing detailed report to: $ReportPath"

try {
    $reportLines = @()
    $reportLines += "Shai-Hulud Dynamic Detection Report"
    $reportLines += ("Timestamp: " + (Get-Date).ToString("u"))
    $reportLines += "Scan Mode: $ScanMode"
    $reportLines += "Scan Duration: $([math]::Round($ScanDuration.TotalSeconds, 1)) seconds"
    $reportLines += "Paths Scanned: $($RootPaths -join ', ')"
    $reportLines += ""

    if ($Compromised.Count -gt 0) {
        $reportLines += "Compromised packages loaded: $($Compromised.Count)"
    } else {
        $reportLines += "Compromised packages loaded: 0 (feed fetch failed or returned no data)"
    }
    $reportLines += ""

    if ($allFindings.Count -eq 0) {
        $reportLines += "No indicators of compromise found in scanned locations."
    } else {
        $reportLines += "Indicators of compromise detected: $($allFindings.Count)"
        $reportLines += ""
        foreach ($hit in $allFindings) {
            $indicator = if ($hit.Package) { $hit.Package } else { $hit.Indicator }
            $reportLines += ("Type: {0} | Package/Indicator: {1} | Location: {2}" -f `
                $hit.Type, `
                $indicator, `
                $hit.Location)
        }
    }

    $reportLines | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
    Write-Host "[*] Report written successfully."
}
catch {
    Write-Host "[!] Failed to write report: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================"
Write-Host " Scan complete - review the report carefully"
Write-Host "============================================"
Write-Host ""
